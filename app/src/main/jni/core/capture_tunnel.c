/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PCAPdroid is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PCAPdroid.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2026 - PCAPdroid TunnelEmbedded
 */

/*
 * L3 pass-through datapath for the embedded tunnel.
 *
 * Unlike run_vpn, this datapath performs no userspace NAT: the IP packets read from the
 * tun are analyzed and then handed to the tunnel backend unchanged, and the inner packets
 * coming back from the tunnel are analyzed and written to the tun unchanged. Nothing
 * rewrites addresses, ports or TCP sequence numbers, which has three consequences:
 *
 *  - the PCAP produced in this mode is faithful per packet, so the caveat in
 *    docs/how_it_works.md does not apply here;
 *  - connections are tracked by observing the packets, like in root mode, rather than by
 *    owning a socket per connection;
 *  - the DNS server advertised on the tun is the one from the tunnel configuration, so
 *    there is no internal DNS address to rewrite: PCAPdroid sees the queries anyway
 *    because it sees every packet.
 *
 * The features that fundamentally need an L4 proxy (TLS decryption through the mitm
 * addon, port mapping, SOCKS5 chaining) are not available in this datapath; the Java side
 * refuses that combination, and PD_TUNNEL_DATAPATH_L4 is the path that will support them.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <unistd.h>

#include "pcapdroid.h"
#include "tunnel.h"
#include "common/utils.h"

/* How long a tracked flow may stay idle before it is purged, per protocol.
 * Mirrors the zdtun timeouts so that the connections list behaves consistently across
 * capture modes. */
#define TUNNEL_TCP_TIMEOUT_MS   (300 * 1000)
#define TUNNEL_UDP_TIMEOUT_MS   (30 * 1000)
#define TUNNEL_ICMP_TIMEOUT_MS  (10 * 1000)

typedef struct tunnel_conn_t {
    zdtun_5tuple_t tuple;
    pd_conn_t *data;

    UT_hash_handle hh;
} tunnel_conn_t;

/* ******************************************************* */

static void remove_connection(pcapdroid_t *pd, tunnel_conn_t *conn) {
    switch(conn->tuple.ipproto) {
        case IPPROTO_TCP:  pd->stats.num_tcp_conn--;  break;
        case IPPROTO_UDP:  pd->stats.num_udp_conn--;  break;
        case IPPROTO_ICMP: pd->stats.num_icmp_conn--; break;
    }

    HASH_DEL(pd->tunnel.connections, conn);
    pd_free(conn);
}

/* ******************************************************* */

/* Derives the connection status from the observed packets.
 *
 * This is the same state machine as the one in capture_pcap.c, with one simplification:
 * here the direction is known exactly (a packet either came from the tun or from the
 * tunnel), whereas pcapd has to guess it from the interface. */
static void update_connection_status(pcapdroid_t *pd, tunnel_conn_t *conn,
                                     zdtun_pkt_t *pkt, uint8_t dir) {
    /* NOTE: conn may be freed below, the caller must not use it afterwards */
    if((conn->data->status >= CONN_STATUS_CLOSED) || (pkt->flags & ZDTUN_PKT_IS_FRAGMENT))
        return;

    zdtun_5tuple_t *tuple = &conn->tuple;
    pd_conn_t *data = conn->data;

    if(tuple->ipproto == IPPROTO_TCP) {
        struct tcphdr *tcp = pkt->tcp;

        data->tcp_flags[dir] |= tcp->th_flags;
        uint8_t seen_flags = data->tcp_flags[0] & data->tcp_flags[1];

        if(tcp->th_flags & TH_RST)
            data->status = CONN_STATUS_RESET;
        else if(seen_flags & TH_FIN) {
            if(!data->last_ack)
                data->last_ack = true;
            else if(tcp->th_flags & TH_ACK)
                data->status = CONN_STATUS_CLOSED;
        } else if(data->status < CONN_STATUS_CONNECTED) {
            const uint8_t syn_ack_flags = TH_SYN | TH_ACK;

            if((pkt->l7_len > 0) || ((seen_flags & syn_ack_flags) == syn_ack_flags))
                data->status = CONN_STATUS_CONNECTED;
            else
                data->status = CONN_STATUS_CONNECTING;
        }
    } else {
        if(data->status < CONN_STATUS_CONNECTED)
            data->status = CONN_STATUS_CONNECTED;

        if((tuple->ipproto == IPPROTO_UDP) &&
                (pkt->l7_len >= sizeof(dns_packet_t)) &&
                (tuple->dst_port == ntohs(53))) {
            const dns_packet_t *dns = (dns_packet_t *) pkt->l7;

            if((dns->flags & DNS_FLAGS_MASK) == DNS_TYPE_REQUEST)
                data->pending_dns_queries++;
            else if((dns->flags & DNS_FLAGS_MASK) == DNS_TYPE_RESPONSE) {
                data->pending_dns_queries--;

                if(data->pending_dns_queries == 0) {
                    data->status = CONN_STATUS_CLOSED;

                    /* Drop it from the table so that a reused socket (e.g. the A query
                     * followed by the AAAA query) starts a new connection and its query
                     * gets extracted. */
                    data->to_purge = true;
                    remove_connection(pd, conn);
                }
            }
        }
    }
}

/* ******************************************************* */

static int resolve_uid(pcapdroid_t *pd, const zdtun_5tuple_t *tuple) {
    char buf[256];
    int uid = get_uid(pd->vpn.resolver, tuple);

    zdtun_5tuple2str(tuple, buf, sizeof(buf));

    if(uid >= 0) {
        char appbuf[64];

        get_appname_by_uid(pd, uid, appbuf, sizeof(appbuf));
        log_d("%s [%d/%s]", buf, uid, appbuf);
    } else {
        uid = UID_UNKNOWN;
        log_d("%s => UID not found!", buf);
    }

    return uid;
}

/* ******************************************************* */

/* Looks up the flow a packet belongs to, creating it when needed.
 *
 * `is_tx` tells whether the packet came from the tun (true) or from the tunnel (false).
 * The 5-tuple is always stored in the client-to-server orientation, so an ingress packet
 * is looked up with its peers swapped. */
static tunnel_conn_t* get_connection(pcapdroid_t *pd, zdtun_pkt_t *pkt, bool is_tx,
                                     bool *is_new) {
    tunnel_conn_t *conn = NULL;
    *is_new = false;

    if(!is_tx)
        tupleSwapPeers(&pkt->tuple);

    HASH_FIND(hh, pd->tunnel.connections, &pkt->tuple, sizeof(zdtun_5tuple_t), conn);
    if(conn)
        return conn;

    if((pkt->flags & ZDTUN_PKT_IS_FRAGMENT) && !(pkt->flags & ZDTUN_PKT_IS_FIRST_FRAGMENT)) {
        /* A non-first fragment cannot start a flow: its L4 ports are unknown. It is still
         * relayed by the caller, only the analysis is skipped. */
        pd->num_discarded_fragments++;
        return NULL;
    }

    if(!is_tx) {
        /* An unsolicited inbound packet. In L3 mode the tunnel peer can send anything it
         * wants, so this is tracked as a new (server-initiated) flow rather than dropped,
         * which is what makes port scans and push traffic visible in the connections list. */
        log_d("inbound packet starting a new flow");
    }

    conn = pd_malloc(sizeof(tunnel_conn_t));
    if(!conn) {
        log_f("malloc(tunnel_conn_t) failed [%d]: %s", errno, strerror(errno));
        return NULL;
    }

    pd_conn_t *data = pd_new_connection(pd, &pkt->tuple, resolve_uid(pd, &pkt->tuple));
    if(!data) {
        pd_free(conn);
        return NULL;
    }

    conn->tuple = pkt->tuple;
    conn->data = data;
    HASH_ADD(hh, pd->tunnel.connections, tuple, sizeof(zdtun_5tuple_t), conn);

    switch(conn->tuple.ipproto) {
        case IPPROTO_TCP:
            pd->stats.num_tcp_conn++;
            pd->stats.num_tcp_opened++;
            break;
        case IPPROTO_UDP:
            pd->stats.num_udp_conn++;
            pd->stats.num_udp_opened++;
            break;
        case IPPROTO_ICMP:
            pd->stats.num_icmp_conn++;
            pd->stats.num_icmp_opened++;
            break;
    }

    *is_new = true;
    return conn;
}

/* ******************************************************* */

static struct timeval* get_pkt_timestamp(struct timeval *tv) {
    struct timespec ts;

    if(!clock_gettime(CLOCK_REALTIME, &ts)) {
        tv->tv_sec = ts.tv_sec;
        tv->tv_usec = ts.tv_nsec / 1000;
    }

    return tv;
}

/* ******************************************************* */

/* Decides whether a brand new flow must be blocked.
 *
 * In L3 mode there is no DNAT to apply: the tun advertises the tunnel's own DNS server,
 * so queries already carry their final destination. What remains is the opportunistic
 * private-DNS blocking, which forces the system resolver to fall back to plaintext DNS so
 * that the queries stay readable. */
static bool should_block_new_flow(pcapdroid_t *pd, pkt_context_t *pctx) {
    const zdtun_5tuple_t *tuple = pctx->tuple;

    if(!block_private_dns || (tuple->ipproto == IPPROTO_ICMP))
        return false;

    zdtun_ip_t dst_ip = tuple->dst_ip;
    bool is_dns_server = is_known_dns_ip(&dst_ip, tuple->ipver);

    if(is_dns_server && (tuple->ipproto == IPPROTO_UDP) && (ntohs(tuple->dst_port) == 53)) {
        /* Plaintext DNS to a known resolver: this is what we want, let it through */
        pd->num_dns_requests++;
        return false;
    }

    if(is_dns_server) {
        log_d("blocking the connection to the private DNS server");
        return true;
    }

    return false;
}

/* ******************************************************* */

/* Shared analysis for both directions. Returns true when the packet must be relayed. */
static bool analyze_packet(pcapdroid_t *pd, zdtun_pkt_t *pkt, bool is_tx) {
    bool is_new = false;
    tunnel_conn_t *conn = get_connection(pd, pkt, is_tx, &is_new);

    if(!conn) {
        /* Not trackable (fragment or allocation failure). Relay it anyway: dropping it
         * would break the inner protocols for a bookkeeping reason. */
        return true;
    }

    conn->data->pcap.last_update_ms = pd->now_ms;

    /* Copy the tuple: update_connection_status may free conn while pctx still refers to it */
    zdtun_5tuple_t conn_tuple = conn->tuple;
    pd_conn_t *data = conn->data;

    struct timeval tv = {0};
    pkt_context_t pctx;
    pd_init_pkt_context(&pctx, pkt, is_tx, &conn_tuple, data, get_pkt_timestamp(&tv));
    pd_process_packet(pd, &pctx);

    if(is_new) {
        data->blacklisted_internal |= should_block_new_flow(pd, &pctx);
        data->to_block |= data->blacklisted_internal;
    }

    if(data->to_block) {
        data->blocked_pkts++;
        data->update_type |= CONN_UPDATE_STATS;
        pd_notify_connection_update(pd, &conn_tuple, data);

        /* A blocked flow is closed right away: without a socket to reset, leaving it in
         * the table would only make the app retry into a black hole. */
        data->status = CONN_STATUS_CLOSED;
        data->to_purge = true;
        remove_connection(pd, conn);
        return false;
    }

    update_connection_status(pd, conn, pkt, !is_tx);
    pd_account_stats(pd, &pctx);

    return true;
}

/* ******************************************************* */

static void purge_expired_connections(pcapdroid_t *pd, bool purge_all) {
    tunnel_conn_t *conn, *tmp;

    HASH_ITER(hh, pd->tunnel.connections, conn, tmp) {
        uint64_t timeout = TUNNEL_UDP_TIMEOUT_MS;

        switch(conn->tuple.ipproto) {
            case IPPROTO_TCP:  timeout = TUNNEL_TCP_TIMEOUT_MS;  break;
            case IPPROTO_ICMP: timeout = TUNNEL_ICMP_TIMEOUT_MS; break;
        }

        if(purge_all || (pd->now_ms >= (conn->data->pcap.last_update_ms + timeout))) {
            //log_d("IDLE (type=%d)", conn->tuple.ipproto);

            conn->data->update_type |= CONN_UPDATE_STATS;
            if(conn->data->status < CONN_STATUS_CLOSED)
                conn->data->status = CONN_STATUS_CLOSED;

            if(pd_notify_connection_update(pd, &conn->tuple, conn->data) < 0)
                pd_purge_connection(pd, conn->data);
            else {
                pd_giveup_dpi(pd, conn->data, &conn->tuple);
                conn->data->to_purge = true;
            }

            remove_connection(pd, conn);
        }
    }
}

/* ******************************************************* */

void tunnel_iter_connections(pcapdroid_t *pd, conn_cb cb) {
    tunnel_conn_t *conn, *tmp;

    HASH_ITER(hh, pd->tunnel.connections, conn, tmp) {
        if(cb(pd, &conn->tuple, conn->data) != 0)
            return;
    }
}

/* ******************************************************* */

int run_tunnel(pcapdroid_t *pd) {
    char buffer[VPN_BUFFER_SIZE];
    uint64_t next_purge_ms;
    int rv = -1;

    /* zdtun is used here only as a packet parser: in this datapath it owns no connection
     * and no socket. The same trick is used by run_pcap. */
    zdtun_callbacks_t callbacks = {.send_client = (void *) 1};
    if((pd->zdt = zdtun_init(&callbacks, NULL)) == NULL) {
        log_f("zdtun_init failed");
        return -1;
    }

#if ANDROID
    pd->vpn.resolver = init_uid_resolver(pd->sdk_ver, pd->env, pd->capture_service);
    pd->vpn.ipv4.enabled = (bool) getIntPref(pd->env, pd->capture_service, "getIPv4Enabled");
    pd->vpn.ipv6.enabled = (bool) getIntPref(pd->env, pd->capture_service, "getIPv6Enabled");

    /* Read by vpn_process_ndpi, which pd_process_packet calls for every VpnService-based
     * capture, this one included. Without it, QUIC blocking would silently do nothing. */
    pd->vpn.block_quic_mode = getIntPref(pd->env, pd->capture_service, "getBlockQuickMode");

    /* The DNS fields of pd->vpn stay zeroed on purpose: this datapath performs no DNAT,
     * the tun advertises the tunnel's own DNS server (see docs/tunnel_embedded.md). */
#endif

    pd->tunnel.tun = pd_tunnel_new(pd);
    if(!pd->tunnel.tun) {
        log_f("the embedded tunnel could not be initialized");
        goto cleanup;
    }

    if(pd_tunnel_start(pd->tunnel.tun) != 0) {
        pd_tunnel_status_t status;
        pd_tunnel_get_status(pd->tunnel.tun, &status);
        log_f("the embedded tunnel failed to start: %s", status.last_error);
        goto cleanup;
    }

    int flags = fcntl(pd->vpn.tunfd, F_GETFL, 0);
    if((flags < 0) || (fcntl(pd->vpn.tunfd, F_SETFL, flags & ~O_NONBLOCK) < 0)) {
        log_f("fcntl ~O_NONBLOCK error [%d]: %s", errno, strerror(errno));
        goto cleanup;
    }

    pd_refresh_time(pd);
    next_purge_ms = pd->now_ms + PERIODIC_PURGE_TIMEOUT_MS;

    log_i("Starting the tunnel packet loop");
    if(pd->cb.notify_service_status && running)
        pd->cb.notify_service_status(pd, "started");

    while(running) {
        fd_set fdset;
        fd_set wrfds;
        struct timeval timeout = {.tv_sec = 0, .tv_usec = SELECT_TIMEOUT_MS * 1000};

        FD_ZERO(&fdset);
        FD_ZERO(&wrfds);
        FD_SET(pd->vpn.tunfd, &fdset);
        int max_fd = pd->vpn.tunfd;

        int tunnel_fd = pd_tunnel_fds(pd->tunnel.tun, &fdset, &wrfds);
        if(tunnel_fd >= 0)
            max_fd = max(max_fd, tunnel_fd);

        if((select(max_fd + 1, &fdset, &wrfds, NULL, &timeout) < 0) && (errno != EINTR)) {
            log_e("select failed [%d]: %s", errno, strerror(errno));
            break;
        }

        if(!running)
            break;

        pd_refresh_time(pd);

        /* Egress: from the apps to the tunnel */
        if(FD_ISSET(pd->vpn.tunfd, &fdset)) {
            int size = read(pd->vpn.tunfd, buffer, sizeof(buffer));

            if(size > 0) {
                zdtun_pkt_t pkt;

                if(zdtun_parse_pkt(pd->zdt, buffer, size, &pkt) != 0)
                    log_d("zdtun_parse_pkt failed");
                else if(((pkt.tuple.ipver == 6) && !pd->vpn.ipv6.enabled) ||
                        ((pkt.tuple.ipver == 4) && !pd->vpn.ipv4.enabled)) {
                    char buf[512];
                    log_d("ignoring IPv%d packet: %s", pkt.tuple.ipver,
                          zdtun_5tuple2str(&pkt.tuple, buf, sizeof(buf)));
                } else if(analyze_packet(pd, &pkt, true)) {
                    if(pd_tunnel_send_ip(pd->tunnel.tun, buffer, size) != 0)
                        pd->num_dropped_pkts++;
                }
            } else if(size < 0) {
                if(errno == EIO) {
                    log_i("Got I/O error on the tun (terminating?)");
                    running = false;
                } else
                    log_e("read(tunfd) failed [%d]: %s", errno, strerror(errno));
            }
        }

        /* Ingress: from the tunnel back to the apps.
         * One outer datagram can release several inner packets, so this drains the
         * backend until it reports that nothing is left. */
        while(running) {
            int size = pd_tunnel_recv_ip(pd->tunnel.tun, buffer, sizeof(buffer));

            if(size == 0)
                break;
            if(size < 0) {
                log_f("the embedded tunnel failed, stopping the capture");
                running = false;
                break;
            }

            zdtun_pkt_t pkt;
            if(zdtun_parse_pkt(pd->zdt, buffer, size, &pkt) != 0) {
                log_d("zdtun_parse_pkt failed on an inner packet");
                continue;
            }

            /* Cryptokey routing, enforced before anything else looks at the packet.
             * The datagram is authenticated, so it really came from our peer, but that
             * says nothing about the source address it put in the inner header: without
             * this check a hostile peer could inject packets that appear to come from a
             * LAN host or from a server the app trusts.
             *
             * NOTE: pkt.tuple is still as received here, analyze_packet is what swaps the
             * peers for an ingress packet. */
            /* Copied out of the packed 5-tuple, as the rest of the codebase does, to
             * avoid taking the address of a possibly unaligned member. */
            zdtun_ip_t inner_src = pkt.tuple.src_ip;
            if(!pd_tunnel_allows_source(pd->tunnel.tun, &inner_src, pkt.tuple.ipver)) {
                char buf[512];
                log_w("dropping inner packet with a source outside AllowedIPs: %s",
                      zdtun_5tuple2str(&pkt.tuple, buf, sizeof(buf)));
                pd->tunnel.tun->status.spoofed_pkts++;
                pd->num_dropped_pkts++;
                continue;
            }

            if(!analyze_packet(pd, &pkt, false))
                continue;

            int written = write(pd->vpn.tunfd, buffer, size);
            if(written != size) {
                if(written < 0) {
                    if(errno == ENOBUFS) {
                        log_d("Got ENOBUFS writing to the tun, dropping the packet");
                        pd->num_dropped_pkts++;
                    } else if(errno == EIO) {
                        log_i("Got I/O error on the tun (terminating?)");
                        running = false;
                    } else {
                        log_f("write(tunfd) failed [%d]: %s", errno, strerror(errno));
                        running = false;
                    }
                } else {
                    log_f("partial tun write (%d / %d)", written, size);
                    running = false;
                }
            }
        }

        if(pd_tunnel_tick(pd->tunnel.tun) != 0) {
            pd_tunnel_status_t status;
            pd_tunnel_get_status(pd->tunnel.tun, &status);
            log_f("the embedded tunnel failed: %s", status.last_error);
            running = false;
        }

        pd_housekeeping(pd);

        if(pd->now_ms >= next_purge_ms) {
            purge_expired_connections(pd, false);
            next_purge_ms = pd->now_ms + PERIODIC_PURGE_TIMEOUT_MS;
        }
    }

    rv = 0;

cleanup:
    purge_expired_connections(pd, true);

    if(pd->tunnel.tun) {
        pd_tunnel_free(pd->tunnel.tun);
        pd->tunnel.tun = NULL;
    }

#if ANDROID
    destroy_uid_resolver(pd->vpn.resolver);
    pd->vpn.resolver = NULL;
#endif

    if(pd->zdt) {
        zdtun_finalize(pd->zdt);
        pd->zdt = NULL;
    }

    return rv;
}
