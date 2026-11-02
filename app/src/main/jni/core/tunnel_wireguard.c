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
 * WireGuard egress backend.
 *
 * The cryptographic state machine lives in libwgtunnel.so (Rust, built on boringtun);
 * see app/src/main/rust/wgtunnel. This file owns everything the state machine must not
 * know about: the VpnService-protected UDP socket to the peer, the buffers, the 250 ms
 * tick and the status reporting.
 *
 * The Rust library is loaded with dlopen, exactly like libushark.so: libcapture.so does
 * not link against it, so a build without the Rust toolchain still produces a working
 * APK, in which the embedded tunnel simply reports itself as unavailable.
 */

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "pcapdroid.h"
#include "tunnel.h"
#include "common/utils.h"

/* Must match wgt_abi_version() in the Rust crate */
#define WGT_ABI_VERSION 1

/* Mirrors WgtResult in the Rust crate */
#define WGT_DONE              0
#define WGT_WRITE_TO_NETWORK  1
#define WGT_WRITE_TO_TUN      2
#define WGT_ERR              -1
#define WGT_NOBUFFER         -2
#define WGT_RATELIMITED      -3

/* The WireGuard transport header adds 32 bytes to every data packet. The inner MTU is
 * bounded by PD_TUNNEL_MAX_MTU, so this is enough for any packet we can produce, plus
 * room for the handshake messages (148 bytes at most). */
#define PD_TUNNEL_MAX_MTU 9000
#define WG_BUF_SIZE       (PD_TUNNEL_MAX_MTU + 64)

typedef struct wgt_tunnel wgt_tunnel_t;

typedef struct {
    int64_t ms_since_handshake;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    int32_t loss_bp;
    int32_t rtt_ms;
} wgt_stats_t;

/* ******************************************************* */

/* dlopen'd entry points */
static void *wg_dll;
static uint32_t (*wg_abi_version)(void);
static wgt_tunnel_t* (*wg_new)(const char *, const char *, const char *, uint16_t, uint32_t);
static void (*wg_free)(wgt_tunnel_t *);
static int (*wg_encapsulate)(wgt_tunnel_t *, const uint8_t *, size_t, uint8_t *, size_t, size_t *);
static int (*wg_decapsulate)(wgt_tunnel_t *, const uint8_t *, size_t, uint8_t *, size_t, size_t *);
static int (*wg_update_timers)(wgt_tunnel_t *, uint8_t *, size_t, size_t *);
static bool (*wg_stats)(wgt_tunnel_t *, wgt_stats_t *);
static bool (*wg_last_error)(wgt_tunnel_t *, char *, size_t);

typedef struct {
    wgt_tunnel_t *tunn;
    socket_t sock;
    bool drain_pending;   /* boringtun queued packets that must be flushed */
    uint64_t next_tick_ms;
    uint8_t buf[WG_BUF_SIZE];
} wg_priv_t;

/* ******************************************************* */

static void set_error(pd_tunnel_t *tun, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(tun->status.last_error, sizeof(tun->status.last_error), fmt, args);
    va_end(args);

    log_e("wireguard: %s", tun->status.last_error);
}

static bool load_library(pd_tunnel_t *tun) {
    if(wg_dll)
        return true;

    pcapdroid_t *pd = tun->pd;
    char lib_path[PATH_MAX];
    lib_path[0] = '\0';

    if(!pd->cb.get_libprog_path) {
        set_error(tun, "get_libprog_path not defined");
        return false;
    }

    pd->cb.get_libprog_path(pd, "wgtunnel", lib_path, sizeof(lib_path));
    if(!lib_path[0]) {
        set_error(tun, "libwgtunnel.so not found");
        return false;
    }

    wg_dll = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
    if(!wg_dll) {
        set_error(tun, "cannot load libwgtunnel.so: %s", dlerror());
        return false;
    }

    wg_abi_version = dlsym(wg_dll, "wgt_abi_version");
    wg_new = dlsym(wg_dll, "wgt_new");
    wg_free = dlsym(wg_dll, "wgt_free");
    wg_encapsulate = dlsym(wg_dll, "wgt_encapsulate");
    wg_decapsulate = dlsym(wg_dll, "wgt_decapsulate");
    wg_update_timers = dlsym(wg_dll, "wgt_update_timers");
    wg_stats = dlsym(wg_dll, "wgt_stats");
    wg_last_error = dlsym(wg_dll, "wgt_last_error");

    if(!wg_abi_version || !wg_new || !wg_free || !wg_encapsulate || !wg_decapsulate ||
            !wg_update_timers || !wg_stats || !wg_last_error) {
        set_error(tun, "libwgtunnel.so misses required symbols");
        goto fail;
    }

    /* Refuse a stale library rather than calling it with the wrong signatures */
    uint32_t abi = wg_abi_version();
    if(abi != WGT_ABI_VERSION) {
        set_error(tun, "libwgtunnel.so ABI mismatch: got %u, expected %u", abi, WGT_ABI_VERSION);
        goto fail;
    }

    log_i("libwgtunnel.so loaded (ABI %u): %s", abi, lib_path);
    return true;

fail:
    dlclose(wg_dll);
    wg_dll = NULL;
    return false;
}

/* ******************************************************* */

static socket_t open_socket(pd_tunnel_t *tun) {
    int family = (tun->cfg.endpoint_ipver == 6) ? AF_INET6 : AF_INET;

    socket_t sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if(sock == INVALID_SOCKET) {
        set_error(tun, "socket failed [%d]: %s", errno, strerror(errno));
        return INVALID_SOCKET;
    }

#if ANDROID
    /* Must happen before connect, otherwise the datagrams would be routed back into our
     * own tun and the tunnel would talk to itself. */
    pcapdroid_t *pd = tun->pd;
    jboolean is_protected = (*pd->env)->CallBooleanMethod(pd->env, pd->capture_service,
                                                          mids.protect, sock);
    jniCheckException(pd->env);

    if(!is_protected) {
        set_error(tun, "VpnService.protect failed on the tunnel socket");
        close(sock);
        return INVALID_SOCKET;
    }
#endif

    int flags = fcntl(sock, F_GETFL, 0);
    if((flags < 0) || (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)) {
        set_error(tun, "fcntl O_NONBLOCK failed [%d]: %s", errno, strerror(errno));
        close(sock);
        return INVALID_SOCKET;
    }

    /* connect() on a UDP socket lets us use send/recv and surfaces ICMP errors */
    if(family == AF_INET6) {
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(tun->cfg.endpoint_port);
        memcpy(&addr.sin6_addr, &tun->cfg.endpoint_ip.ip6, 16);

        if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            set_error(tun, "connect failed [%d]: %s", errno, strerror(errno));
            close(sock);
            return INVALID_SOCKET;
        }
    } else {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(tun->cfg.endpoint_port);
        addr.sin_addr.s_addr = tun->cfg.endpoint_ip.ip4;

        if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            set_error(tun, "connect failed [%d]: %s", errno, strerror(errno));
            close(sock);
            return INVALID_SOCKET;
        }
    }

    return sock;
}

/* ******************************************************* */

static int wg_start(pd_tunnel_t *tun) {
    if(!load_library(tun))
        return -1;

    if((tun->cfg.mtu <= 0) || (tun->cfg.mtu > PD_TUNNEL_MAX_MTU)) {
        set_error(tun, "invalid tunnel MTU %d", tun->cfg.mtu);
        return -1;
    }

    wg_priv_t *priv = pd_calloc(1, sizeof(wg_priv_t));
    if(!priv) {
        set_error(tun, "wg_priv_t allocation failed");
        return -1;
    }
    priv->sock = INVALID_SOCKET;

    priv->tunn = wg_new(tun->cfg.private_key, tun->cfg.peer_public_key,
                        tun->cfg.preshared_key[0] ? tun->cfg.preshared_key : NULL,
                        tun->cfg.keepalive, 0);
    if(!priv->tunn) {
        /* The Rust side only fails here on an undecodable key */
        set_error(tun, "invalid WireGuard keys");
        pd_free(priv);
        return -1;
    }

    priv->sock = open_socket(tun);
    if(priv->sock == INVALID_SOCKET) {
        wg_free(priv->tunn);
        pd_free(priv);
        return -1;
    }

    tun->priv = priv;
    tun->status.state = PD_TUNNEL_CONNECTING;
    tun->status.ms_since_handshake = -1;
    tun->status.rtt_ms = -1;

    char ipstr[INET6_ADDRSTRLEN] = "?";
    inet_ntop((tun->cfg.endpoint_ipver == 6) ? AF_INET6 : AF_INET,
              &tun->cfg.endpoint_ip, ipstr, sizeof(ipstr));
    log_i("WireGuard tunnel started, endpoint %s:%u, mtu %d, keepalive %u",
          ipstr, tun->cfg.endpoint_port, tun->cfg.mtu, tun->cfg.keepalive);

    /* Kick the handshake immediately instead of waiting for the first packet, so that the
     * tunnel is usually up by the time an app sends anything. */
    pd_refresh_time(tun->pd);
    priv->next_tick_ms = 0;
    return 0;
}

static void wg_stop(pd_tunnel_t *tun) {
    wg_priv_t *priv = (wg_priv_t *) tun->priv;
    if(!priv)
        return;

    if(priv->sock != INVALID_SOCKET)
        close(priv->sock);
    if(priv->tunn)
        wg_free(priv->tunn);

    pd_free(priv);
    tun->priv = NULL;
    tun->status.state = PD_TUNNEL_DOWN;
}

static int wg_fds(pd_tunnel_t *tun, fd_set *rdfds, fd_set *wrfds) {
    wg_priv_t *priv = (wg_priv_t *) tun->priv;
    if(!priv || (priv->sock == INVALID_SOCKET))
        return -1;

    FD_SET(priv->sock, rdfds);
    return priv->sock;
}

/* Sends a datagram produced by the Rust side to the peer. */
static void send_to_peer(pd_tunnel_t *tun, const uint8_t *buf, size_t len) {
    wg_priv_t *priv = (wg_priv_t *) tun->priv;

    ssize_t rv = send(priv->sock, buf, len, 0);
    if(rv == (ssize_t)len) {
        tun->status.tx_datagrams++;
        return;
    }

    if(rv < 0) {
        /* ECONNREFUSED is reported on a connected UDP socket when the peer is not
         * listening; EAGAIN means the send buffer is full. Neither is fatal: WireGuard
         * retries handshakes on its own and the inner protocols handle the loss. */
        if((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == ECONNREFUSED) ||
                (errno == ENETUNREACH) || (errno == EHOSTUNREACH)) {
            log_d("tunnel send failed [%d]: %s", errno, strerror(errno));
            tun->status.dropped_pkts++;
            return;
        }

        set_error(tun, "tunnel send failed [%d]: %s", errno, strerror(errno));
        tun->status.state = PD_TUNNEL_ERROR;
        return;
    }

    log_w("partial tunnel send (%zd / %zu)", rv, len);
    tun->status.dropped_pkts++;
}

static int wg_send_ip(pd_tunnel_t *tun, const char *pkt, int len) {
    wg_priv_t *priv = (wg_priv_t *) tun->priv;
    size_t written = 0;

    if(!priv || (len <= 0))
        return -1;

    if(len > tun->cfg.mtu) {
        /* The tun MTU is set from the tunnel configuration, so this should not happen;
         * dropping is still better than emitting a datagram the path cannot carry. */
        log_d("dropping %d bytes packet, over the tunnel MTU (%d)", len, tun->cfg.mtu);
        tun->status.dropped_pkts++;
        return -1;
    }

    int rv = wg_encapsulate(priv->tunn, (const uint8_t *)pkt, len,
                            priv->buf, sizeof(priv->buf), &written);

    switch(rv) {
        case WGT_WRITE_TO_NETWORK:
            send_to_peer(tun, priv->buf, written);
            tun->status.tx_bytes += len;
            return 0;

        case WGT_DONE:
            /* Queued until the handshake completes: boringtun will release it on the next
             * decapsulate/tick, so this is a success for the caller. */
            tun->status.tx_bytes += len;
            return 0;

        case WGT_RATELIMITED:
            log_d("tunnel handshake rate limited, dropping packet");
            tun->status.dropped_pkts++;
            return -1;

        default: {
            char err[128];
            if(wg_last_error(priv->tunn, err, sizeof(err)))
                log_d("encapsulate failed: %s", err);
            else
                log_d("encapsulate failed (%d)", rv);
            tun->status.dropped_pkts++;
            return -1;
        }
    }
}

static int wg_recv_ip(pd_tunnel_t *tun, char *buf, int bufsize) {
    wg_priv_t *priv = (wg_priv_t *) tun->priv;
    if(!priv)
        return -1;

    /* Bounded to keep one call from starving the tun side of the datapath */
    for(int iter = 0; iter < 64; iter++) {
        size_t written = 0;
        int rv;

        if(priv->drain_pending) {
            /* boringtun releases the packets queued during the handshake only when
             * decapsulate is called with an empty datagram (see the
             * handshake_completes_between_two_tunnels test in the Rust crate). */
            rv = wg_decapsulate(priv->tunn, NULL, 0, priv->buf, sizeof(priv->buf), &written);
        } else {
            uint8_t datagram[WG_BUF_SIZE];
            ssize_t r = recv(priv->sock, datagram, sizeof(datagram), 0);

            if(r < 0) {
                if((errno == EAGAIN) || (errno == EWOULDBLOCK))
                    return 0;
                if((errno == ECONNREFUSED) || (errno == ENETUNREACH) || (errno == EHOSTUNREACH)) {
                    /* Queued ICMP error from a previous send; the socket stays usable */
                    log_d("tunnel recv error [%d]: %s", errno, strerror(errno));
                    continue;
                }

                set_error(tun, "tunnel recv failed [%d]: %s", errno, strerror(errno));
                return -1;
            }
            if(r == 0)
                return 0;

            tun->status.rx_datagrams++;
            rv = wg_decapsulate(priv->tunn, datagram, r, priv->buf, sizeof(priv->buf), &written);
        }

        switch(rv) {
            case WGT_WRITE_TO_NETWORK:
                /* A handshake message, a cookie reply or a queued data packet */
                send_to_peer(tun, priv->buf, written);
                priv->drain_pending = true;
                continue;

            case WGT_WRITE_TO_TUN:
                if((int)written > bufsize) {
                    log_w("inner packet (%zu) over the datapath buffer (%d), dropping",
                          written, bufsize);
                    tun->status.dropped_pkts++;
                    continue;
                }
                memcpy(buf, priv->buf, written);
                tun->status.rx_bytes += written;
                return (int) written;

            case WGT_DONE:
                if(priv->drain_pending) {
                    priv->drain_pending = false;
                    continue;
                }
                /* Keepalive or an empty datagram: nothing to deliver */
                continue;

            default:
                /* Malformed or unauthenticated datagram. Expected on an open UDP port, so
                 * it is only logged at debug level and never stops the capture. */
                log_d("decapsulate failed (%d)", rv);
                priv->drain_pending = false;
                continue;
        }
    }

    return 0;
}

static int wg_tick(pd_tunnel_t *tun) {
    wg_priv_t *priv = (wg_priv_t *) tun->priv;
    if(!priv)
        return -1;

    pcapdroid_t *pd = tun->pd;
    if(pd->now_ms < priv->next_tick_ms)
        return 0;
    priv->next_tick_ms = pd->now_ms + PD_TUNNEL_TICK_MS;

    size_t written = 0;
    int rv = wg_update_timers(priv->tunn, priv->buf, sizeof(priv->buf), &written);

    if(rv == WGT_WRITE_TO_NETWORK)
        send_to_peer(tun, priv->buf, written);
    else if(rv < 0 && rv != WGT_RATELIMITED) {
        char err[128];
        if(wg_last_error(priv->tunn, err, sizeof(err)))
            log_d("update_timers: %s", err);
    }

    return (tun->status.state == PD_TUNNEL_ERROR) ? -1 : 0;
}

static void wg_get_status(pd_tunnel_t *tun, pd_tunnel_status_t *out) {
    wg_priv_t *priv = (wg_priv_t *) tun->priv;

    *out = tun->status;
    if(!priv)
        return;

    wgt_stats_t stats = {0};
    if(wg_stats(priv->tunn, &stats)) {
        out->ms_since_handshake = stats.ms_since_handshake;
        out->rtt_ms = stats.rtt_ms;

        /* REJECT_AFTER_TIME is 180 s in the WireGuard spec: past that, the session is
         * dead and a new handshake is required. */
        if(out->state != PD_TUNNEL_ERROR)
            out->state = ((stats.ms_since_handshake >= 0) && (stats.ms_since_handshake < 180000))
                         ? PD_TUNNEL_UP : PD_TUNNEL_CONNECTING;
    }
}

/* ******************************************************* */

const pd_tunnel_ops_t pd_tunnel_wireguard_ops = {
    .name = "wireguard",
    .start = wg_start,
    .stop = wg_stop,
    .fds = wg_fds,
    .send_ip = wg_send_ip,
    .recv_ip = wg_recv_ip,
    .tick = wg_tick,
    .get_status = wg_get_status,
};
