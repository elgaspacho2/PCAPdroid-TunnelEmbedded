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

#ifndef __PD_TUNNEL_H__
#define __PD_TUNNEL_H__

#include <stdbool.h>
#include <sys/select.h>

#include "zdtun.h"

/* Forward declaration only: pcapdroid.h includes this header, so this file must not
 * include it back. */
struct pcapdroid;

typedef struct pd_tunnel pd_tunnel_t;

/* ******************************************************* */

/* The egress backend used by the capture.
 *
 * PD_EGRESS_SOCKETS is the historical behaviour: zdtun terminates each connection and
 * reconnects it through a VpnService-protected L4 socket. The kernel rewrites the
 * headers, which is why the resulting PCAP cannot be analyzed packet by packet.
 *
 * PD_EGRESS_TUNNEL routes the captured packets through a tunnel that lives inside the
 * app. Because the tunnel's own outer socket is a plain protected UDP socket, PCAPdroid
 * can relay the inner IP packets verbatim without needing root, and therefore holds the
 * single per-profile VpnService slot while the "real" VPN runs embedded in the app. */
typedef enum {
    PD_EGRESS_SOCKETS = 0,
    PD_EGRESS_TUNNEL = 1,
} pd_egress_mode_t;

/* How the packets reach the tunnel.
 *
 * PD_TUNNEL_DATAPATH_L3 relays the IP packets as they come out of the tun, with no
 * userspace NAT at all. Flow tracking is done by observing the packets, as in root mode.
 * This is the faithful datapath: the PCAP matches what the apps actually sent.
 *
 * PD_TUNNEL_DATAPATH_L4 keeps zdtun's userspace NAT, so the features that need an L4
 * proxy (TLS decryption through the mitm addon, port mapping, SOCKS5 chaining) keep
 * working. It requires a userspace TCP/IP stack to turn the proxied sockets back into IP
 * packets; see docs/tunnel_embedded.md for the status of that work. */
typedef enum {
    PD_TUNNEL_DATAPATH_L3 = 0,
    PD_TUNNEL_DATAPATH_L4 = 1,
} pd_tunnel_datapath_t;

typedef enum {
    PD_TUNNEL_TYPE_NONE = 0,
    PD_TUNNEL_TYPE_WIREGUARD = 1,
} pd_tunnel_type_t;

/* ******************************************************* */

typedef enum {
    PD_TUNNEL_DOWN = 0,       /* not started, or stopped */
    PD_TUNNEL_CONNECTING,     /* started, no completed handshake yet */
    PD_TUNNEL_UP,             /* a session is established */
    PD_TUNNEL_ERROR,          /* unrecoverable: the capture must be stopped */
} pd_tunnel_state_t;

typedef struct {
    pd_tunnel_state_t state;
    int64_t ms_since_handshake;  /* -1 when no handshake completed yet */
    uint64_t tx_bytes;           /* inner (plaintext) bytes sent into the tunnel */
    uint64_t rx_bytes;           /* inner (plaintext) bytes received from the tunnel */
    uint64_t tx_datagrams;       /* outer UDP datagrams sent */
    uint64_t rx_datagrams;       /* outer UDP datagrams received */
    uint64_t dropped_pkts;       /* inner packets dropped (encap errors, buffer, MTU) */
    int rtt_ms;                  /* -1 when unknown */
    char last_error[128];        /* empty when there is nothing to report */
} pd_tunnel_status_t;

/* ******************************************************* */

typedef struct {
    const char *name;

    /* Brings the tunnel up. Returns 0 on success. On failure the backend must leave
     * nothing allocated and may fill `status.last_error`. */
    int (*start)(pd_tunnel_t *tun);

    /* Tears the tunnel down. Must tolerate being called after a failed start. */
    void (*stop)(pd_tunnel_t *tun);

    /* Adds the backend's descriptors to the select sets and returns the highest one,
     * or -1 when the backend has no descriptor to watch. */
    int (*fds)(pd_tunnel_t *tun, fd_set *rdfds, fd_set *wrfds);

    /* Sends one plaintext IP packet into the tunnel.
     * Returns 0 when the packet was sent or legitimately queued (e.g. while the handshake
     * is still in flight), and -1 when it was dropped. A drop is never fatal: the
     * datapath only accounts it. */
    int (*send_ip)(pd_tunnel_t *tun, const char *pkt, int len);

    /* Returns the next plaintext IP packet coming out of the tunnel.
     * Returns the packet length, 0 when nothing more is available right now, and -1 on a
     * fatal error. The datapath calls this in a loop until it returns 0, because a single
     * outer datagram can release several inner packets. */
    int (*recv_ip)(pd_tunnel_t *tun, char *buf, int bufsize);

    /* Runs the backend's timers (handshakes, keepalives, rekeying).
     * Returns 0 on success, -1 on a fatal error. */
    int (*tick)(pd_tunnel_t *tun);

    void (*get_status)(pd_tunnel_t *tun, pd_tunnel_status_t *out);
} pd_tunnel_ops_t;

/* ******************************************************* */

struct pd_tunnel {
    const pd_tunnel_ops_t *ops;
    struct pcapdroid *pd;
    void *priv;

    /* Configuration, filled by pd_tunnel_new from the Java-side settings */
    struct {
        pd_tunnel_type_t type;
        pd_tunnel_datapath_t datapath;

        /* The peer endpoint, already resolved to a literal address by the Java side: at
         * startup there is no tunnel yet, and resolving a hostname here would leak a DNS
         * query outside the tunnel and race with the capture's own DNS handling. */
        zdtun_ip_t endpoint_ip;
        int endpoint_ipver;
        uint16_t endpoint_port;   /* host byte order */

        uint16_t keepalive;       /* seconds, 0 to disable */
        int mtu;                  /* inner MTU, i.e. the tun MTU */

        char private_key[64];
        char peer_public_key[64];
        char preshared_key[64];
    } cfg;

    pd_tunnel_status_t status;
};

/* ******************************************************* */

/* Allocates a tunnel from the settings exposed by the capture service.
 * Returns NULL when the tunnel egress is disabled or misconfigured. The caller owns the
 * returned object and must release it with pd_tunnel_free. */
pd_tunnel_t* pd_tunnel_new(struct pcapdroid *pd);

void pd_tunnel_free(pd_tunnel_t *tun);

/* Thin wrappers that keep the NULL checks and the status bookkeeping in one place. */
int pd_tunnel_start(pd_tunnel_t *tun);
void pd_tunnel_stop(pd_tunnel_t *tun);
int pd_tunnel_fds(pd_tunnel_t *tun, fd_set *rdfds, fd_set *wrfds);
int pd_tunnel_send_ip(pd_tunnel_t *tun, const char *pkt, int len);
int pd_tunnel_recv_ip(pd_tunnel_t *tun, char *buf, int bufsize);
int pd_tunnel_tick(pd_tunnel_t *tun);
void pd_tunnel_get_status(pd_tunnel_t *tun, pd_tunnel_status_t *out);
const char* pd_tunnel_state2str(pd_tunnel_state_t state);

/* Backend constructors. Implemented by the tunnel_*.c files. */
extern const pd_tunnel_ops_t pd_tunnel_wireguard_ops;

/* The L3 pass-through datapath, implemented in capture_tunnel.c */
extern int run_tunnel(struct pcapdroid *pd);

/* How often the backend timers must run. WireGuard's state machine is specified in terms
 * of 250 ms ticks, which also matches SELECT_TIMEOUT_MS. */
#define PD_TUNNEL_TICK_MS 250

#endif // __PD_TUNNEL_H__
