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
 * Backend-independent part of the embedded tunnel: configuration loading, lifecycle and
 * the status bookkeeping shared by every backend.
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "pcapdroid.h"
#include "tunnel.h"
#include "common/utils.h"

/* ******************************************************* */

const char* pd_tunnel_state2str(pd_tunnel_state_t state) {
    switch(state) {
        case PD_TUNNEL_DOWN:       return "down";
        case PD_TUNNEL_CONNECTING: return "connecting";
        case PD_TUNNEL_UP:         return "up";
        case PD_TUNNEL_ERROR:      return "error";
        default:                   return "?";
    }
}

/* ******************************************************* */

/* Parses the comma-separated AllowedIPs list handed over by the Java side, e.g.
 * "0.0.0.0/0,::/0" or "10.0.0.0/8,192.168.1.5/32".
 *
 * Any malformed entry fails the whole parse: installing a partially applied filter would
 * silently widen or narrow what the peer may send, and neither is acceptable for a
 * security check. */
bool pd_tunnel_parse_allowed_ips(pd_tunnel_t *tun, const char *list) {
    const char *p = list;
    tun->cfg.num_allowed_ips = 0;

    while(*p) {
        while((*p == ',') || (*p == ' '))
            p++;
        if(!*p)
            break;

        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);

        char entry[INET6_ADDRSTRLEN + 8];
        if(len >= sizeof(entry)) {
            log_e("tunnel: AllowedIPs entry too long");
            goto fail;
        }
        memcpy(entry, p, len);
        entry[len] = '\0';

        if(tun->cfg.num_allowed_ips >= PD_TUNNEL_MAX_ALLOWED_IPS) {
            log_e("tunnel: more than %d AllowedIPs entries", PD_TUNNEL_MAX_ALLOWED_IPS);
            goto fail;
        }

        char *slash = strchr(entry, '/');
        if(!slash) {
            log_e("tunnel: AllowedIPs entry '%s' has no prefix length", entry);
            goto fail;
        }
        *slash = '\0';

        pd_tunnel_prefix_t *prefix = &tun->cfg.allowed_ips[tun->cfg.num_allowed_ips];
        int ipver = zdtun_parse_ip(entry, &prefix->ip);
        if((ipver != 4) && (ipver != 6)) {
            log_e("tunnel: AllowedIPs entry '%s' is not an IP address", entry);
            goto fail;
        }

        const char *plen_str = slash + 1;
        char *endptr = NULL;
        long plen = strtol(plen_str, &endptr, 10);
        int maxlen = (ipver == 6) ? 128 : 32;

        /* endptr == plen_str means strtol consumed nothing, as in "10.0.0.0/": without
         * this check plen would stay 0 and the entry would turn into a /0, i.e. allow
         * every source address. */
        if((endptr == plen_str) || *endptr || (plen < 0) || (plen > maxlen)) {
            log_e("tunnel: invalid AllowedIPs prefix length '%s'", slash + 1);
            goto fail;
        }

        prefix->ipver = (uint8_t) ipver;
        prefix->prefixlen = (uint8_t) plen;
        tun->cfg.num_allowed_ips++;

        p = end ? (end + 1) : (p + len);
    }

    if(tun->cfg.num_allowed_ips == 0) {
        log_e("tunnel: no AllowedIPs configured");
        return false;
    }

    return true;

fail:
    /* Leave nothing behind: pd_tunnel_allows_source denies everything on an empty list */
    tun->cfg.num_allowed_ips = 0;
    return false;
}

/* ******************************************************* */

bool pd_tunnel_allows_source(pd_tunnel_t *tun, const zdtun_ip_t *src, int ipver) {
    if(!tun)
        return false;

    for(int i = 0; i < tun->cfg.num_allowed_ips; i++) {
        const pd_tunnel_prefix_t *prefix = &tun->cfg.allowed_ips[i];
        if(prefix->ipver != ipver)
            continue;

        int bits = prefix->prefixlen;
        if(bits == 0)
            return true; /* 0.0.0.0/0 or ::/0: the peer may use any source */

        /* Both addresses are in network byte order, so comparing them byte by byte
         * compares them most-significant bit first. */
        const uint8_t *a = (ipver == 6) ? (const uint8_t *) &src->ip6
                                        : (const uint8_t *) &src->ip4;
        const uint8_t *b = (ipver == 6) ? (const uint8_t *) &prefix->ip.ip6
                                        : (const uint8_t *) &prefix->ip.ip4;

        int whole_bytes = bits / 8;
        int rem_bits = bits % 8;

        if(memcmp(a, b, whole_bytes) != 0)
            continue;

        if(rem_bits) {
            uint8_t mask = (uint8_t) (0xFF << (8 - rem_bits));
            if((a[whole_bytes] & mask) != (b[whole_bytes] & mask))
                continue;
        }

        return true;
    }

    return false;
}

/* ******************************************************* */

#if ANDROID

static bool load_config(pcapdroid_t *pd, pd_tunnel_t *tun) {
    JNIEnv *env = pd->env;
    jobject svc = pd->capture_service;

    tun->cfg.type = (pd_tunnel_type_t) getIntPref(env, svc, "getTunnelType");
    tun->cfg.datapath = (pd_tunnel_datapath_t) getIntPref(env, svc, "getTunnelDatapath");
    tun->cfg.keepalive = (uint16_t) getIntPref(env, svc, "getTunnelKeepalive");
    tun->cfg.mtu = getIntPref(env, svc, "getTunnelMTU");
    tun->cfg.endpoint_port = (uint16_t) getIntPref(env, svc, "getTunnelEndpointPort");

    /* The Java side resolves the endpoint hostname while the capture is being set up, on
     * the underlying network. Doing it here would either leak a DNS query outside the
     * tunnel or deadlock against our own DNS handling. */
    tun->cfg.endpoint_ip = getIPPref(env, svc, "getTunnelEndpointAddress",
                                     &tun->cfg.endpoint_ipver);

    getStringPref(pd, "getTunnelPrivateKey", tun->cfg.private_key, sizeof(tun->cfg.private_key));
    getStringPref(pd, "getTunnelPeerPublicKey", tun->cfg.peer_public_key, sizeof(tun->cfg.peer_public_key));
    getStringPref(pd, "getTunnelPresharedKey", tun->cfg.preshared_key, sizeof(tun->cfg.preshared_key));

    /* getIPPref leaves ipver at 0 for an empty value and sets it to -1 for a malformed
     * one, so anything but 4 or 6 means the Java side has nothing usable for us. */
    if((tun->cfg.endpoint_ipver != 4) && (tun->cfg.endpoint_ipver != 6)) {
        log_e("tunnel: the endpoint address is missing or could not be resolved");
        return false;
    }
    if(tun->cfg.endpoint_port == 0) {
        log_e("tunnel: no endpoint port configured");
        return false;
    }
    if(!tun->cfg.private_key[0] || !tun->cfg.peer_public_key[0]) {
        log_e("tunnel: missing keys");
        return false;
    }

    char allowed_ips[1024];
    allowed_ips[0] = '\0';
    getStringPref(pd, "getTunnelAllowedIps", allowed_ips, sizeof(allowed_ips));
    if(!pd_tunnel_parse_allowed_ips(tun, allowed_ips))
        return false;

    log_i("tunnel: %d AllowedIPs entries", tun->cfg.num_allowed_ips);
    return true;
}

#endif // ANDROID

/* ******************************************************* */

pd_tunnel_t* pd_tunnel_new(pcapdroid_t *pd) {
    pd_tunnel_t *tun = pd_calloc(1, sizeof(pd_tunnel_t));
    if(!tun) {
        log_f("calloc(pd_tunnel_t) failed");
        return NULL;
    }

    tun->pd = pd;
    tun->status.ms_since_handshake = -1;
    tun->status.rtt_ms = -1;

#if ANDROID
    if(!load_config(pd, tun)) {
        pd_free(tun);
        return NULL;
    }
#else
    /* The host build has no capture service to read the settings from. Tunnel mode is
     * only reachable from the app. */
    log_e("tunnel: not supported on this platform");
    pd_free(tun);
    return NULL;
#endif

    switch(tun->cfg.type) {
        case PD_TUNNEL_TYPE_WIREGUARD:
            tun->ops = &pd_tunnel_wireguard_ops;
            break;
        default:
            log_e("tunnel: unsupported tunnel type %d", tun->cfg.type);
            pd_free(tun);
            return NULL;
    }

    log_i("tunnel: %s backend, %s datapath", tun->ops->name,
          (tun->cfg.datapath == PD_TUNNEL_DATAPATH_L3) ? "L3 pass-through" : "L4 proxy");
    return tun;
}

void pd_tunnel_free(pd_tunnel_t *tun) {
    if(!tun)
        return;

    pd_tunnel_stop(tun);

    /* Wipe the keys: the capture service is long-lived and its heap may end up in a
     * crash dump. */
    memset(&tun->cfg, 0, sizeof(tun->cfg));
    pd_free(tun);
}

/* ******************************************************* */

int pd_tunnel_start(pd_tunnel_t *tun) {
    if(!tun || !tun->ops || !tun->ops->start)
        return -1;

    int rv = tun->ops->start(tun);
    if(rv != 0)
        tun->status.state = PD_TUNNEL_ERROR;

    return rv;
}

void pd_tunnel_stop(pd_tunnel_t *tun) {
    if(tun && tun->ops && tun->ops->stop)
        tun->ops->stop(tun);
}

int pd_tunnel_fds(pd_tunnel_t *tun, fd_set *rdfds, fd_set *wrfds) {
    if(!tun || !tun->ops || !tun->ops->fds)
        return -1;

    return tun->ops->fds(tun, rdfds, wrfds);
}

int pd_tunnel_send_ip(pd_tunnel_t *tun, const char *pkt, int len) {
    if(!tun || !tun->ops || !tun->ops->send_ip)
        return -1;

    return tun->ops->send_ip(tun, pkt, len);
}

int pd_tunnel_recv_ip(pd_tunnel_t *tun, char *buf, int bufsize) {
    if(!tun || !tun->ops || !tun->ops->recv_ip)
        return -1;

    return tun->ops->recv_ip(tun, buf, bufsize);
}

int pd_tunnel_tick(pd_tunnel_t *tun) {
    if(!tun || !tun->ops || !tun->ops->tick)
        return -1;

    return tun->ops->tick(tun);
}

void pd_tunnel_get_status(pd_tunnel_t *tun, pd_tunnel_status_t *out) {
    if(!tun) {
        memset(out, 0, sizeof(*out));
        out->ms_since_handshake = -1;
        out->rtt_ms = -1;
        return;
    }

    if(tun->ops && tun->ops->get_status)
        tun->ops->get_status(tun, out);
    else
        *out = tun->status;
}
