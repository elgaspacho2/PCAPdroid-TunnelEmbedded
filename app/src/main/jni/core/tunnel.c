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

#include <string.h>

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
