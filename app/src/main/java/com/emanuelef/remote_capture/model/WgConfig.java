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

package com.emanuelef.remote_capture.model;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.Serializable;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * The configuration of the WireGuard tunnel embedded in the app.
 *
 * It is parsed from the wg-quick format, so that a user can paste the very same file their
 * VPN provider or their own server handed them. Only the subset of the format that is
 * meaningful inside PCAPdroid is honoured; see {@link #parse(String)} for what is ignored
 * and why.
 */
public class WgConfig implements Serializable {
    /** A base64 X25519 key is 44 characters, including the trailing '=' */
    private static final int KEY_B64_LEN = 44;

    /** wg-quick's own default when the Interface section does not set one */
    public static final int DEFAULT_MTU = 1420;

    /** Smallest MTU that still lets IPv6 work (RFC 8200) */
    public static final int MIN_MTU = 1280;

    /** The tun MTU cannot exceed what the outer path can carry */
    public static final int MAX_MTU = 1500;

    /** Must stay in sync with PD_TUNNEL_MAX_ALLOWED_IPS in jni/core/tunnel.h */
    public static final int MAX_ALLOWED_IPS = 32;

    public static class InetPrefix implements Serializable {
        public final String address;
        public final int prefixLen;

        public InetPrefix(String address, int prefixLen) {
            this.address = address;
            this.prefixLen = prefixLen;
        }

        public boolean isIPv6() {
            return address.contains(":");
        }

        @NonNull
        @Override
        public String toString() {
            return address + "/" + prefixLen;
        }
    }

    // [Interface]
    public String privateKey = "";
    public final List<InetPrefix> addresses = new ArrayList<>();
    public final List<String> dnsServers = new ArrayList<>();
    public int mtu = DEFAULT_MTU;

    // [Peer]
    public String peerPublicKey = "";
    public String presharedKey = "";
    public String endpointHost = "";
    public int endpointPort;
    public final List<InetPrefix> allowedIps = new ArrayList<>();
    public int persistentKeepalive;

    /**
     * The endpoint address, resolved to a literal IP by the capture service before the tun
     * is established. Kept apart from {@link #endpointHost} so that the original hostname
     * stays visible in the UI.
     */
    public String resolvedEndpoint = "";

    /* ******************************************************* */

    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
    }

    /* ******************************************************* */

    /**
     * Parses a wg-quick configuration file.
     *
     * The keys that only make sense for the wg-quick script itself (PreUp, PostUp,
     * PreDown, PostDown, Table, SaveConfig, FwMark) are ignored: PCAPdroid configures the
     * tun through VpnService.Builder, not through ip(8), and running shell hooks from the
     * app would be both impossible without root and a nasty injection vector.
     */
    public static WgConfig parse(String text) throws ParseException {
        if ((text == null) || text.trim().isEmpty())
            throw new ParseException("empty configuration");

        WgConfig cfg = new WgConfig();
        String section = "";
        int peers = 0;
        int lineno = 0;

        for (String rawLine: text.split("\\R")) {
            lineno++;

            // Strip comments. '#' is the wg-quick comment marker; ';' is accepted too, as
            // some exporters use it.
            int comment = rawLine.indexOf('#');
            if (comment >= 0)
                rawLine = rawLine.substring(0, comment);
            comment = rawLine.indexOf(';');
            if (comment >= 0)
                rawLine = rawLine.substring(0, comment);

            String line = rawLine.trim();
            if (line.isEmpty())
                continue;

            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length() - 1).trim().toLowerCase(Locale.ROOT);

                if (section.equals("peer") && (++peers > 1))
                    throw new ParseException("multiple [Peer] sections are not supported: " +
                            "the embedded tunnel talks to a single peer");
                continue;
            }

            int eq = line.indexOf('=');
            if (eq <= 0)
                throw new ParseException("line " + lineno + ": expected key = value");

            String key = line.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(eq + 1).trim();

            if (value.isEmpty())
                throw new ParseException("line " + lineno + ": empty value for " + key);

            switch (section) {
                case "interface": parseInterfaceKey(cfg, key, value, lineno); break;
                case "peer":      parsePeerKey(cfg, key, value, lineno); break;
                default:
                    throw new ParseException("line " + lineno + ": value outside of a section");
            }
        }

        validate(cfg);
        return cfg;
    }

    private static void parseInterfaceKey(WgConfig cfg, String key, String value, int lineno)
            throws ParseException {
        switch (key) {
            case "privatekey":
                cfg.privateKey = requireKey(value, "PrivateKey", lineno);
                break;
            case "address":
                for (String part: value.split(","))
                    cfg.addresses.add(parsePrefix(part.trim(), lineno));
                break;
            case "dns":
                for (String part: value.split(",")) {
                    String dns = part.trim();
                    if (dns.isEmpty())
                        continue;

                    // wg-quick also accepts search domains here; those are not something
                    // VpnService.Builder can express, so they are skipped rather than
                    // rejected, to keep real-world configs usable.
                    if (isIpAddress(dns))
                        cfg.dnsServers.add(dns);
                }
                break;
            case "mtu":
                cfg.mtu = parseInt(value, "MTU", lineno);
                break;
            case "preup": case "postup": case "predown": case "postdown":
            case "table": case "saveconfig": case "fwmark":
                // Deliberately ignored, see the method documentation
                break;
            default:
                throw new ParseException("line " + lineno + ": unknown [Interface] key '" + key + "'");
        }
    }

    private static void parsePeerKey(WgConfig cfg, String key, String value, int lineno)
            throws ParseException {
        switch (key) {
            case "publickey":
                cfg.peerPublicKey = requireKey(value, "PublicKey", lineno);
                break;
            case "presharedkey":
                cfg.presharedKey = requireKey(value, "PresharedKey", lineno);
                break;
            case "endpoint": {
                int sep = value.lastIndexOf(':');
                if (sep <= 0)
                    throw new ParseException("line " + lineno + ": Endpoint must be host:port");

                String host = value.substring(0, sep).trim();
                // A bracketed IPv6 literal, as in [2001:db8::1]:51820
                if (host.startsWith("[") && host.endsWith("]"))
                    host = host.substring(1, host.length() - 1);

                if (host.isEmpty())
                    throw new ParseException("line " + lineno + ": Endpoint has no host");

                cfg.endpointHost = host;
                cfg.endpointPort = parseInt(value.substring(sep + 1).trim(), "Endpoint port", lineno);

                if ((cfg.endpointPort <= 0) || (cfg.endpointPort > 65535))
                    throw new ParseException("line " + lineno + ": invalid Endpoint port");
                break;
            }
            case "allowedips":
                for (String part: value.split(","))
                    cfg.allowedIps.add(parsePrefix(part.trim(), lineno));
                break;
            case "persistentkeepalive":
                cfg.persistentKeepalive = parseInt(value, "PersistentKeepalive", lineno);
                if ((cfg.persistentKeepalive < 0) || (cfg.persistentKeepalive > 65535))
                    throw new ParseException("line " + lineno + ": invalid PersistentKeepalive");
                break;
            default:
                throw new ParseException("line " + lineno + ": unknown [Peer] key '" + key + "'");
        }
    }

    /* ******************************************************* */

    private static void validate(WgConfig cfg) throws ParseException {
        if (cfg.privateKey.isEmpty())
            throw new ParseException("[Interface] PrivateKey is missing");
        if (cfg.peerPublicKey.isEmpty())
            throw new ParseException("[Peer] PublicKey is missing");
        if (cfg.endpointHost.isEmpty())
            throw new ParseException("[Peer] Endpoint is missing");
        if (cfg.addresses.isEmpty())
            throw new ParseException("[Interface] Address is missing");

        if ((cfg.mtu < MIN_MTU) || (cfg.mtu > MAX_MTU))
            throw new ParseException("[Interface] MTU must be between " + MIN_MTU + " and " + MAX_MTU);

        if (cfg.allowedIps.size() > MAX_ALLOWED_IPS)
            throw new ParseException("[Peer] AllowedIPs has more than " + MAX_ALLOWED_IPS + " entries");

        if (cfg.allowedIps.isEmpty()) {
            // wg-quick has no default here, but a capture tool is only useful when it sees
            // everything, so fall back to a full tunnel.
            cfg.allowedIps.add(new InetPrefix("0.0.0.0", 0));
            cfg.allowedIps.add(new InetPrefix("::", 0));
        }
    }

    private static String requireKey(String value, String name, int lineno) throws ParseException {
        String key = value.trim();

        // Hex keys are accepted by the native layer too, so allow them here
        if (key.length() == 64 && key.matches("[0-9a-fA-F]+"))
            return key;

        if (key.length() != KEY_B64_LEN)
            throw new ParseException("line " + lineno + ": " + name + " is not a valid key");

        try {
            if (Base64.getDecoder().decode(key).length != 32)
                throw new ParseException("line " + lineno + ": " + name + " is not a valid key");
        } catch (IllegalArgumentException e) {
            throw new ParseException("line " + lineno + ": " + name + " is not valid base64");
        }

        return key;
    }

    private static InetPrefix parsePrefix(String value, int lineno) throws ParseException {
        if (value.isEmpty())
            throw new ParseException("line " + lineno + ": empty address");

        String addr = value;
        int prefixLen = -1;
        int slash = value.indexOf('/');

        if (slash >= 0) {
            addr = value.substring(0, slash).trim();
            prefixLen = parseInt(value.substring(slash + 1).trim(), "prefix length", lineno);
        }

        if (!isIpAddress(addr))
            throw new ParseException("line " + lineno + ": '" + addr + "' is not an IP address");

        boolean isV6 = addr.contains(":");
        int maxPrefix = isV6 ? 128 : 32;

        if (prefixLen < 0)
            prefixLen = maxPrefix;
        else if (prefixLen > maxPrefix)
            throw new ParseException("line " + lineno + ": prefix length out of range for " + addr);

        return new InetPrefix(addr, prefixLen);
    }

    private static int parseInt(String value, String name, int lineno) throws ParseException {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new ParseException("line " + lineno + ": " + name + " is not a number");
        }
    }

    /**
     * Checks that a string is an IP literal, without ever resolving it: a DNS lookup here
     * would both block the UI thread and leak the name outside the tunnel.
     */
    private static boolean isIpAddress(String s) {
        if (s.isEmpty())
            return false;

        if (s.contains(":")) {
            // An IPv6 literal cannot be a hostname, so a parse failure is decisive
            try {
                return InetAddress.getByName(s) instanceof Inet6Address;
            } catch (UnknownHostException e) {
                return false;
            }
        }

        // IPv4 dotted quad, checked by hand so that "example.com" is never resolved
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4)
            return false;

        for (String part: parts) {
            if (part.isEmpty() || (part.length() > 3) || !part.matches("[0-9]+"))
                return false;
            if (Integer.parseInt(part) > 255)
                return false;
        }

        return true;
    }

    /* ******************************************************* */

    @Nullable
    public InetPrefix getFirstAddress(boolean ipv6) {
        for (InetPrefix prefix: addresses) {
            if (prefix.isIPv6() == ipv6)
                return prefix;
        }
        return null;
    }

    public boolean hasIPv4Address() {
        return getFirstAddress(false) != null;
    }

    public boolean hasIPv6Address() {
        return getFirstAddress(true) != null;
    }

    /** True when the peer's AllowedIPs cover the whole address space of the given family */
    public boolean isFullTunnel(boolean ipv6) {
        for (InetPrefix prefix: allowedIps) {
            if ((prefix.isIPv6() == ipv6) && (prefix.prefixLen == 0))
                return true;
        }
        return false;
    }

    @NonNull
    @Override
    public String toString() {
        // NOTE: never include the keys, this ends up in the logs
        return "WgConfig{endpoint=" + endpointHost + ":" + endpointPort +
                ", addresses=" + addresses +
                ", dns=" + dnsServers +
                ", allowedIps=" + allowedIps +
                ", mtu=" + mtu +
                ", keepalive=" + persistentKeepalive + "}";
    }
}
