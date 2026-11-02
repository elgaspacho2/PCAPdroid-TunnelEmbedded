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
 * Tests for the embedded tunnel's cryptokey routing, i.e. the check that rejects inner
 * packets whose source address the peer is not allowed to use. A hole here would let an
 * authenticated-but-hostile peer impersonate any host, so the matcher gets its own tests.
 */

#include <assert.h>
#include <string.h>

#include "test_utils.h"
#include "core/pcapdroid.h"
#include "core/tunnel.h"

/* ******************************************************* */

static bool allows(pd_tunnel_t *tun, const char *ip) {
    zdtun_ip_t parsed = {0};
    int ipver = zdtun_parse_ip(ip, &parsed);

    assert(ipver > 0);
    return pd_tunnel_allows_source(tun, &parsed, ipver);
}

static void parse_ok(pd_tunnel_t *tun, const char *list, int expected_entries) {
    assert(pd_tunnel_parse_allowed_ips(tun, list));
    assert(tun->cfg.num_allowed_ips == expected_entries);
}

static void parse_fails(pd_tunnel_t *tun, const char *list) {
    assert(!pd_tunnel_parse_allowed_ips(tun, list));

    /* A rejected list must leave nothing installed, so that the matcher denies
     * everything rather than applying a half-parsed filter */
    assert(tun->cfg.num_allowed_ips == 0);
    assert(!allows(tun, "10.0.0.1"));
    assert(!allows(tun, "2001:db8::1"));
}

/* ******************************************************* */

static void test_full_tunnel() {
    pd_tunnel_t tun = {0};

    parse_ok(&tun, "0.0.0.0/0,::/0", 2);

    assert(allows(&tun, "1.1.1.1"));
    assert(allows(&tun, "10.0.0.1"));
    assert(allows(&tun, "255.255.255.255"));
    assert(allows(&tun, "2001:db8::1"));
    assert(allows(&tun, "fe80::1"));
}

static void test_split_tunnel() {
    pd_tunnel_t tun = {0};

    parse_ok(&tun, "10.0.0.0/8, 192.168.1.0/24", 2);

    assert(allows(&tun, "10.0.0.1"));
    assert(allows(&tun, "10.255.255.254"));
    assert(allows(&tun, "192.168.1.7"));

    assert(!allows(&tun, "11.0.0.1"));
    assert(!allows(&tun, "192.168.2.7"));
    assert(!allows(&tun, "9.255.255.255"));

    /* An IPv4 prefix must never authorize an IPv6 source */
    assert(!allows(&tun, "2001:db8::1"));

    /* Including an IPv4-mapped IPv6 source: the peer could otherwise wrap an address
     * covered by an IPv4 prefix into an IPv6 header and slip past the check.
     * Built by hand because zdtun_parse_ip dispatches on the presence of a '.' and so
     * cannot parse "::ffff:10.0.0.1". */
    zdtun_ip_t mapped = {0};
    uint8_t *bytes = (uint8_t *) &mapped.ip6;
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    bytes[12] = 10; bytes[13] = 0; bytes[14] = 0; bytes[15] = 1;
    assert(!pd_tunnel_allows_source(&tun, &mapped, 6));
}

static void test_non_byte_aligned_prefix() {
    pd_tunnel_t tun = {0};

    /* /12 covers 10.0.0.0 - 10.15.255.255: the boundary is inside a byte, which is where
     * a naive memcmp-only matcher breaks */
    parse_ok(&tun, "10.0.0.0/12", 1);

    assert(allows(&tun, "10.0.0.1"));
    assert(allows(&tun, "10.15.255.255"));
    assert(!allows(&tun, "10.16.0.0"));
    assert(!allows(&tun, "10.255.0.1"));

    parse_ok(&tun, "203.0.113.128/25", 1);
    assert(allows(&tun, "203.0.113.128"));
    assert(allows(&tun, "203.0.113.255"));
    assert(!allows(&tun, "203.0.113.127"));
}

static void test_host_prefix() {
    pd_tunnel_t tun = {0};

    parse_ok(&tun, "198.51.100.7/32", 1);
    assert(allows(&tun, "198.51.100.7"));
    assert(!allows(&tun, "198.51.100.8"));
    assert(!allows(&tun, "198.51.100.6"));
}

static void test_ipv6_prefixes() {
    pd_tunnel_t tun = {0};

    parse_ok(&tun, "2001:db8:1234::/48", 1);
    assert(allows(&tun, "2001:db8:1234::1"));
    assert(allows(&tun, "2001:db8:1234:ffff::1"));
    assert(!allows(&tun, "2001:db8:1235::1"));
    assert(!allows(&tun, "2001:db9:1234::1"));

    /* An IPv6 prefix must never authorize an IPv4 source */
    assert(!allows(&tun, "10.0.0.1"));

    parse_ok(&tun, "fd86:ea04:1115::2/128", 1);
    assert(allows(&tun, "fd86:ea04:1115::2"));
    assert(!allows(&tun, "fd86:ea04:1115::3"));

    /* Non-byte-aligned IPv6 boundary */
    parse_ok(&tun, "2001:db8::/33", 1);
    assert(allows(&tun, "2001:db8:7fff::1"));
    assert(!allows(&tun, "2001:db8:8000::1"));
}

static void test_empty_list_denies_everything() {
    pd_tunnel_t tun = {0};

    /* Fail closed: an unconfigured tunnel must not accept anything */
    assert(!allows(&tun, "10.0.0.1"));
    assert(!allows(&tun, "2001:db8::1"));
    assert(!pd_tunnel_allows_source(NULL, NULL, 4));

    parse_fails(&tun, "");
    parse_fails(&tun, "   ");
    parse_fails(&tun, ",,,");
}

static void test_malformed_lists_are_rejected() {
    pd_tunnel_t tun = {0};

    parse_fails(&tun, "10.0.0.0");               // no prefix length
    parse_fails(&tun, "10.0.0.0/");              // empty prefix length: must not become /0
    parse_fails(&tun, "10.0.0.0/33");            // out of range for IPv4
    parse_fails(&tun, "2001:db8::/129");         // out of range for IPv6
    parse_fails(&tun, "10.0.0.0/-1");
    parse_fails(&tun, "10.0.0.0/8x");            // trailing garbage
    parse_fails(&tun, "not-an-ip/8");
    parse_fails(&tun, "10.0.0.0/8,garbage/16");  // one bad entry fails the whole list
    parse_fails(&tun, "999.0.0.0/8");

    /* A list longer than the native array must be refused, not silently truncated */
    char long_list[2048];
    long_list[0] = '\0';
    for(int i = 0; i < PD_TUNNEL_MAX_ALLOWED_IPS + 1; i++) {
        char entry[32];
        snprintf(entry, sizeof(entry), "%s10.%d.0.0/16", (i > 0) ? "," : "", i);
        strncat(long_list, entry, sizeof(long_list) - strlen(long_list) - 1);
    }
    parse_fails(&tun, long_list);
}

static void test_exactly_max_entries_is_accepted() {
    pd_tunnel_t tun = {0};
    char list[2048];

    list[0] = '\0';
    for(int i = 0; i < PD_TUNNEL_MAX_ALLOWED_IPS; i++) {
        char entry[32];
        snprintf(entry, sizeof(entry), "%s10.%d.0.0/16", (i > 0) ? "," : "", i);
        strncat(list, entry, sizeof(list) - strlen(list) - 1);
    }

    parse_ok(&tun, list, PD_TUNNEL_MAX_ALLOWED_IPS);
    assert(allows(&tun, "10.0.0.1"));
    assert(allows(&tun, "10.31.0.1"));
    assert(!allows(&tun, "10.32.0.1"));
}

/* ******************************************************* */

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <test>\n", argv[0]);
        return 1;
    }

    const char *test = argv[1];

    if(!strcmp(test, "full_tunnel"))                  test_full_tunnel();
    else if(!strcmp(test, "split_tunnel"))            test_split_tunnel();
    else if(!strcmp(test, "non_byte_aligned_prefix")) test_non_byte_aligned_prefix();
    else if(!strcmp(test, "host_prefix"))             test_host_prefix();
    else if(!strcmp(test, "ipv6_prefixes"))           test_ipv6_prefixes();
    else if(!strcmp(test, "empty_list"))              test_empty_list_denies_everything();
    else if(!strcmp(test, "malformed_lists"))         test_malformed_lists_are_rejected();
    else if(!strcmp(test, "max_entries"))             test_exactly_max_entries_is_accepted();
    else {
        fprintf(stderr, "unknown test: %s\n", test);
        return 1;
    }

    printf("%s: OK\n", test);
    return 0;
}
