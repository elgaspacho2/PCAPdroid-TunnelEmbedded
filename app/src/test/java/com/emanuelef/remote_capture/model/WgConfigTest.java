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

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class WgConfigTest {
    /* Two valid base64 X25519 keys, generated for the test. They are not used anywhere. */
    private static final String PRIV_KEY = "aFq3tPHEZxkyZbqPsZ5r5xnWJVQNRYy4kXHNPzvQYVo=";
    private static final String PUB_KEY  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    private static final String PSK      = "FpCFb3FxdhPHe+GGBhLw1vLa4LgGrKhMhaCmGaZxJ3M=";

    private static final String FULL_CONFIG =
            "[Interface]\n" +
            "PrivateKey = " + PRIV_KEY + "\n" +
            "Address = 10.6.0.2/32, fd86:ea04:1115::2/128\n" +
            "DNS = 10.6.0.1, fd86:ea04:1115::1\n" +
            "MTU = 1420\n" +
            "\n" +
            "[Peer]\n" +
            "PublicKey = " + PUB_KEY + "\n" +
            "PresharedKey = " + PSK + "\n" +
            "AllowedIPs = 0.0.0.0/0, ::/0\n" +
            "Endpoint = vpn.example.com:51820\n" +
            "PersistentKeepalive = 25\n";

    @Test
    public void parsesAFullWgQuickConfig() throws Exception {
        WgConfig cfg = WgConfig.parse(FULL_CONFIG);

        assertEquals(PRIV_KEY, cfg.privateKey);
        assertEquals(PUB_KEY, cfg.peerPublicKey);
        assertEquals(PSK, cfg.presharedKey);
        assertEquals("vpn.example.com", cfg.endpointHost);
        assertEquals(51820, cfg.endpointPort);
        assertEquals(1420, cfg.mtu);
        assertEquals(25, cfg.persistentKeepalive);

        assertEquals(2, cfg.addresses.size());
        assertEquals("10.6.0.2", cfg.addresses.get(0).address);
        assertEquals(32, cfg.addresses.get(0).prefixLen);
        assertTrue(cfg.addresses.get(1).isIPv6());

        assertEquals(2, cfg.dnsServers.size());
        assertEquals("10.6.0.1", cfg.dnsServers.get(0));

        assertTrue(cfg.hasIPv4Address());
        assertTrue(cfg.hasIPv6Address());
        assertTrue(cfg.isFullTunnel(false));
        assertTrue(cfg.isFullTunnel(true));
    }

    @Test
    public void appliesTheWgQuickDefaults() throws Exception {
        WgConfig cfg = WgConfig.parse(
                "[Interface]\n" +
                "PrivateKey = " + PRIV_KEY + "\n" +
                "Address = 10.6.0.2/32\n" +
                "[Peer]\n" +
                "PublicKey = " + PUB_KEY + "\n" +
                "Endpoint = 198.51.100.7:51820\n");

        assertEquals(WgConfig.DEFAULT_MTU, cfg.mtu);
        assertEquals(0, cfg.persistentKeepalive);
        assertEquals("", cfg.presharedKey);
        // No AllowedIPs means "capture everything", not "capture nothing"
        assertTrue(cfg.isFullTunnel(false));
        assertTrue(cfg.isFullTunnel(true));
    }

    @Test
    public void handlesCommentsBlankLinesAndCaseInsensitiveKeys() throws Exception {
        WgConfig cfg = WgConfig.parse(
                "# my provider's config\n" +
                "[interface]\n" +
                "  privatekey=" + PRIV_KEY + "   # the key\n" +
                "\n" +
                "ADDRESS = 10.6.0.2/32\n" +
                "; another comment style\n" +
                "[PEER]\n" +
                "PUBLICKEY = " + PUB_KEY + "\n" +
                "Endpoint=198.51.100.7:51820\n");

        assertEquals(PRIV_KEY, cfg.privateKey);
        assertEquals("198.51.100.7", cfg.endpointHost);
    }

    @Test
    public void parsesABracketedIPv6Endpoint() throws Exception {
        WgConfig cfg = WgConfig.parse(
                "[Interface]\n" +
                "PrivateKey = " + PRIV_KEY + "\n" +
                "Address = 10.6.0.2/32\n" +
                "[Peer]\n" +
                "PublicKey = " + PUB_KEY + "\n" +
                "Endpoint = [2001:db8::1]:51820\n");

        assertEquals("2001:db8::1", cfg.endpointHost);
        assertEquals(51820, cfg.endpointPort);
    }

    @Test
    public void ignoresTheWgQuickScriptHooks() throws Exception {
        // These would be shell commands run by wg-quick; PCAPdroid must not choke on them,
        // and must certainly not run them
        WgConfig cfg = WgConfig.parse(
                "[Interface]\n" +
                "PrivateKey = " + PRIV_KEY + "\n" +
                "Address = 10.6.0.2/32\n" +
                "PostUp = iptables -A FORWARD -i %i -j ACCEPT\n" +
                "Table = off\n" +
                "FwMark = 0xca6c\n" +
                "[Peer]\n" +
                "PublicKey = " + PUB_KEY + "\n" +
                "Endpoint = 198.51.100.7:51820\n");

        assertNotNull(cfg);
        assertEquals("198.51.100.7", cfg.endpointHost);
    }

    @Test
    public void skipsSearchDomainsInTheDnsLine() throws Exception {
        WgConfig cfg = WgConfig.parse(
                "[Interface]\n" +
                "PrivateKey = " + PRIV_KEY + "\n" +
                "Address = 10.6.0.2/32\n" +
                "DNS = 10.6.0.1, example.com\n" +
                "[Peer]\n" +
                "PublicKey = " + PUB_KEY + "\n" +
                "Endpoint = 198.51.100.7:51820\n");

        assertEquals(1, cfg.dnsServers.size());
        assertEquals("10.6.0.1", cfg.dnsServers.get(0));
    }

    @Test
    public void detectsASplitTunnel() throws Exception {
        WgConfig cfg = WgConfig.parse(
                "[Interface]\n" +
                "PrivateKey = " + PRIV_KEY + "\n" +
                "Address = 10.6.0.2/32\n" +
                "[Peer]\n" +
                "PublicKey = " + PUB_KEY + "\n" +
                "AllowedIPs = 10.0.0.0/8, 192.168.0.0/16\n" +
                "Endpoint = 198.51.100.7:51820\n");

        assertFalse(cfg.isFullTunnel(false));
        assertFalse(cfg.isFullTunnel(true));
        assertEquals(2, cfg.allowedIps.size());
        assertEquals(8, cfg.allowedIps.get(0).prefixLen);
    }

    /* ******************************************************* */

    private void assertRejected(String config, String expectedInMessage) {
        try {
            WgConfig.parse(config);
            fail("the configuration should have been rejected: " + config);
        } catch (WgConfig.ParseException e) {
            assertTrue("unexpected message: " + e.getMessage(),
                    e.getMessage().toLowerCase().contains(expectedInMessage.toLowerCase()));
        }
    }

    @Test
    public void rejectsAnEmptyConfig() {
        assertRejected("", "empty");
        assertRejected("   \n\n  ", "empty");
    }

    @Test
    public void rejectsMissingMandatoryKeys() {
        assertRejected(
                "[Interface]\nAddress = 10.6.0.2/32\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7:51820\n",
                "PrivateKey");

        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\nAddress = 10.6.0.2/32\n" +
                "[Peer]\nEndpoint = 198.51.100.7:51820\n",
                "PublicKey");

        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\nAddress = 10.6.0.2/32\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\n",
                "Endpoint");

        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7:51820\n",
                "Address");
    }

    @Test
    public void rejectsAnInvalidKey() {
        assertRejected(
                "[Interface]\nPrivateKey = not-a-key\nAddress = 10.6.0.2/32\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7:51820\n",
                "not a valid key");
    }

    @Test
    public void rejectsAnOutOfRangeMtu() {
        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\nAddress = 10.6.0.2/32\nMTU = 9000\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7:51820\n",
                "MTU");

        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\nAddress = 10.6.0.2/32\nMTU = 500\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7:51820\n",
                "MTU");
    }

    @Test
    public void rejectsMultiplePeers() {
        assertRejected(FULL_CONFIG +
                "\n[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.8:51820\n",
                "single peer");
    }

    @Test
    public void rejectsAHostnameWhereAnIpIsRequired() {
        // Resolving this would leak a DNS query before the tunnel is up
        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\nAddress = example.com/32\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7:51820\n",
                "is not an IP address");
    }

    @Test
    public void rejectsAMalformedEndpoint() {
        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\nAddress = 10.6.0.2/32\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7\n",
                "host:port");

        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\nAddress = 10.6.0.2/32\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7:0\n",
                "port");
    }

    @Test
    public void rejectsAnUnknownKey() {
        assertRejected(
                "[Interface]\nPrivateKey = " + PRIV_KEY + "\nAddress = 10.6.0.2/32\n" +
                "Jwt = hunter2\n" +
                "[Peer]\nPublicKey = " + PUB_KEY + "\nEndpoint = 198.51.100.7:51820\n",
                "unknown [Interface] key");
    }

    @Test
    public void neverLeaksTheKeysInToString() throws Exception {
        String dump = WgConfig.parse(FULL_CONFIG).toString();

        assertFalse(dump.contains(PRIV_KEY));
        assertFalse(dump.contains(PUB_KEY));
        assertFalse(dump.contains(PSK));
        assertTrue(dump.contains("vpn.example.com"));
    }
}
