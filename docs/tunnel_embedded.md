# Embedded tunnel

This fork lets PCAPdroid send the captured traffic through a tunnel that runs **inside the
app**, instead of through the userspace NAT it normally uses.

## Why

Android allows a single `VpnService` per user profile. PCAPdroid needs it to capture
without root, so it cannot coexist with any other VPN app: whichever starts second wins,
and the other one is torn down. `VpnReconnectService` only softens the symptom, by waiting
for the other VPN to stop before restarting the capture.

The way out is not to ask Android for a second slot, but to stop needing one. PCAPdroid
keeps the only slot and the "real" VPN becomes a userspace client living in the app: the
tunnel's outer socket is an ordinary UDP socket that `VpnService.protect()` keeps out of
the tun, so nothing else has to be registered with the system.

There is a second, less obvious benefit. Without root, an app cannot emit raw IP packets,
which is precisely why PCAPdroid has to terminate every connection on a socket and
re-synthesize the headers (see [how_it_works.md](how_it_works.md)). An embedded tunnel
removes that constraint: the inner packets are carried verbatim inside the tunnel's
datagrams, so PCAPdroid can relay them untouched and the resulting PCAP becomes faithful
packet by packet.

## Architecture

```
                        ┌──────────────── PCAPdroid ─────────────────┐
  app sockets           │                                            │
       │                │   run_tunnel()            pd_tunnel_t      │
       ▼                │  capture_tunnel.c          tunnel.h        │
  kernel ──► tun ──────►│  parse ─ DPI ─ firewall ─► send_ip() ──┐   │
                        │                                        │   │
       ◄─────── tun ◄───│  parse ─ DPI ─ firewall ◄─ recv_ip() ◄─┤   │
                        │                                        │   │
                        │                            tunnel_wireguard.c
                        │                            ├ libwgtunnel.so (Rust/boringtun)
                        │                            └ protected UDP socket ──► peer
                        └────────────────────────────────────────────┘
```

| Layer | File | Role |
|---|---|---|
| Datapath | `jni/core/capture_tunnel.c` | Reads the tun, tracks flows from the packets, runs the analysis, hands the packets to the backend |
| Abstraction | `jni/core/tunnel.h`, `tunnel.c` | `pd_tunnel_t` ops, configuration loading, status |
| Backend | `jni/core/tunnel_wireguard.c` | Owns the protected UDP socket, the buffers and the 250 ms tick |
| Crypto | `rust/wgtunnel/` | WireGuard state machine (boringtun), exposed over a C ABI |
| Config | `java/.../model/WgConfig.java` | wg-quick parser |
| Wiring | `java/.../CaptureService.java` | Validation, tun setup, endpoint resolution, JNI getters |

The Rust library owns no socket and no file descriptor: it only turns plaintext IP packets
into WireGuard datagrams and back. Everything else — accounting, the firewall, the PCAP
dumper — stays in the C core, where PCAPdroid already implements it.

`libwgtunnel.so` is loaded with `dlopen`, like `libushark.so`: `libcapture.so` does not
link against it, so a build without the Rust toolchain still produces a working APK in
which the embedded tunnel simply reports itself as unavailable.

## The two datapaths

`Prefs.TunnelDatapath` selects how the packets reach the tunnel.

### L3 pass-through (`l3`) — implemented

No userspace NAT at all. The IP packets are relayed exactly as the apps emitted them.

* Flows are tracked by observing the packets, reusing the state machine of the root-mode
  capture (`capture_pcap.c`), with one simplification: here the direction is known exactly
  instead of being guessed from the interface.
* UIDs still come from `uid_resolver` (`getConnectionOwnerUid`, or `/proc` on older
  releases), which does not depend on the egress.
* The tun carries the addresses, routes and DNS servers from the tunnel configuration, not
  `VPN_IP_ADDRESS`: with nothing rewriting the packets, the peer receives them with the
  source address assigned here and drops anything outside its `AllowedIPs`.
* **Not available:** TLS decryption through the mitm addon, port mapping and SOCKS5
  chaining. All three need a socket to hand to a proxy, and this datapath never creates
  one. `CaptureService.setupTunnelEgress` refuses the combination instead of silently
  ignoring half the settings.

### L4 proxy (`l4`) — not implemented yet

Keeps zdtun's userspace NAT and replaces only the socket egress, so the proxy-based
features keep working. It needs a userspace TCP/IP stack to turn the proxied sockets back
into IP packets; `smoltcp` is the natural fit, since the tunnel core is already in Rust.
Selecting it today aborts the capture with an explicit message rather than falling back.

## DNS and QUIC

In the default mode, PCAPdroid advertises an internal DNS address (`10.215.173.2`) and
rewrites the destination of the queries, so that it can read them. In tunnel mode that
trick is unnecessary and is therefore not used: the tun advertises the DNS server from the
tunnel configuration, the queries are sent straight to it, and PCAPdroid reads them off
the tun because it sees every packet. One fewer rewrite, one fewer thing to get wrong.

If the configuration has no `DNS =` line, the tun falls back to the DNS server configured
in PCAPdroid. The resolver of the underlying network would not do: its address is not
routed into the tunnel, so the queries would be dropped.

One behavioural difference is worth knowing about. In the default mode, a blocked DNS
query gets a spoofed reply pointing at `0.0.0.0`, so the app fails fast instead of
retrying. The L3 datapath has no zdtun connection to build that reply from, so it closes
the flow instead; a blocked app may retry its query a few times before giving up. A
standalone reply builder would fix it and is listed below.

Private-DNS blocking (`PREF_AUTO_BLOCK_PRIVATE_DNS`) and QUIC blocking
(`PREF_BLOCK_QUIC`) still apply, since both are decisions about whether to forward a
flow, not rewrites. QUIC is relayed like any other UDP traffic.

## MTU

The default mode uses `VPN_MTU = 10000`, which is fine when the kernel re-fragments on the
egress socket. A tunnel has no such luxury: an inner packet plus the WireGuard transport
header (32 bytes), UDP (8) and IP (20 or 40) must still fit the real path MTU. The tun
therefore uses the configuration's `MTU`, defaulting to wg-quick's own 1420, and
`WgConfig` rejects anything outside 1280–1500.

## Security notes

* The tunnel configuration is **never** included in a settings backup
  (`PrefsSchema`: `.noBackup()`), because it carries the WireGuard private key and a backup
  is a plain JSON file users share.
* It is **not** settable through the app API (`CaptureSettings(Context, Intent)`). Accepting
  a WireGuard configuration from an intent would let any app on the device route the
  traffic of every other app through a server of its choosing.
* `WgConfig.toString()` never prints the keys: it ends up in the logs.
* `pd_tunnel_free` wipes the keys from the heap, as the capture service is long-lived.
* Every exported Rust function is wrapped in `catch_unwind`. The library parses untrusted
  network input, and a panic unwinding across the FFI boundary is undefined behaviour,
  while `panic = "abort"` would take down the whole capture service. For the same reason
  the release profile deliberately does **not** set `panic = "abort"`.
* The wg-quick keys that only make sense for the shell script (`PostUp`, `PreDown`,
  `Table`, `FwMark`, …) are parsed and ignored, never executed.
* A malformed or unauthenticated datagram arriving on the UDP socket is logged at debug
  level and dropped. It is expected traffic on an open port and must not stop a capture.

## Building

The Rust core is built by the `buildWgTunnel` Gradle task, which runs before the native
libraries are merged into the APK:

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

```bash
./gradlew assembleStandardDebug
```

The task is skipped with a warning when `cargo-ndk` is missing, and can be skipped
explicitly:

```bash
./gradlew assembleStandardDebug -PskipRust
```

The output lands in `app/src/main/jniLibs/<abi>/libwgtunnel.so`, which is git-ignored.

To run the Rust tests, which include a full handshake and a data round-trip between two
tunnel instances:

```bash
cd app/src/main/rust/wgtunnel && cargo test
```

## Status

Done:

* Rust WireGuard core with a C ABI, covered by tests (handshake, data round-trip, key
  handling, rejection of malformed input).
* `pd_tunnel_t` egress abstraction and the WireGuard backend.
* L3 pass-through datapath, wired into `pd_run`.
* wg-quick parser with tests, preferences, and the `CaptureService` plumbing.

Remaining, in rough order:

1. **Settings UI.** The preferences and the plumbing exist; there is no screen yet to paste
   a configuration, show the tunnel state or generate a keypair. `wgt_keypair` and
   `wgt_pubkey_from_private` are exported for it.
2. **Status reporting.** `pd_tunnel_get_status` returns handshake age, RTT and counters;
   nothing surfaces them in `StatusFragment` yet.
3. **Roaming.** When the underlying network changes, the UDP socket must be recreated and
   re-protected. Today a fatal socket error stops the capture, which
   `PREF_RESTART_ON_DISCONNECT` partially covers.
4. **AllowedIPs filtering on ingress.** A single-peer client with `0.0.0.0/0, ::/0` needs
   none, but a split tunnel should drop inner packets whose source falls outside the
   configured ranges.
5. **Spoofed replies for blocked DNS queries**, to match the default mode (see above).
6. **L4 datapath** (see above).
7. **On-device testing.** Everything here is validated by unit tests and compilation; none
   of it has run on a device yet.
