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

//! Userspace WireGuard state machine for PCAPdroid's embedded tunnel.
//!
//! This library is deliberately *transport-less*: it owns no socket and no tun file
//! descriptor. It only converts plaintext IP packets into WireGuard datagrams and back,
//! so that the C core keeps full control over the `VpnService.protect()`ed UDP socket
//! and over the tun fd. That keeps packet accounting, the firewall and the PCAP dumper
//! on the C side, where PCAPdroid already implements them.
//!
//! Every exported function is `#[no_mangle] extern "C"` and is wrapped in
//! [`std::panic::catch_unwind`]: this code processes untrusted network input, and a
//! panic unwinding across the FFI boundary would be undefined behaviour, while aborting
//! would take the whole capture service down.

use std::io::Write;
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// Size of a base64-encoded X25519 key, including the NUL terminator.
pub const WGT_KEY_STRLEN: usize = 45;

/// Bytes added by the WireGuard transport header to every data packet.
pub const WGT_OVERHEAD: usize = 32;

/* ******************************************************* */

/// Result codes shared with the C side (see `tunnel_wireguard.c`).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WgtResult {
    /// Nothing to do: the input was consumed without producing an output packet.
    /// For `wgt_encapsulate` this means the packet was queued pending a handshake.
    Done = 0,
    /// `dst` holds a datagram to be sent to the peer endpoint over UDP.
    WriteToNetwork = 1,
    /// `dst` holds a plaintext IP packet to be delivered to the tun.
    WriteToTun = 2,
    /// Invalid arguments, or a key/handshake error. Non-fatal: the caller drops the packet.
    Err = -1,
    /// The output buffer was too small for the produced packet. The packet is lost.
    NoBuffer = -2,
    /// The peer is rate-limiting us, or the handshake is being retried too fast.
    RateLimited = -3,
}

/// Opaque handle handed out to C.
pub struct WgTunnel {
    tunn: Tunn,
    /// Set when the last operation produced a diagnostic worth surfacing in the UI.
    last_error: Option<String>,
}

/// Counters mirrored into the PCAPdroid status UI.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct WgtStats {
    /// Milliseconds since the last completed handshake, or -1 if none completed yet.
    pub ms_since_handshake: i64,
    /// Plaintext bytes handed to `wgt_encapsulate`.
    pub tx_bytes: u64,
    /// Plaintext bytes produced by `wgt_decapsulate`.
    pub rx_bytes: u64,
    /// Estimated packet loss, in the 0..=10000 range (basis points), or -1 if unknown.
    pub loss_bp: i32,
    /// Estimated round-trip time in milliseconds, or -1 if unknown.
    pub rtt_ms: i32,
}

/* ******************************************************* */

fn decode_key(s: &str) -> Option<[u8; 32]> {
    // WireGuard keys are base64, but wg-quick users paste hex now and then: accept both.
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(out);
    }

    let decoded = BASE64.decode(s.trim()).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Some(out)
}

unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(ptr).to_str().ok()
}

/// Writes a NUL-terminated base64 key into a caller-provided buffer of
/// [`WGT_KEY_STRLEN`] bytes. Returns false if the buffer is too small.
unsafe fn write_key_str(out: *mut c_char, out_len: usize, key: &[u8; 32]) -> bool {
    let encoded = BASE64.encode(key);
    if out.is_null() || out_len < encoded.len() + 1 {
        return false;
    }
    let dst = slice::from_raw_parts_mut(out as *mut u8, out_len);
    let mut cursor = &mut dst[..];
    if cursor.write_all(encoded.as_bytes()).is_err() {
        return false;
    }
    dst[encoded.len()] = 0;
    true
}

/* ******************************************************* */

/// Creates a WireGuard tunnel state machine for a single peer.
///
/// * `private_key_b64` — this client's private key (base64 or hex).
/// * `peer_public_key_b64` — the peer's public key (base64 or hex).
/// * `preshared_key_b64` — optional PSK, may be NULL or empty.
/// * `keepalive` — persistent keepalive in seconds, 0 to disable.
/// * `index` — a locally unique tunnel index (use 0 for a single tunnel).
///
/// Returns NULL when a key cannot be decoded. The handle must be released with
/// [`wgt_free`].
#[no_mangle]
pub unsafe extern "C" fn wgt_new(
    private_key_b64: *const c_char,
    peer_public_key_b64: *const c_char,
    preshared_key_b64: *const c_char,
    keepalive: u16,
    index: u32,
) -> *mut WgTunnel {
    catch_unwind(AssertUnwindSafe(|| {
        let private = match cstr_to_str(private_key_b64).and_then(decode_key) {
            Some(k) => StaticSecret::from(k),
            None => return std::ptr::null_mut(),
        };
        let peer = match cstr_to_str(peer_public_key_b64).and_then(decode_key) {
            Some(k) => PublicKey::from(k),
            None => return std::ptr::null_mut(),
        };
        let psk = match cstr_to_str(preshared_key_b64) {
            Some(s) if !s.trim().is_empty() => match decode_key(s) {
                Some(k) => Some(k),
                None => return std::ptr::null_mut(),
            },
            _ => None,
        };

        // The rate limiter protects against handshake floods from the network. A client
        // talks to exactly one peer, but the socket is still reachable by anyone who can
        // guess the source port, so it is worth keeping.
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&private), 100));

        // Note: Tunn::new is infallible in boringtun 0.7 (key validation already
        // happened in decode_key above), so there is no error branch to handle here.
        let tunn = Tunn::new(
            private,
            peer,
            psk,
            if keepalive == 0 { None } else { Some(keepalive) },
            index,
            Some(limiter),
        );

        Box::into_raw(Box::new(WgTunnel {
            tunn,
            last_error: None,
        }))
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Releases a handle returned by [`wgt_new`]. NULL is accepted.
#[no_mangle]
pub unsafe extern "C" fn wgt_free(handle: *mut WgTunnel) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(handle));
    }));
}

/* ******************************************************* */

fn map_result(
    res: TunnResult<'_>,
    written: &mut usize,
    tunnel: &mut WgTunnel,
) -> WgtResult {
    match res {
        TunnResult::Done => {
            *written = 0;
            WgtResult::Done
        }
        TunnResult::WriteToNetwork(buf) => {
            *written = buf.len();
            WgtResult::WriteToNetwork
        }
        TunnResult::WriteToTunnelV4(buf, _) | TunnResult::WriteToTunnelV6(buf, _) => {
            *written = buf.len();
            WgtResult::WriteToTun
        }
        TunnResult::Err(e) => {
            *written = 0;
            match e {
                WireGuardError::ConnectionExpired | WireGuardError::NoCurrentSession => {
                    // Expected while a handshake is in flight; not worth surfacing.
                    WgtResult::Done
                }
                WireGuardError::DestinationBufferTooSmall => WgtResult::NoBuffer,
                WireGuardError::UnderLoad => WgtResult::RateLimited,
                other => {
                    tunnel.last_error = Some(format!("{other:?}"));
                    WgtResult::Err
                }
            }
        }
    }
}

/// Encapsulates one plaintext IP packet.
///
/// `dst` must have room for `src_len + WGT_OVERHEAD` bytes. When the result is
/// [`WgtResult::Done`] the packet was queued until the handshake completes, and the
/// caller must not retry it: boringtun will emit it once the session is up.
#[no_mangle]
pub unsafe extern "C" fn wgt_encapsulate(
    handle: *mut WgTunnel,
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_len: usize,
    written: *mut usize,
) -> c_int {
    ffi_transform(handle, dst, dst_len, written, |tunnel, out| {
        if src.is_null() || src_len == 0 {
            return None;
        }
        let input = slice::from_raw_parts(src, src_len);
        Some(tunnel.tunn.encapsulate(input, out))
    })
}

/// Decapsulates one datagram received from the peer.
///
/// After a call that returns [`WgtResult::WriteToNetwork`] (a handshake response or a
/// cookie reply), the caller must send that datagram and then keep calling this function
/// with `src_len == 0` until it returns [`WgtResult::Done`], to drain the packets
/// boringtun queued while the session was being established.
#[no_mangle]
pub unsafe extern "C" fn wgt_decapsulate(
    handle: *mut WgTunnel,
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_len: usize,
    written: *mut usize,
) -> c_int {
    ffi_transform(handle, dst, dst_len, written, |tunnel, out| {
        let input: &[u8] = if src.is_null() || src_len == 0 {
            &[]
        } else {
            slice::from_raw_parts(src, src_len)
        };
        // src_addr is only used by the rate limiter to build cookies; the C side talks to
        // a single endpoint, so None keeps the ABI simple.
        Some(tunnel.tunn.decapsulate(None, input, out))
    })
}

/// Advances the WireGuard timers. Must be called about every 250 ms, and may produce a
/// handshake initiation or a keepalive to be sent to the peer.
#[no_mangle]
pub unsafe extern "C" fn wgt_update_timers(
    handle: *mut WgTunnel,
    dst: *mut u8,
    dst_len: usize,
    written: *mut usize,
) -> c_int {
    ffi_transform(handle, dst, dst_len, written, |tunnel, out| {
        Some(tunnel.tunn.update_timers(out))
    })
}

/// Shared prologue/epilogue for the three transform entry points.
unsafe fn ffi_transform<F>(
    handle: *mut WgTunnel,
    dst: *mut u8,
    dst_len: usize,
    written: *mut usize,
    op: F,
) -> c_int
where
    F: for<'a> FnOnce(&mut WgTunnel, &'a mut [u8]) -> Option<TunnResult<'a>>,
{
    if !written.is_null() {
        *written = 0;
    }
    if handle.is_null() || dst.is_null() || dst_len == 0 {
        return WgtResult::Err as c_int;
    }

    let res = catch_unwind(AssertUnwindSafe(|| {
        let tunnel = &mut *handle;
        let out = slice::from_raw_parts_mut(dst, dst_len);

        // SAFETY: boringtun borrows `out` for the lifetime of the returned TunnResult;
        // the borrow ends before this closure returns the mapped result.
        let out_ptr = out.as_mut_ptr();
        let out_slice = slice::from_raw_parts_mut(out_ptr, dst_len);

        let mut n = 0usize;
        let code = match op(tunnel, out_slice) {
            Some(r) => map_result(r, &mut n, tunnel),
            None => WgtResult::Err,
        };
        (code, n)
    }));

    match res {
        Ok((code, n)) => {
            if !written.is_null() {
                *written = n;
            }
            code as c_int
        }
        Err(_) => WgtResult::Err as c_int,
    }
}

/* ******************************************************* */

/// Fills `out` with the current tunnel counters. Returns false on invalid arguments.
#[no_mangle]
pub unsafe extern "C" fn wgt_stats(handle: *mut WgTunnel, out: *mut WgtStats) -> bool {
    if handle.is_null() || out.is_null() {
        return false;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let tunnel = &mut *handle;
        let (since_handshake, tx, rx, loss, rtt) = tunnel.tunn.stats();

        *out = WgtStats {
            ms_since_handshake: since_handshake
                .map(|d| d.as_millis() as i64)
                .unwrap_or(-1),
            tx_bytes: tx as u64,
            rx_bytes: rx as u64,
            loss_bp: if loss.is_finite() && loss >= 0.0 {
                (loss * 10000.0).round().clamp(0.0, 10000.0) as i32
            } else {
                -1
            },
            rtt_ms: rtt.map(|v| v as i32).unwrap_or(-1),
        };
        true
    }))
    .unwrap_or(false)
}

/// Copies the last non-transient error into `out` (NUL-terminated, truncated as needed)
/// and clears it. Returns false when there is no pending error.
#[no_mangle]
pub unsafe extern "C" fn wgt_last_error(
    handle: *mut WgTunnel,
    out: *mut c_char,
    out_len: usize,
) -> bool {
    if handle.is_null() || out.is_null() || out_len == 0 {
        return false;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let tunnel = &mut *handle;
        match tunnel.last_error.take() {
            Some(msg) => {
                let bytes = msg.as_bytes();
                let n = bytes.len().min(out_len - 1);
                let dst = slice::from_raw_parts_mut(out as *mut u8, out_len);
                dst[..n].copy_from_slice(&bytes[..n]);
                dst[n] = 0;
                true
            }
            None => false,
        }
    }))
    .unwrap_or(false)
}

/* ******************************************************* */

/// Generates a fresh X25519 keypair. Both buffers must be [`WGT_KEY_STRLEN`] bytes.
#[no_mangle]
pub unsafe extern "C" fn wgt_keypair(
    private_out: *mut c_char,
    private_len: usize,
    public_out: *mut c_char,
    public_len: usize,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);

        write_key_str(private_out, private_len, &secret.to_bytes())
            && write_key_str(public_out, public_len, public.as_bytes())
    }))
    .unwrap_or(false)
}

/// Derives the public key matching `private_key_b64`. Lets the UI show the key the user
/// has to configure on the peer, without storing it twice.
#[no_mangle]
pub unsafe extern "C" fn wgt_pubkey_from_private(
    private_key_b64: *const c_char,
    public_out: *mut c_char,
    public_len: usize,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let key = match cstr_to_str(private_key_b64).and_then(decode_key) {
            Some(k) => k,
            None => return false,
        };
        let secret = StaticSecret::from(key);
        write_key_str(public_out, public_len, PublicKey::from(&secret).as_bytes())
    }))
    .unwrap_or(false)
}

/// Validates a base64/hex key without allocating a tunnel. Used by the config parser.
#[no_mangle]
pub unsafe extern "C" fn wgt_key_is_valid(key_b64: *const c_char) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        cstr_to_str(key_b64).and_then(decode_key).is_some()
    }))
    .unwrap_or(false)
}

/// ABI version, bumped whenever an exported signature changes. The C loader refuses a
/// library whose version it does not know, so a stale `libwgtunnel.so` cannot be
/// mismatched against a newer `libcapture.so`.
#[no_mangle]
pub extern "C" fn wgt_abi_version() -> u32 {
    1
}

/* ******************************************************* */

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// boringtun validates the decapsulated payload: it must be a well-formed IPv4 or
    /// IPv6 packet whose length field matches the datagram, otherwise decapsulate
    /// returns an error. So the fixture has to be a real packet, not filler bytes.
    fn ipv4_udp_packet(payload_len: usize) -> Vec<u8> {
        let total = 20 + 8 + payload_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45; // IPv4, IHL 5
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 215, 173, 1]);
        pkt[16..20].copy_from_slice(&[10, 215, 173, 2]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        pkt
    }

    fn keypair() -> (CString, CString) {
        let mut priv_buf = [0i8; WGT_KEY_STRLEN];
        let mut pub_buf = [0i8; WGT_KEY_STRLEN];
        unsafe {
            assert!(wgt_keypair(
                priv_buf.as_mut_ptr(),
                priv_buf.len(),
                pub_buf.as_mut_ptr(),
                pub_buf.len()
            ));
            (
                CString::from(std::ffi::CStr::from_ptr(priv_buf.as_ptr())),
                CString::from(std::ffi::CStr::from_ptr(pub_buf.as_ptr())),
            )
        }
    }

    #[test]
    fn keys_roundtrip() {
        let (priv_key, pub_key) = keypair();
        let mut derived = [0i8; WGT_KEY_STRLEN];
        unsafe {
            assert!(wgt_pubkey_from_private(
                priv_key.as_ptr(),
                derived.as_mut_ptr(),
                derived.len()
            ));
            let derived = std::ffi::CStr::from_ptr(derived.as_ptr());
            assert_eq!(derived.to_str().unwrap(), pub_key.to_str().unwrap());
            assert!(wgt_key_is_valid(priv_key.as_ptr()));
        }
    }

    #[test]
    fn hex_keys_are_accepted() {
        let hex = "a".repeat(64);
        assert!(decode_key(&hex).is_some());
        assert!(decode_key("not a key").is_none());
        // 31 bytes of base64 must be rejected
        assert!(decode_key(&BASE64.encode([0u8; 31])).is_none());
    }

    #[test]
    fn handshake_completes_between_two_tunnels() {
        let (a_priv, a_pub) = keypair();
        let (b_priv, b_pub) = keypair();

        unsafe {
            let a = wgt_new(a_priv.as_ptr(), b_pub.as_ptr(), std::ptr::null(), 0, 0);
            let b = wgt_new(b_priv.as_ptr(), a_pub.as_ptr(), std::ptr::null(), 0, 1);
            assert!(!a.is_null() && !b.is_null());

            let mut buf_a = [0u8; 2048];
            let mut buf_b = [0u8; 2048];
            let mut n = 0usize;

            // A sends a packet: it is queued and a handshake initiation comes out.
            let payload = ipv4_udp_packet(32);
            let rv = wgt_encapsulate(
                a,
                payload.as_ptr(),
                payload.len(),
                buf_a.as_mut_ptr(),
                buf_a.len(),
                &mut n,
            );
            assert_eq!(rv, WgtResult::WriteToNetwork as c_int);
            let init_len = n;

            // B answers with a handshake response.
            let rv = wgt_decapsulate(
                b,
                buf_a.as_ptr(),
                init_len,
                buf_b.as_mut_ptr(),
                buf_b.len(),
                &mut n,
            );
            assert_eq!(rv, WgtResult::WriteToNetwork as c_int);
            let resp_len = n;

            // A consumes the response. This emits a keepalive first, and the queued data
            // packet only comes out on a follow-up drain call with an empty datagram:
            // this is the contract tunnel_wireguard.c must honour, so assert it here.
            let mut to_peer: Vec<Vec<u8>> = Vec::new();
            let mut input_len = resp_len;
            loop {
                let rv = wgt_decapsulate(
                    a,
                    buf_b.as_ptr(),
                    input_len,
                    buf_a.as_mut_ptr(),
                    buf_a.len(),
                    &mut n,
                );
                input_len = 0; // subsequent calls drain the queue
                if rv != WgtResult::WriteToNetwork as c_int {
                    assert_eq!(rv, WgtResult::Done as c_int);
                    break;
                }
                to_peer.push(buf_a[..n].to_vec());
                assert!(to_peer.len() < 8, "drain loop did not terminate");
            }
            assert!(
                to_peer.len() >= 2,
                "expected a keepalive plus the queued data packet, got {}",
                to_peer.len()
            );

            // B decrypts them and gets the original plaintext back.
            let mut delivered = false;
            for datagram in &to_peer {
                let rv = wgt_decapsulate(
                    b,
                    datagram.as_ptr(),
                    datagram.len(),
                    buf_b.as_mut_ptr(),
                    buf_b.len(),
                    &mut n,
                );
                if rv == WgtResult::WriteToTun as c_int {
                    assert_eq!(&buf_b[..n], &payload[..]);
                    delivered = true;
                }
            }
            assert!(delivered, "the queued packet never reached the peer");

            let mut stats = WgtStats::default();
            assert!(wgt_stats(b, &mut stats));
            assert!(stats.ms_since_handshake >= 0);

            wgt_free(a);
            wgt_free(b);
        }
    }

    #[test]
    fn garbage_input_is_rejected_without_panicking() {
        let (a_priv, _) = keypair();
        let (_, b_pub) = keypair();
        unsafe {
            let a = wgt_new(a_priv.as_ptr(), b_pub.as_ptr(), std::ptr::null(), 25, 0);
            assert!(!a.is_null());

            let mut out = [0u8; 2048];
            let mut n = 0usize;
            let junk = [0xffu8; 64];
            let rv = wgt_decapsulate(
                a,
                junk.as_ptr(),
                junk.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            );
            assert!(rv < 0 || rv == WgtResult::Done as c_int);

            // NULL handle must not crash
            assert_eq!(
                wgt_encapsulate(
                    std::ptr::null_mut(),
                    junk.as_ptr(),
                    junk.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut n
                ),
                WgtResult::Err as c_int
            );
            wgt_free(a);
        }
    }
}
