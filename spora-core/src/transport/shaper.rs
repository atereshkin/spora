//! The nz "Shaper" — a keyed, per-datagram wire transform that removes the
//! carrier's structural DPI tells (fixed handshake sizes, the raw Curve25519
//! ephemeral, the demux-index echo) without touching the Noise/AEAD framing.
//!
//! It is applied between `frame_data` and the UDP socket (`obfuscate`) and
//! reversed at the raw recv points before demux (`deobfuscate`). The key is
//! derived from `routing_key || secret`, so both peers agree with no on-wire
//! negotiation and the transform carries no cross-user signature (the AmneziaWG
//! lesson). It is always-on for the nz carrier — the transform costs one 4-byte
//! HMAC per data packet and adds zero data-plane bytes, so there is no reason to
//! ship the bare wire.
//!
//! Split by packet class:
//! - **data / msg2 / cert-auth / signal / close** — mask only the 4-byte leading
//!   demux field (the `recv_index`, or msg1's echoed `idx_B` on msg2), keyed off
//!   the 8 wire bytes at `[4..12]` (the header-protected counter, which is unique
//!   per packet). No length change → no MTU cost. Closes the index-echo tell.
//! - **msg1** (the only relay-read packet) — keep `routing_key[0..20]` cleartext
//!   so the dumb relay still routes, then an 8-byte per-packet nonce, a keystream
//!   mask over the 52-byte body (idx_B + NNpsk0 msg1), and random pad. Re-rolled
//!   on every retransmit. Closes the fixed-size and raw-ephemeral tells on the
//!   first packet.
//!
//! `deobfuscate` is TOTAL: it never panics on arbitrary or truncated input (it is
//! inserted upstream of the framing's length gates, so a short crafted packet
//! must not crash the receive loop). See `docs/noise-carrier-design.md`.

use std::sync::Arc;

use ring::hmac;

use crate::identity::ROUTING_KEY_LEN;

/// A shaper shared (cloned) across a session's send path, its signal channel, and
/// its receive pump — one instance per identity, keyed off `routing_key||secret`.
pub(crate) type SharedShaper = Arc<dyn Shaper>;

/// The nz carrier's wire shaper for a given identity. Always the v1 scramble —
/// the transform is ~free (one 4-byte HMAC per data packet, zero added bytes), so
/// bare nz is never shipped.
pub(crate) fn nz_shaper(routing_key: &[u8; ROUTING_KEY_LEN], secret: &[u8]) -> SharedShaper {
    Arc::new(ScrambleV1::new(routing_key, secret))
}

/// Leading demux field masked on data-class packets (`recv_index`, or msg1's
/// echoed `idx_B` on msg2).
const DEMUX_LEN: usize = 4;
/// Wire bytes used as the per-packet mask nonce on data-class packets: the
/// header-protected counter at `[4..12]`, unique per sent packet.
const NONCE_LO: usize = 4;
const NONCE_HI: usize = 12;
/// Minimum framed length to mask a data-class packet (`[4..12]` must exist). A
/// real data packet is `>= DATA_MIN_LEN` (29); shorter input passes through
/// untouched and the framing's length gate rejects it.
const DATA_MASKABLE_MIN: usize = NONCE_HI;

/// Per-packet nonce length on the msg1 handshake transform.
const MSG1_NONCE: usize = 8;
/// Fixed framed msg1 length: routing_key(20) + idx_B(4) + NNpsk0 msg1(48).
const MSG1_FRAMED_LEN: usize = ROUTING_KEY_LEN + 4 + 48;
/// Masked body of msg1 — everything after the cleartext routing_key.
const MSG1_BODY: usize = MSG1_FRAMED_LEN - ROUTING_KEY_LEN;
/// Max random pad appended to a shaped msg1, spreading it out of the fixed size.
const MSG1_PAD_MAX: usize = 256;
/// Smallest shaped msg1 the receiver will parse: routing_key + nonce + body.
const MSG1_WIRE_MIN: usize = ROUTING_KEY_LEN + MSG1_NONCE + MSG1_BODY;

/// A reversible, keyed, per-datagram wire transform applied outside the Noise
/// framing. Send/receive halves share one instance (`Arc`), keyed per identity.
pub(crate) trait Shaper: Send + Sync {
    /// Transform one fully-framed datagram for the wire. `is_first` marks the
    /// handshake msg1, whose routing_key prefix must stay cleartext for the relay.
    fn obfuscate(&self, framed: &[u8], is_first: bool) -> Vec<u8>;
    /// Reverse `obfuscate`. TOTAL: returns `None` on any datagram that is not a
    /// valid shaped packet, and never panics on arbitrary/truncated input.
    fn deobfuscate(&self, wire: &[u8]) -> Option<Vec<u8>>;
}

/// Pass-through shaper (bare nz). Used in tests and as the conceptual default;
/// the nz carrier always wires `ScrambleV1`, so this is unused in a release build.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Identity;

impl Shaper for Identity {
    fn obfuscate(&self, framed: &[u8], _is_first: bool) -> Vec<u8> {
        framed.to_vec()
    }
    fn deobfuscate(&self, wire: &[u8]) -> Option<Vec<u8>> {
        Some(wire.to_vec())
    }
}

/// The v1 nz shaper. See the module docs.
pub(crate) struct ScrambleV1 {
    key: hmac::Key,
    routing_key: [u8; ROUTING_KEY_LEN],
}

impl ScrambleV1 {
    pub(crate) fn new(routing_key: &[u8; ROUTING_KEY_LEN], secret: &[u8]) -> Self {
        // Domain-separated from derive_psk / derive_hp_key.
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(b"spora-nz-shaper-v1");
        ctx.update(routing_key);
        ctx.update(secret);
        let mut k = [0u8; 32];
        k.copy_from_slice(ctx.finish().as_ref());
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            routing_key: *routing_key,
        }
    }

    /// 4-byte mask for the leading demux field, from the 8 wire bytes at `[4..12]`.
    fn demux_mask(&self, nonce8: &[u8]) -> [u8; DEMUX_LEN] {
        let tag = hmac::sign(&self.key, nonce8);
        let mut m = [0u8; DEMUX_LEN];
        m.copy_from_slice(&tag.as_ref()[..DEMUX_LEN]);
        m
    }

    /// XOR the leading `DEMUX_LEN` bytes in place, keyed off `buf[4..12]`. Caller
    /// guarantees `buf.len() >= DATA_MASKABLE_MIN`.
    fn xor_demux(&self, buf: &mut [u8]) {
        let mask = self.demux_mask(&buf[NONCE_LO..NONCE_HI]);
        for (b, m) in buf[..DEMUX_LEN].iter_mut().zip(mask.iter()) {
            *b ^= *m;
        }
    }

    /// `n` bytes of keystream for the msg1 body mask, from the msg1 nonce.
    fn msg1_keystream(&self, nonce: &[u8], n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n + 32);
        let mut ctr: u8 = 0;
        while out.len() < n {
            let mut m = [0u8; MSG1_NONCE + 1];
            m[..MSG1_NONCE].copy_from_slice(nonce);
            m[MSG1_NONCE] = ctr;
            out.extend_from_slice(hmac::sign(&self.key, &m).as_ref());
            ctr += 1;
        }
        out.truncate(n);
        out
    }
}

impl Shaper for ScrambleV1 {
    fn obfuscate(&self, framed: &[u8], is_first: bool) -> Vec<u8> {
        if is_first {
            // msg1: routing_key(20) | nonce(8) | mask(body[52]) | pad.
            debug_assert_eq!(
                framed.len(),
                MSG1_FRAMED_LEN,
                "shaped msg1 must be framed msg1"
            );
            let nonce: [u8; MSG1_NONCE] = rand::random();
            let ks = self.msg1_keystream(&nonce, MSG1_BODY);
            let mut out = Vec::with_capacity(MSG1_WIRE_MIN + MSG1_PAD_MAX);
            out.extend_from_slice(&framed[..ROUTING_KEY_LEN]);
            out.extend_from_slice(&nonce);
            for (b, k) in framed[ROUTING_KEY_LEN..].iter().zip(ks.iter()) {
                out.push(b ^ k);
            }
            // Random-length, random-byte pad — the receiver ignores it (the real
            // body length is fixed), so it needs no wire length field.
            let pad_len = (rand::random::<u16>() as usize) % (MSG1_PAD_MAX + 1);
            let base = out.len();
            out.resize(base + pad_len, 0);
            use rand::Rng;
            rand::thread_rng().fill(&mut out[base..]);
            out
        } else {
            let mut out = framed.to_vec();
            if out.len() >= DATA_MASKABLE_MIN {
                self.xor_demux(&mut out);
            }
            out
        }
    }

    fn deobfuscate(&self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() >= ROUTING_KEY_LEN && wire[..ROUTING_KEY_LEN] == self.routing_key {
            // msg1 branch — guard the full slice length before any indexing.
            if wire.len() < MSG1_WIRE_MIN {
                return None;
            }
            let nonce = &wire[ROUTING_KEY_LEN..ROUTING_KEY_LEN + MSG1_NONCE];
            let body = &wire[ROUTING_KEY_LEN + MSG1_NONCE..MSG1_WIRE_MIN];
            let ks = self.msg1_keystream(nonce, MSG1_BODY);
            let mut out = Vec::with_capacity(MSG1_FRAMED_LEN);
            out.extend_from_slice(&wire[..ROUTING_KEY_LEN]);
            for (b, k) in body.iter().zip(ks.iter()) {
                out.push(b ^ k);
            }
            Some(out)
        } else {
            // data class — too short to have masked [0..4] means it's not ours;
            // pass through unchanged so the framing's length gate drops it.
            if wire.len() < DATA_MASKABLE_MIN {
                return Some(wire.to_vec());
            }
            let mut out = wire.to_vec();
            self.xor_demux(&mut out);
            Some(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rk() -> [u8; ROUTING_KEY_LEN] {
        let mut k = [0u8; ROUTING_KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        k
    }

    fn shaper() -> ScrambleV1 {
        ScrambleV1::new(&rk(), &[0x42u8; 16])
    }

    #[test]
    fn data_class_round_trips_and_masks_the_index() {
        let s = shaper();
        // recv_index(4) | protected_counter(8) | ciphertext...
        let framed: Vec<u8> = (0..40u8).collect();
        let wire = s.obfuscate(&framed, false);
        assert_eq!(wire.len(), framed.len(), "data class adds no bytes");
        assert_ne!(
            &wire[..4],
            &framed[..4],
            "demux field is masked on the wire"
        );
        assert_eq!(&wire[4..], &framed[4..], "only the leading 4 bytes change");
        assert_eq!(s.deobfuscate(&wire).unwrap(), framed, "round-trips");
    }

    #[test]
    fn masked_index_varies_with_the_counter() {
        // Two packets with the SAME recv_index but different counters must not
        // produce the same masked prefix (this is the index-echo tell being closed).
        let s = shaper();
        let mut a: Vec<u8> = vec![9, 9, 9, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb];
        let mut b = a.clone();
        b[7] = 7; // different counter byte
        let wa = s.obfuscate(&a, false);
        let wb = s.obfuscate(&b, false);
        assert_ne!(
            &wa[..4],
            &wb[..4],
            "same index, different counter -> different masked prefix"
        );
        // sanity: both still round-trip
        assert_eq!(&s.deobfuscate(&wa).unwrap()[..4], &[9, 9, 9, 9]);
        a[0] = 9; // silence unused-mut in some toolchains
        let _ = a;
    }

    #[test]
    fn msg1_round_trips_keeps_routing_key_and_varies() {
        let s = shaper();
        let mut framed = vec![0u8; MSG1_FRAMED_LEN];
        framed[..ROUTING_KEY_LEN].copy_from_slice(&rk());
        for (i, b) in framed[ROUTING_KEY_LEN..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        let w1 = s.obfuscate(&framed, true);
        let w2 = s.obfuscate(&framed, true);
        assert_eq!(
            &w1[..ROUTING_KEY_LEN],
            &rk(),
            "routing_key stays cleartext for the relay"
        );
        assert!(w1.len() >= MSG1_WIRE_MIN, "at least routing_key+nonce+body");
        // Fresh nonce + pad each call -> different wire bytes and (usually) length.
        assert_ne!(w1, w2, "retransmits differ (fresh nonce/pad)");
        assert_ne!(
            &w1[ROUTING_KEY_LEN + MSG1_NONCE..MSG1_WIRE_MIN],
            &framed[ROUTING_KEY_LEN..],
            "body is masked"
        );
        assert_eq!(
            s.deobfuscate(&w1).unwrap(),
            framed,
            "round-trips to the exact framed msg1"
        );
        assert_eq!(s.deobfuscate(&w2).unwrap(), framed);
    }

    #[test]
    fn keyed_per_identity_no_cross_user_signature() {
        let a = ScrambleV1::new(&rk(), &[1u8; 16]);
        let b = ScrambleV1::new(&rk(), &[2u8; 16]); // same routing_key, different secret
        let framed: Vec<u8> = (0..40u8).collect();
        assert_ne!(
            a.obfuscate(&framed, false),
            b.obfuscate(&framed, false),
            "different secret -> different wire"
        );
    }

    #[test]
    fn deobfuscate_is_total_on_garbage_and_truncation() {
        let s = shaper();
        // Never panics, whatever the length or content.
        for len in 0..90usize {
            let mut buf = vec![0x5au8; len];
            // half the cases: prefix with routing_key so the msg1 branch is exercised
            if len >= ROUTING_KEY_LEN && len % 2 == 0 {
                buf[..ROUTING_KEY_LEN].copy_from_slice(&rk());
            }
            let _ = s.deobfuscate(&buf); // must not panic
        }
        // A routing_key-prefixed but too-short packet is rejected, not restored.
        let mut short = vec![0u8; MSG1_WIRE_MIN - 1];
        short[..ROUTING_KEY_LEN].copy_from_slice(&rk());
        assert!(s.deobfuscate(&short).is_none());
    }

    #[test]
    fn identity_is_passthrough() {
        let s = Identity;
        let framed: Vec<u8> = (0..40u8).collect();
        assert_eq!(s.obfuscate(&framed, false), framed);
        assert_eq!(s.obfuscate(&framed, true), framed);
        assert_eq!(s.deobfuscate(&framed).unwrap(), framed);
    }
}
