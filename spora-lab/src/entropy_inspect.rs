//! Tier-3-lite entropy/shape inspector for the nz carrier — the self-contained
//! "DPI's-eye view" analogue of [`crate::quic_inspect`], but for a non-QUIC
//! high-entropy UDP flow. It reimplements, in-tree, the structural tells a
//! passive censor can act on and lets a lab scenario assert them red→green
//! (bare nz flagged → shaped nz passes). No nDPI/Suricata/CensorLab.
//!
//! It works purely from captured UDP payloads plus the (public) `routing_key`,
//! which is the one field both bare and shaped nz carry in clear at `[0..20]` of
//! the handshake's first packet — so msg1 is always locatable, and its size and
//! the demux-index echo are measurable without decrypting anything.

use crate::quic_inspect::udp_payloads_from_pcap;

const ROUTING_KEY_LEN: usize = 20;
/// The exact size of a bare (unshaped) nz msg1: routing_key(20)+idx_B(4)+NNpsk0(48).
pub const BARE_MSG1_LEN: usize = 72;
/// Bytes at which bare msg1 carries `idx_B`, echoed at `[0..4]` of bare msg2.
const IDX_B_LO: usize = ROUTING_KEY_LEN;
const IDX_B_HI: usize = ROUTING_KEY_LEN + 4;

/// What a passive censor can extract from an nz flow's structural tells.
#[derive(Debug, Clone)]
pub struct NzFlowReport {
    /// Sizes of every datagram whose first 20 bytes are the `routing_key` — i.e.
    /// every msg1 (and its relay-forwarded copies / retransmits). Bare nz: all
    /// exactly [`BARE_MSG1_LEN`]. Shaped nz: nonce+pad, always larger and varied.
    pub msg1_sizes: Vec<usize>,
    /// True if some later datagram begins with an msg1's `[20..24]` bytes — the
    /// bare-nz `idx_B` echoed by msg2. Shaped nz masks both, so this is false.
    pub index_echo: bool,
    /// Set-bits-per-byte (population count / length) of the first msg1 payload —
    /// the GFW "fully-encrypted" metric. Reported, not gated: masking leaves this
    /// ~4.0 (inside the (3.4,4.6) block band); escaping the band is a follow-up.
    pub first_msg1_popcount: Option<f64>,
    /// Total datagrams seen (sanity: a real session captured something).
    pub datagrams: usize,
}

impl NzFlowReport {
    /// The bare-nz structural signature a passive censor keys on: a fixed
    /// 72-byte first packet AND the idx_B echo. True = trivially classifiable.
    pub fn looks_like_bare_nz(&self) -> bool {
        let has_bare_msg1 = self.msg1_sizes.iter().any(|&s| s == BARE_MSG1_LEN);
        has_bare_msg1 && self.index_echo
    }

    /// The shaped invariants a scenario asserts (green): msg1 is present but never
    /// the bare fixed size, and the index echo is gone.
    pub fn passes_shaping(&self) -> bool {
        !self.msg1_sizes.is_empty()
            && self.msg1_sizes.iter().all(|&s| s > BARE_MSG1_LEN)
            && !self.index_echo
    }
}

fn set_bits_per_byte(p: &[u8]) -> f64 {
    if p.is_empty() {
        return 0.0;
    }
    let ones: u32 = p.iter().map(|b| b.count_ones()).sum();
    ones as f64 / p.len() as f64
}

/// Analyze captured UDP payloads for the nz structural tells against a known
/// `routing_key`.
pub fn analyze(payloads: &[Vec<u8>], routing_key: &[u8; ROUTING_KEY_LEN]) -> NzFlowReport {
    let is_msg1 = |p: &[u8]| p.len() >= ROUTING_KEY_LEN && &p[..ROUTING_KEY_LEN] == routing_key;

    let msg1_sizes: Vec<usize> = payloads
        .iter()
        .filter(|p| is_msg1(p))
        .map(|p| p.len())
        .collect();

    // Echo: does any datagram start with some msg1's [20..24]?
    let mut index_echo = false;
    for m in payloads.iter().filter(|p| is_msg1(p)) {
        if m.len() < IDX_B_HI {
            continue;
        }
        let idx_b = &m[IDX_B_LO..IDX_B_HI];
        if payloads
            .iter()
            .any(|p| !std::ptr::eq(p.as_slice(), m.as_slice()) && p.len() >= 4 && &p[..4] == idx_b)
        {
            index_echo = true;
            break;
        }
    }

    let first_msg1_popcount = payloads
        .iter()
        .find(|p| is_msg1(p))
        .map(|p| set_bits_per_byte(p));

    NzFlowReport {
        msg1_sizes,
        index_echo,
        first_msg1_popcount,
        datagrams: payloads.len(),
    }
}

/// Convenience: analyze a raw pcap directly.
pub fn analyze_pcap(pcap: &[u8], routing_key: &[u8; ROUTING_KEY_LEN]) -> NzFlowReport {
    analyze(&udp_payloads_from_pcap(pcap), routing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rk() -> [u8; ROUTING_KEY_LEN] {
        let mut k = [0u8; ROUTING_KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8) + 1;
        }
        k
    }

    /// Synthetic BARE nz handshake: the 72-byte msg1 and a 56-byte msg2 echoing
    /// idx_B. The inspector must flag both structural tells (the "red" case that
    /// proves it isn't vacuously passing the live shaped capture).
    #[test]
    fn flags_bare_nz_structure() {
        let rk = rk();
        let idx_b = [0xaa, 0xbb, 0xcc, 0xdd];
        let mut msg1 = Vec::new();
        msg1.extend_from_slice(&rk); // [0..20]
        msg1.extend_from_slice(&idx_b); // [20..24]
        msg1.extend_from_slice(&[0x11u8; 48]); // NNpsk0 msg1 -> total 72
        assert_eq!(msg1.len(), BARE_MSG1_LEN);
        let mut msg2 = Vec::new();
        msg2.extend_from_slice(&idx_b); // echo at [0..4]
        msg2.extend_from_slice(&[0x22u8; 52]); // -> total 56
        let data = vec![0x33u8; 1149];

        let r = analyze(&[msg1, msg2, data], &rk);
        assert_eq!(r.msg1_sizes, vec![BARE_MSG1_LEN]);
        assert!(r.index_echo, "bare msg2 echoes idx_B");
        assert!(r.looks_like_bare_nz());
        assert!(!r.passes_shaping());
    }

    /// Synthetic SHAPED nz: msg1 with a nonce+pad (no fixed 72), no echo (idx_B
    /// masked). The inspector must clear it.
    #[test]
    fn passes_shaped_nz_structure() {
        let rk = rk();
        let mut msg1 = Vec::new();
        msg1.extend_from_slice(&rk);
        msg1.extend_from_slice(&[0x77u8; 8]); // nonce
        msg1.extend_from_slice(&[0x88u8; 52]); // masked body
        msg1.extend_from_slice(&[0x99u8; 40]); // pad -> total 120, != 72
        let msg2 = vec![0x12u8; 56]; // masked prefix, no routing_key, no idx_B echo
        let data = vec![0x34u8; 1149];

        let r = analyze(&[msg1, msg2, data], &rk);
        assert!(r.msg1_sizes.iter().all(|&s| s > BARE_MSG1_LEN));
        assert!(!r.index_echo);
        assert!(r.passes_shaping());
        assert!(!r.looks_like_bare_nz());
    }
}
