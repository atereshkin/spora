//! Share-side IP fragment reassembly.
//!
//! The tunnel ([`crate::transport::quic::QuicPeerTransport`]) fragments any
//! inner datagram larger than the QUIC `max_datagram_size` — IPv4 via classic
//! header fragmentation, IPv6 via the RFC 8200 Fragment extension header. On
//! the share→client direction the client's *kernel* reassembles. On the
//! client→share direction there is no kernel: packets feed the userland
//! smoltcp netstack, which parses each IP packet in isolation
//! (`UdpPacket::new_checked` length-checks the leading fragment and drops it,
//! the rest are orphans) — so an oversized inbound UDP datagram (large DNS,
//! an HTTP/3 upload, anything sent before the client's MTU callback fires) is
//! silently blackholed.
//!
//! [`IpReassembler`] sits in front of the netstack and rebuilds whole
//! datagrams from fragments. Unfragmented and non-IP packets pass straight
//! through. Incomplete groups are evicted by age and a hard group cap bounds
//! memory against a peer that sends fragments and never completes them.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// Drop a partially-reassembled datagram if it isn't completed within this
/// window (RFC 791 suggests a similar order of magnitude).
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on concurrently-tracked fragment groups (memory bound).
const MAX_GROUPS: usize = 256;
/// An IP payload length field maxes out at 65535 bytes (both families).
const MAX_DATAGRAM_LEN: usize = 65_535;

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
enum FragKey {
    V4 {
        src: [u8; 4],
        dst: [u8; 4],
        proto: u8,
        id: u16,
    },
    /// RFC 8200 groups by (src, dst, identification); the protocol lives in
    /// the Fragment header itself.
    V6 {
        src: [u8; 16],
        dst: [u8; 16],
        id: u32,
    },
}

struct FragGroup {
    /// IP header taken from the offset-0 fragment, or empty until it arrives.
    /// IPv4: the ihl bytes verbatim. IPv6: the 40-byte fixed header with
    /// `next_header` already rewritten back to the Fragment header's
    /// transport protocol (the Fragment header itself is stripped).
    header: Vec<u8>,
    /// offset-in-bytes -> payload chunk.
    chunks: BTreeMap<usize, Vec<u8>>,
    /// Sum of stored chunk bytes — bounded to keep an overlapping-fragment
    /// flood from ballooning a single group's memory.
    stored_bytes: usize,
    /// Total payload length, known once the last fragment (MF=0) is seen.
    total_len: Option<usize>,
    deadline: Instant,
}

impl FragGroup {
    fn new(now: Instant) -> Self {
        Self {
            header: Vec::new(),
            chunks: BTreeMap::new(),
            stored_bytes: 0,
            total_len: None,
            deadline: now + REASSEMBLY_TIMEOUT,
        }
    }

    /// Whether every byte from 0 to `total_len` is covered and the header is
    /// present. Tolerates duplicate/overlapping fragments.
    fn complete(&self) -> bool {
        let Some(total) = self.total_len else {
            return false;
        };
        if self.header.is_empty() {
            return false;
        }
        let mut covered_end = 0usize;
        for (&off, chunk) in &self.chunks {
            if off > covered_end {
                return false; // gap
            }
            covered_end = covered_end.max(off + chunk.len());
        }
        covered_end >= total
    }

    /// Rebuild the whole datagram: header (lengths fixed; for IPv4 the
    /// fragment bits cleared and checksum recomputed) followed by the
    /// assembled payload.
    fn assemble(&self) -> Vec<u8> {
        let total = self.total_len.expect("complete() checked total_len");
        let hdr_len = self.header.len();
        let mut payload = vec![0u8; total];
        for (&off, chunk) in &self.chunks {
            let end = (off + chunk.len()).min(total);
            if off < end {
                payload[off..end].copy_from_slice(&chunk[..end - off]);
            }
        }
        let mut out = Vec::with_capacity(hdr_len + total);
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&payload);
        if (out[0] >> 4) == 6 {
            // IPv6: only payload_length needs fixing (next_header was
            // restored when the header was stored; there is no checksum).
            out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
            return out;
        }
        // Total length.
        let total_len = (hdr_len + total) as u16;
        out[2..4].copy_from_slice(&total_len.to_be_bytes());
        // Clear flags + fragment offset (MF, DF, offset all go to 0).
        out[6] = 0;
        out[7] = 0;
        // Recompute the header checksum.
        out[10] = 0;
        out[11] = 0;
        let csum = ipv4_header_checksum(&out[..hdr_len]);
        out[10..12].copy_from_slice(&csum.to_be_bytes());
        out
    }
}

#[derive(Default)]
pub struct IpReassembler {
    groups: HashMap<FragKey, FragGroup>,
}

impl IpReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one inbound IP packet; returns the packets to hand to the
    /// netstack. A non-IP or unfragmented packet passes straight through
    /// (one out). A fragment yields nothing until its datagram completes,
    /// then the single reassembled packet.
    pub fn process(&mut self, pkt: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
        // Drive age-based eviction off every packet (cheap when no groups are
        // in flight), so a stale group can't linger behind a stream of
        // unfragmented traffic.
        if !self.groups.is_empty() {
            self.evict_expired(now);
        }

        // (key, header for the offset-0 fragment, offset, more-fragments,
        // payload chunk range start) — or pass the packet through untouched.
        let (key, header, offset_bytes, mf, data_start) = match pkt.first().map(|b| b >> 4) {
            Some(4) if pkt.len() >= 20 => {
                let ihl = ((pkt[0] & 0x0f) as usize) * 4;
                if ihl < 20 || pkt.len() < ihl {
                    return vec![pkt];
                }
                let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
                let mf = (flags_frag & 0x2000) != 0;
                let offset_bytes = ((flags_frag & 0x1fff) as usize) * 8;
                // Unfragmented: no MF and zero offset → pass straight through.
                if !mf && offset_bytes == 0 {
                    return vec![pkt];
                }
                let key = FragKey::V4 {
                    src: [pkt[12], pkt[13], pkt[14], pkt[15]],
                    dst: [pkt[16], pkt[17], pkt[18], pkt[19]],
                    proto: pkt[9],
                    id: u16::from_be_bytes([pkt[4], pkt[5]]),
                };
                (key, pkt[..ihl].to_vec(), offset_bytes, mf, ihl)
            }
            // IPv6 with a leading Fragment header (the only ext header the
            // tunnel's own fragmentation produces). Other v6 packets pass
            // through whole.
            Some(6) if pkt.len() >= 48 && pkt[6] == 44 => {
                let off_flags = u16::from_be_bytes([pkt[42], pkt[43]]);
                let mf = (off_flags & 1) != 0;
                let offset_bytes = ((off_flags >> 3) as usize) * 8;
                let key = FragKey::V6 {
                    src: pkt[8..24].try_into().expect("16 bytes"),
                    dst: pkt[24..40].try_into().expect("16 bytes"),
                    id: u32::from_be_bytes([pkt[44], pkt[45], pkt[46], pkt[47]]),
                };
                // Store the fixed header with next_header restored to the
                // transport protocol — the Fragment header is stripped here.
                let mut header = pkt[..40].to_vec();
                header[6] = pkt[40];
                (key, header, offset_bytes, mf, 48)
            }
            _ => return vec![pkt],
        };

        let payload_len = pkt.len() - data_start;
        // Reject implausible offsets (a malformed peer) rather than allocate.
        if offset_bytes + payload_len > MAX_DATAGRAM_LEN {
            return Vec::new();
        }
        // Bound the number of distinct in-flight datagrams.
        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_GROUPS {
            self.evict_oldest();
        }

        let group = self
            .groups
            .entry(key)
            .or_insert_with(|| FragGroup::new(now));
        if offset_bytes == 0 {
            group.header = header;
        }
        if !mf {
            group.total_len = Some(offset_bytes + payload_len);
        }
        // Insert the chunk. An exact-offset duplicate is ignored. A *new*
        // offset is rejected if it would push the group past MAX_DATAGRAM_LEN of
        // stored payload: a legitimate datagram's fragments never overlap, so
        // they sum to at most the datagram size, but a malicious peer can spray
        // overlapping fragments at offsets 0,8,16,… each carrying a full payload
        // and never completing the datagram. Without this bound that stores many
        // MiB per group; with it, each group holds at most ~64 KiB.
        if !group.chunks.contains_key(&offset_bytes) {
            if group.stored_bytes + payload_len > MAX_DATAGRAM_LEN {
                return Vec::new();
            }
            group.stored_bytes += payload_len;
            group
                .chunks
                .insert(offset_bytes, pkt[data_start..].to_vec());
        }

        if group.complete() {
            let group = self.groups.remove(&key).expect("just inserted");
            vec![group.assemble()]
        } else {
            Vec::new()
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        self.groups.retain(|_, g| g.deadline > now);
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .groups
            .iter()
            .min_by_key(|(_, g)| g.deadline)
            .map(|(k, _)| *k)
        {
            self.groups.remove(&key);
        }
    }
}

/// Standard IPv4 header checksum (ones'-complement sum of 16-bit words).
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an IPv4/UDP packet with `payload_len` bytes of UDP payload.
    fn ipv4_udp(id: u16, payload_len: usize) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .udp(40000, 5678)
            .write(&mut pkt, &vec![0xABu8; payload_len])
            .unwrap();
        // Set the IP identification field (etherparse defaults it to 0).
        pkt[4..6].copy_from_slice(&id.to_be_bytes());
        // Recompute header checksum after touching the id.
        pkt[10] = 0;
        pkt[11] = 0;
        let c = ipv4_header_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        pkt
    }

    /// The reassembled form a correct reassembler must produce: identical to
    /// the original except the fragment word (DF/MF/offset) is cleared and the
    /// header checksum recomputed. (etherparse sets DF on its packets.)
    fn normalize(pkt: &[u8]) -> Vec<u8> {
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        let mut out = pkt.to_vec();
        out[6] = 0;
        out[7] = 0;
        out[10] = 0;
        out[11] = 0;
        let c = ipv4_header_checksum(&out[..ihl]);
        out[10..12].copy_from_slice(&c.to_be_bytes());
        out
    }

    /// Fragment an IPv4 packet into chunks of at most `max_data` payload bytes
    /// (8-byte aligned), the way the tunnel does.
    fn fragment(pkt: &[u8], max_data: usize) -> Vec<Vec<u8>> {
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        let header = &pkt[..ihl];
        let payload = &pkt[ihl..];
        let max_data = max_data & !7;
        let mut frags = Vec::new();
        let mut off = 0;
        while off < payload.len() {
            let end = (off + max_data).min(payload.len());
            let is_last = end >= payload.len();
            let mut f = Vec::new();
            f.extend_from_slice(header);
            f.extend_from_slice(&payload[off..end]);
            let total = (ihl + (end - off)) as u16;
            f[2..4].copy_from_slice(&total.to_be_bytes());
            let mut flags_frag = ((off / 8) as u16) & 0x1fff;
            if !is_last {
                flags_frag |= 0x2000;
            }
            f[6..8].copy_from_slice(&flags_frag.to_be_bytes());
            f[10] = 0;
            f[11] = 0;
            let c = ipv4_header_checksum(&f[..ihl]);
            f[10..12].copy_from_slice(&c.to_be_bytes());
            frags.push(f);
            off = end;
        }
        frags
    }

    #[test]
    fn unfragmented_passes_through_untouched() {
        let mut r = IpReassembler::new();
        let pkt = ipv4_udp(1, 100);
        let out = r.process(pkt.clone(), Instant::now());
        assert_eq!(out, vec![pkt]);
    }

    #[test]
    fn non_ipv4_passes_through() {
        let mut r = IpReassembler::new();
        let v6 = vec![0x60u8; 80];
        assert_eq!(r.process(v6.clone(), Instant::now()), vec![v6]);
        let tiny = vec![0x45u8, 0x00];
        assert_eq!(r.process(tiny.clone(), Instant::now()), vec![tiny]);
    }

    #[test]
    fn reassembles_in_order() {
        let mut r = IpReassembler::new();
        let now = Instant::now();
        let pkt = ipv4_udp(7, 2000);
        let frags = fragment(&pkt, 1400);
        assert!(frags.len() >= 2);

        let mut out = Vec::new();
        for f in &frags {
            out.extend(r.process(f.clone(), now));
        }
        assert_eq!(out.len(), 1, "exactly one reassembled packet");
        assert_eq!(
            out[0],
            normalize(&pkt),
            "reassembles to the original (DF cleared)"
        );
    }

    #[test]
    fn reassembles_out_of_order_and_with_a_duplicate() {
        let mut r = IpReassembler::new();
        let now = Instant::now();
        let pkt = ipv4_udp(9, 3000);
        let mut frags = fragment(&pkt, 800);
        assert!(frags.len() >= 3);
        // Reorder and duplicate one fragment.
        frags.reverse();
        let dup = frags[1].clone();
        frags.insert(0, dup);

        let mut out = Vec::new();
        for f in &frags {
            out.extend(r.process(f.clone(), now));
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], normalize(&pkt));
    }

    #[test]
    fn interleaved_datagrams_reassemble_independently() {
        let mut r = IpReassembler::new();
        let now = Instant::now();
        let a = ipv4_udp(11, 2000);
        let b = ipv4_udp(22, 2500);
        let fa = fragment(&a, 1000);
        let fb = fragment(&b, 1000);

        let mut out = Vec::new();
        // Interleave the two fragment trains.
        for i in 0..fa.len().max(fb.len()) {
            if let Some(f) = fa.get(i) {
                out.extend(r.process(f.clone(), now));
            }
            if let Some(f) = fb.get(i) {
                out.extend(r.process(f.clone(), now));
            }
        }
        assert_eq!(out.len(), 2);
        assert!(out.contains(&normalize(&a)));
        assert!(out.contains(&normalize(&b)));
    }

    #[test]
    fn incomplete_group_is_evicted_after_timeout() {
        let mut r = IpReassembler::new();
        let t0 = Instant::now();
        let pkt = ipv4_udp(31, 2000);
        let frags = fragment(&pkt, 800);
        // Deliver all but the last fragment.
        for f in &frags[..frags.len() - 1] {
            assert!(r.process(f.clone(), t0).is_empty());
        }
        assert_eq!(r.groups.len(), 1);
        // A later packet triggers eviction of the stale group.
        let unrelated = ipv4_udp(32, 50);
        r.process(unrelated, t0 + REASSEMBLY_TIMEOUT + Duration::from_secs(1));
        assert_eq!(r.groups.len(), 0, "stale group evicted");
    }

    /// A raw IPv4/UDP fragment at an arbitrary byte offset (MF set, never last).
    fn raw_frag(id: u16, offset_bytes: usize, payload_len: usize) -> Vec<u8> {
        let mut f = vec![0u8; 20 + payload_len];
        f[0] = 0x45; // IPv4, ihl=5
        let total = (20 + payload_len) as u16;
        f[2..4].copy_from_slice(&total.to_be_bytes());
        f[4..6].copy_from_slice(&id.to_be_bytes());
        let ff = (((offset_bytes / 8) as u16) & 0x1fff) | 0x2000; // MF set
        f[6..8].copy_from_slice(&ff.to_be_bytes());
        f[8] = 64; // ttl
        f[9] = 17; // UDP
        f[12..16].copy_from_slice(&[10, 0, 0, 2]);
        f[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let c = ipv4_header_checksum(&f[..20]);
        f[10..12].copy_from_slice(&c.to_be_bytes());
        f
    }

    #[test]
    fn overlapping_fragments_are_byte_bounded() {
        let mut r = IpReassembler::new();
        let now = Instant::now();
        // Spray overlapping fragments at offsets 0,8,16,… each carrying a full
        // ~1.3 KiB payload, none completing the datagram. Each is a new offset,
        // so without a per-group byte bound they all accumulate (many MiB).
        let payload_len = 1304; // multiple of 8
        for unit in 0..2000u16 {
            let off = (unit as usize) * 8;
            if off + payload_len > MAX_DATAGRAM_LEN {
                break;
            }
            r.process(raw_frag(7, off, payload_len), now);
        }
        let g = r.groups.values().next().expect("one in-flight group");
        assert!(
            g.stored_bytes <= MAX_DATAGRAM_LEN,
            "per-group stored bytes must be bounded, got {}",
            g.stored_bytes
        );
        // And the cap doesn't break legitimate reassembly.
        let pkt = ipv4_udp(99, 4000);
        let frags = fragment(&pkt, 1000);
        let mut out = Vec::new();
        for fr in &frags {
            out.extend(r.process(fr.clone(), now));
        }
        assert_eq!(out, vec![normalize(&pkt)]);
    }

    /// Build an IPv6/UDP packet with `payload_len` bytes of UDP payload.
    fn ipv6_udp(payload_len: usize) -> Vec<u8> {
        let src = std::net::Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 2);
        let dst = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
            .udp(40000, 5678)
            .write(&mut pkt, &vec![0xABu8; payload_len])
            .unwrap();
        pkt
    }

    /// Fragment an IPv6 packet the way the tunnel does (RFC 8200 Fragment
    /// extension header), `max_data` payload bytes per fragment (8-aligned).
    fn fragment_v6(pkt: &[u8], max_data: usize, id: u32) -> Vec<Vec<u8>> {
        let next_header = pkt[6];
        let payload = &pkt[40..];
        let max_data = max_data & !7;
        let mut frags = Vec::new();
        let mut off = 0;
        while off < payload.len() {
            let end = (off + max_data).min(payload.len());
            let is_last = end >= payload.len();
            let mut f = pkt[..40].to_vec();
            f[6] = 44;
            f[4..6].copy_from_slice(&((8 + end - off) as u16).to_be_bytes());
            f.push(next_header);
            f.push(0);
            let off_flags = (((off / 8) as u16) << 3) | u16::from(!is_last);
            f.extend_from_slice(&off_flags.to_be_bytes());
            f.extend_from_slice(&id.to_be_bytes());
            f.extend_from_slice(&payload[off..end]);
            frags.push(f);
            off = end;
        }
        frags
    }

    #[test]
    fn ipv6_non_fragment_passes_through() {
        let mut r = IpReassembler::new();
        let pkt = ipv6_udp(100);
        assert_eq!(r.process(pkt.clone(), Instant::now()), vec![pkt]);
    }

    #[test]
    fn reassembles_ipv6_fragments_out_of_order() {
        let mut r = IpReassembler::new();
        let now = Instant::now();
        let pkt = ipv6_udp(3000);
        let mut frags = fragment_v6(&pkt, 1024, 0xDEAD_BEEF);
        assert!(frags.len() >= 3);
        frags.reverse();

        let mut out = Vec::new();
        for f in &frags {
            out.extend(r.process(f.clone(), now));
        }
        // IPv6 reassembly is bit-exact: no checksum or flag fixups needed.
        assert_eq!(out, vec![pkt]);
    }

    #[test]
    fn interleaved_v4_and_v6_trains_reassemble_independently() {
        let mut r = IpReassembler::new();
        let now = Instant::now();
        let a = ipv4_udp(11, 2000);
        let b = ipv6_udp(2500);
        let fa = fragment(&a, 1000);
        let fb = fragment_v6(&b, 1000, 7);

        let mut out = Vec::new();
        for i in 0..fa.len().max(fb.len()) {
            if let Some(f) = fa.get(i) {
                out.extend(r.process(f.clone(), now));
            }
            if let Some(f) = fb.get(i) {
                out.extend(r.process(f.clone(), now));
            }
        }
        assert_eq!(out.len(), 2);
        assert!(out.contains(&normalize(&a)));
        assert!(out.contains(&b));
    }

    #[test]
    fn ipv6_fragments_with_distinct_ids_do_not_mix() {
        let mut r = IpReassembler::new();
        let now = Instant::now();
        let pkt = ipv6_udp(2000);
        let fa = fragment_v6(&pkt, 1024, 1);
        let fb = fragment_v6(&pkt, 1024, 2);
        // First fragment of train A, then ALL of train B: only B completes.
        assert!(r.process(fa[0].clone(), now).is_empty());
        let mut out = Vec::new();
        for f in &fb {
            out.extend(r.process(f.clone(), now));
        }
        assert_eq!(out, vec![pkt]);
        assert_eq!(r.groups.len(), 1, "train A still pending under its own id");
    }

    #[test]
    fn truncated_ipv6_fragment_header_passes_through() {
        // 6-in-the-version-nibble but too short for fixed+fragment headers:
        // must not panic, must not be eaten.
        let mut r = IpReassembler::new();
        let mut junk = vec![0x60u8; 44];
        junk[6] = 44;
        assert_eq!(r.process(junk.clone(), Instant::now()), vec![junk]);
    }

    #[test]
    fn group_cap_is_enforced() {
        let mut r = IpReassembler::new();
        let now = Instant::now();
        // Open more than MAX_GROUPS incomplete datagrams (first fragment only).
        for id in 0..(MAX_GROUPS as u16 + 50) {
            let pkt = ipv4_udp(id.max(1), 2000);
            let frags = fragment(&pkt, 800);
            r.process(frags[0].clone(), now);
        }
        assert!(r.groups.len() <= MAX_GROUPS, "group count is bounded");
    }
}
