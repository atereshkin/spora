//! Share-side IPv4 fragment reassembly.
//!
//! The tunnel ([`crate::transport::quic::QuicPeerTransport`]) IPv4-fragments
//! any inner datagram larger than the QUIC `max_datagram_size`. On the
//! share→client direction the client's *kernel* reassembles. On the
//! client→share direction there is no kernel: packets feed the userland
//! smoltcp netstack, which parses each IP packet in isolation
//! (`UdpPacket::new_checked` length-checks the leading fragment and drops it,
//! the rest are orphans) — so an oversized inbound UDP datagram (large DNS,
//! an HTTP/3 upload, anything sent before the client's MTU callback fires) is
//! silently blackholed.
//!
//! [`IpReassembler`] sits in front of the netstack and rebuilds whole
//! datagrams from fragments. Unfragmented and non-IPv4 packets pass straight
//! through. Incomplete groups are evicted by age and a hard group cap bounds
//! memory against a peer that sends fragments and never completes them.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// Drop a partially-reassembled datagram if it isn't completed within this
/// window (RFC 791 suggests a similar order of magnitude).
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on concurrently-tracked fragment groups (memory bound).
const MAX_GROUPS: usize = 256;
/// An IPv4 total length maxes out at 65535 bytes.
const MAX_DATAGRAM_LEN: usize = 65_535;

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FragKey {
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    id: u16,
}

struct FragGroup {
    /// IP header (ihl bytes) taken from the offset-0 fragment, or empty until
    /// it arrives.
    header: Vec<u8>,
    /// offset-in-bytes -> payload chunk.
    chunks: BTreeMap<usize, Vec<u8>>,
    /// Total payload length, known once the last fragment (MF=0) is seen.
    total_len: Option<usize>,
    deadline: Instant,
}

impl FragGroup {
    fn new(now: Instant) -> Self {
        Self {
            header: Vec::new(),
            chunks: BTreeMap::new(),
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

    /// Rebuild the whole datagram: header (length fixed, fragment bits
    /// cleared, checksum recomputed) followed by the assembled payload.
    fn assemble(&self) -> Vec<u8> {
        let total = self.total_len.expect("complete() checked total_len");
        let ihl = self.header.len();
        let mut payload = vec![0u8; total];
        for (&off, chunk) in &self.chunks {
            let end = (off + chunk.len()).min(total);
            if off < end {
                payload[off..end].copy_from_slice(&chunk[..end - off]);
            }
        }
        let mut out = Vec::with_capacity(ihl + total);
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&payload);
        // Total length.
        let total_len = (ihl + total) as u16;
        out[2..4].copy_from_slice(&total_len.to_be_bytes());
        // Clear flags + fragment offset (MF, DF, offset all go to 0).
        out[6] = 0;
        out[7] = 0;
        // Recompute the header checksum.
        out[10] = 0;
        out[11] = 0;
        let csum = ipv4_header_checksum(&out[..ihl]);
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
    /// netstack. A non-IPv4 or unfragmented packet passes straight through
    /// (one out). A fragment yields nothing until its datagram completes,
    /// then the single reassembled packet.
    pub fn process(&mut self, pkt: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
        // Drive age-based eviction off every packet (cheap when no groups are
        // in flight), so a stale group can't linger behind a stream of
        // unfragmented traffic.
        if !self.groups.is_empty() {
            self.evict_expired(now);
        }

        // Not IPv4, or too short to inspect fragmentation → pass through.
        if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
            return vec![pkt];
        }
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

        let key = FragKey {
            src: [pkt[12], pkt[13], pkt[14], pkt[15]],
            dst: [pkt[16], pkt[17], pkt[18], pkt[19]],
            proto: pkt[9],
            id: u16::from_be_bytes([pkt[4], pkt[5]]),
        };
        let payload_len = pkt.len() - ihl;
        // Reject implausible offsets (a malformed peer) rather than allocate.
        if offset_bytes + payload_len > MAX_DATAGRAM_LEN {
            return Vec::new();
        }
        // Bound the number of distinct in-flight datagrams.
        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_GROUPS {
            self.evict_oldest();
        }

        let group = self.groups.entry(key).or_insert_with(|| FragGroup::new(now));
        if offset_bytes == 0 {
            group.header = pkt[..ihl].to_vec();
        }
        if !mf {
            group.total_len = Some(offset_bytes + payload_len);
        }
        // Insert the chunk (ignoring an exact duplicate offset to bound memory).
        group
            .chunks
            .entry(offset_bytes)
            .or_insert_with(|| pkt[ihl..].to_vec());

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
        assert_eq!(out[0], normalize(&pkt), "reassembles to the original (DF cleared)");
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
