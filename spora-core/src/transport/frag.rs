//! Tunnel-layer IP fragmentation, shared across carriers.
//!
//! Oversized inner packets (e.g. a NATing sharer re-originating UDP that can't
//! be MSS-clamped) are split at the tunnel layer so they fit the carrier's
//! datagram budget; the receiving side (`crate::reassembly::IpReassembler`, the
//! peer's kernel behind a TUN, or the lab pump) reassembles them. This lives
//! outside any one carrier because every datagram carrier — QUIC today, the
//! Noise UDP carrier next — needs the same split.

/// Split an IPv4 packet into fragments that each fit within `max_len` bytes
/// (header + data), so a peer's kernel can reassemble the original. Returns
/// `None` if `pkt` isn't IPv4 or can't be fragmented to fit. Every fragment is
/// stamped with `ip_id` as its IP Identification — the caller must pass a value
/// unique per datagram so the receiver doesn't splice unrelated datagrams.
///
/// We clear the Don't-Fragment bit on the fragments: the alternative for a DF
/// packet is to drop it and emit ICMP "fragmentation needed" back toward the
/// origin, which is impractical here (the origin is out on the internet and
/// the tunnel's small MTU isn't its real path MTU). Delivering via
/// fragmentation is what makes UDP-based protocols work across the tunnel.
pub(crate) fn fragment_ipv4(pkt: &[u8], max_len: usize, ip_id: u16) -> Option<Vec<Vec<u8>>> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None; // not IPv4
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl || max_len <= ihl + 8 {
        return None;
    }
    let header = &pkt[..ihl];
    let payload = &pkt[ihl..];

    // Preserve the original fragment offset / MF in case this packet is itself
    // already a fragment (uncommon for our inputs, but correct).
    let orig_flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let orig_offset_units = (orig_flags_frag & 0x1fff) as usize;
    let orig_mf = (orig_flags_frag & 0x2000) != 0;

    // Each fragment's data must be a multiple of 8 bytes (except the last).
    let max_data = (max_len - ihl) & !7usize;
    if max_data == 0 {
        return None;
    }

    let mut frags = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let end = (off + max_data).min(payload.len());
        let chunk = &payload[off..end];
        let is_last = end >= payload.len();

        let mut frag = Vec::with_capacity(ihl + chunk.len());
        frag.extend_from_slice(header);
        frag.extend_from_slice(chunk);

        // Total length.
        let total_len = (ihl + chunk.len()) as u16;
        frag[2..4].copy_from_slice(&total_len.to_be_bytes());

        // Identification: stamp a fresh per-datagram id (shared by this
        // datagram's fragments, distinct between datagrams). smoltcp originates
        // packets with id=0, so without this every oversized datagram on a flow
        // would fragment under the same (src,dst,proto,id=0) and the receiver's
        // reassembly would splice unrelated datagrams together.
        frag[4..6].copy_from_slice(&ip_id.to_be_bytes());

        // Flags + fragment offset. DF cleared; MF set on all but the last
        // (unless the original was already a mid-stream fragment).
        let frag_offset_units = orig_offset_units + off / 8;
        let mut flags_frag = (frag_offset_units as u16) & 0x1fff;
        if !is_last || orig_mf {
            flags_frag |= 0x2000; // MF
        }
        frag[6..8].copy_from_slice(&flags_frag.to_be_bytes());

        // Recompute the header checksum over the modified header.
        frag[10] = 0;
        frag[11] = 0;
        let csum = ipv4_header_checksum(&frag[..ihl]);
        frag[10..12].copy_from_slice(&csum.to_be_bytes());

        frags.push(frag);
        off = end;
    }
    Some(frags)
}

/// IPv6 extension headers we refuse to fragment behind (RFC 8200 would put
/// some of them in the unfragmentable part, but our tunnel only ever needs to
/// fragment plain transport packets — anything else is dropped as before).
fn is_ipv6_ext_header(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 50 | 51 | 60)
}

/// Split an IPv6 packet into fragments that each fit within `max_len` bytes,
/// using the RFC 8200 Fragment extension header, so the receiving side (the
/// peer's kernel behind a TUN, or our reassemblers in front of the netstack)
/// can rebuild the original. Returns `None` if `pkt` isn't a plain-transport
/// IPv6 packet (extension headers present) or can't be fragmented to fit.
/// Every fragment carries `frag_id` as its 32-bit Identification — the caller
/// must pass a value unique per datagram.
///
/// Layout per fragment: the original 40-byte fixed header with `next_header`
/// rewritten to 44 and `payload_length` updated, then the 8-byte Fragment
/// header `[next_header, 0, offset/flags (13-bit offset in 8-byte units, bit
/// 0 = M), id (4 bytes)]`, then the payload slice.
pub(crate) fn fragment_ipv6(pkt: &[u8], max_len: usize, frag_id: u32) -> Option<Vec<Vec<u8>>> {
    const FIXED: usize = 40;
    const FRAG_HDR: usize = 8;
    if pkt.len() < FIXED || (pkt[0] >> 4) != 6 {
        return None;
    }
    let next_header = pkt[6];
    if is_ipv6_ext_header(next_header) {
        return None;
    }
    if max_len <= FIXED + FRAG_HDR + 8 {
        return None;
    }
    let payload = &pkt[FIXED..];

    // Each fragment's data must be a multiple of 8 bytes (except the last).
    let max_data = (max_len - FIXED - FRAG_HDR) & !7usize;
    // Offsets are 13 bits of 8-byte units; anything that would overflow them
    // can't be represented (a >64 KiB packet can't reach us anyway).
    if payload.len() > (1 << 13) * 8 {
        return None;
    }

    let mut frags = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let end = (off + max_data).min(payload.len());
        let chunk = &payload[off..end];
        let is_last = end >= payload.len();

        let mut frag = Vec::with_capacity(FIXED + FRAG_HDR + chunk.len());
        frag.extend_from_slice(&pkt[..FIXED]);
        // Fixed header: next_header = Fragment, payload_length covers the
        // fragment header + this chunk.
        frag[6] = 44;
        let payload_len = (FRAG_HDR + chunk.len()) as u16;
        frag[4..6].copy_from_slice(&payload_len.to_be_bytes());
        // Fragment extension header.
        frag.push(next_header);
        frag.push(0);
        let mut off_flags = ((off / 8) as u16) << 3;
        if !is_last {
            off_flags |= 1; // M: more fragments
        }
        frag.extend_from_slice(&off_flags.to_be_bytes());
        frag.extend_from_slice(&frag_id.to_be_bytes());
        frag.extend_from_slice(chunk);

        frags.push(frag);
        off = end;
    }
    Some(frags)
}

/// Standard IPv4 header checksum (ones'-complement sum of 16-bit words).
pub(crate) fn ipv4_header_checksum(header: &[u8]) -> u16 {
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
