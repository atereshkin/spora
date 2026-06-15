use std::net::IpAddr;

use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};

pub type AnyIpPktFrame = Vec<u8>;

/// Upper bound on the number of IPv6 extension headers walked before the
/// chain is declared garbage. Real packets carry at most a handful.
const MAX_IPV6_EXT_HEADERS: usize = 8;

/// Walks an IPv6 extension-header chain.
///
/// `first` is the fixed header's Next Header field and `payload` the bytes
/// after the 40-byte fixed header. Skips the skippable extension headers —
/// Hop-by-Hop, Routing, Destination Options, each laid out as
/// `{next_header: u8, hdr_ext_len: u8, ...}` and `(hdr_ext_len + 1) * 8`
/// bytes long — and returns the final transport protocol together with the
/// offset of its header within `payload`.
///
/// The walk stops, without skipping, at:
/// - a Fragment header: a non-first fragment carries no transport header and
///   a first fragment must not be half-parsed, so the packet classifies as
///   `Ipv6Frag`; the stack ignores it (reassembly happens upstream);
/// - anything that is not a skippable extension header: a transport protocol
///   (TCP/UDP/ICMPv6/...) or No Next Header;
/// - a malformed chain (header truncated or extending past the packet end,
///   more than `MAX_IPV6_EXT_HEADERS` headers): the packet stays classified
///   as the unskipped extension protocol, which the stack ignores. Never
///   panics on truncated input.
///
/// The returned offset never exceeds `payload.len()`.
fn walk_ipv6_ext_headers(first: IpProtocol, payload: &[u8]) -> (IpProtocol, usize) {
    let mut protocol = first;
    let mut offset = 0;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match protocol {
            IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Opts => {
                let Some(header) = payload.get(offset..offset + 2) else {
                    return (protocol, offset);
                };
                let len = (usize::from(header[1]) + 1) * 8;
                if payload.len() < offset + len {
                    return (protocol, offset);
                }
                protocol = IpProtocol::from(header[0]);
                offset += len;
            }
            _ => return (protocol, offset),
        }
    }
    (protocol, offset)
}

#[derive(Debug)]
pub(super) enum IpPacket<T: AsRef<[u8]>> {
    Ipv4(Ipv4Packet<T>),
    Ipv6(Ipv6Packet<T>),
}

impl<T: AsRef<[u8]> + Copy> IpPacket<T> {
    pub fn new_checked(packet: T) -> smoltcp::wire::Result<IpPacket<T>> {
        let buffer = packet.as_ref();
        match IpVersion::of_packet(buffer)? {
            IpVersion::Ipv4 => Ok(IpPacket::Ipv4(Ipv4Packet::new_checked(packet)?)),
            IpVersion::Ipv6 => Ok(IpPacket::Ipv6(Ipv6Packet::new_checked(packet)?)),
        }
    }

    pub fn src_addr(&self) -> IpAddr {
        match *self {
            IpPacket::Ipv4(ref packet) => IpAddr::from(packet.src_addr()),
            IpPacket::Ipv6(ref packet) => IpAddr::from(packet.src_addr()),
        }
    }

    pub fn dst_addr(&self) -> IpAddr {
        match *self {
            IpPacket::Ipv4(ref packet) => IpAddr::from(packet.dst_addr()),
            IpPacket::Ipv6(ref packet) => IpAddr::from(packet.dst_addr()),
        }
    }

    /// The transport protocol of the packet.
    ///
    /// For IPv6 this walks the extension-header chain, so a packet carrying
    /// Hop-by-Hop/Routing/Destination Options headers still classifies as its
    /// real transport protocol. Fragments classify as `Ipv6Frag` and
    /// malformed chains as the unskipped extension protocol; both are
    /// ignored by the stack.
    pub fn protocol(&self) -> IpProtocol {
        match *self {
            IpPacket::Ipv4(ref packet) => packet.next_header(),
            IpPacket::Ipv6(ref packet) => {
                let buffer = packet.clone().into_inner();
                let packet = Ipv6Packet::new_unchecked(buffer.as_ref());
                walk_ipv6_ext_headers(packet.next_header(), packet.payload()).0
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> IpPacket<&'a T> {
    /// Return a pointer to the payload.
    ///
    /// For IPv6 this is the payload after the walked extension headers, i.e.
    /// it starts at the header of the protocol that `protocol()` returns.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        match *self {
            IpPacket::Ipv4(ref packet) => packet.payload(),
            IpPacket::Ipv6(ref packet) => {
                let payload = packet.payload();
                let (_, offset) = walk_ipv6_ext_headers(packet.next_header(), payload);
                &payload[offset..]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{TcpPacket, UdpPacket};

    /// A minimal IPv6 packet: fixed header followed by `payload`, with the
    /// fixed header's Next Header set to `next_header`.
    fn ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + payload.len()];
        pkt[0] = 0x60; // version 6
        pkt[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        pkt[6] = next_header;
        pkt[7] = 64; // hop limit
        pkt[23] = 1; // src ::1
        pkt[39] = 2; // dst ::2
        pkt[40..].copy_from_slice(payload);
        pkt
    }

    /// A minimal TCP header (no options, no payload).
    fn tcp_header(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut hdr = vec![0u8; 20];
        hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        hdr[12] = 5 << 4; // data offset: 5 words
        hdr
    }

    /// A minimal UDP header (no payload).
    fn udp_header(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut hdr = vec![0u8; 8];
        hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        hdr[4..6].copy_from_slice(&8u16.to_be_bytes()); // length
        hdr
    }

    #[test]
    fn plain_ipv6_tcp() {
        let builder = etherparse::PacketBuilder::ipv6([0; 16], [1; 16], 64)
            .tcp(443, 50000, 0, 64240);
        let mut frame = Vec::with_capacity(builder.size(0));
        builder.write(&mut frame, &[]).unwrap();

        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::Tcp);
        let tcp = TcpPacket::new_checked(packet.payload()).unwrap();
        assert_eq!(tcp.src_port(), 443);
        assert_eq!(tcp.dst_port(), 50000);
    }

    #[test]
    fn plain_ipv4_tcp_unchanged() {
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .tcp(443, 50000, 0, 64240);
        let mut frame = Vec::with_capacity(builder.size(0));
        builder.write(&mut frame, &[]).unwrap();

        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::Tcp);
        let tcp = TcpPacket::new_checked(packet.payload()).unwrap();
        assert_eq!(tcp.src_port(), 443);
        assert_eq!(tcp.dst_port(), 50000);
    }

    #[test]
    fn hop_by_hop_then_udp() {
        // Hop-by-Hop: next_header=UDP, hdr_ext_len=0 (8 bytes total), then a
        // PadN option filling the remaining 6 bytes.
        let mut payload = vec![17, 0, 1, 4, 0, 0, 0, 0];
        payload.extend_from_slice(&udp_header(5353, 5354));
        let frame = ipv6_packet(0, &payload);

        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::Udp);
        let udp = UdpPacket::new_checked(packet.payload()).unwrap();
        assert_eq!(udp.src_port(), 5353);
        assert_eq!(udp.dst_port(), 5354);
    }

    #[test]
    fn chained_ext_headers_then_tcp() {
        // Hop-by-Hop -> Destination Options -> Routing (16 bytes) -> TCP.
        let mut payload = vec![60, 0, 1, 4, 0, 0, 0, 0];
        payload.extend_from_slice(&[43, 0, 1, 4, 0, 0, 0, 0]);
        payload.extend_from_slice(&[6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        payload.extend_from_slice(&tcp_header(80, 8080));
        let frame = ipv6_packet(0, &payload);

        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::Tcp);
        let tcp = TcpPacket::new_checked(packet.payload()).unwrap();
        assert_eq!(tcp.src_port(), 80);
        assert_eq!(tcp.dst_port(), 8080);
    }

    #[test]
    fn fragment_classifies_as_fragment() {
        // Fragment header (next_header=TCP) followed by what would be the
        // transport header of a first fragment: must classify as a fragment,
        // not TCP — reassembly happens upstream.
        let mut payload = vec![6, 0, 0, 1, 0, 0, 0, 1];
        payload.extend_from_slice(&tcp_header(443, 50000));
        let frame = ipv6_packet(44, &payload);
        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::Ipv6Frag);

        // Same behind a Hop-by-Hop header.
        let mut payload = vec![44, 0, 1, 4, 0, 0, 0, 0];
        payload.extend_from_slice(&[6, 0, 0, 1, 0, 0, 0, 1]);
        payload.extend_from_slice(&tcp_header(443, 50000));
        let frame = ipv6_packet(0, &payload);
        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::Ipv6Frag);
    }

    #[test]
    fn no_next_header_passes_through() {
        let frame = ipv6_packet(59, &[]);
        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::Ipv6NoNxt);
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn truncated_ext_header_falls_back_without_panic() {
        // Fixed header claims Hop-by-Hop but only one payload byte follows.
        let frame = ipv6_packet(0, &[17]);
        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::HopByHop);
        let _ = packet.payload(); // must not panic
    }

    #[test]
    fn ext_header_past_end_falls_back_without_panic() {
        // Hop-by-Hop claiming 64 bytes (hdr_ext_len=7) in an 8-byte payload.
        let frame = ipv6_packet(0, &[6, 7, 0, 0, 0, 0, 0, 0]);
        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::HopByHop);
        let _ = packet.payload(); // must not panic
    }

    #[test]
    fn ext_header_chain_at_the_bound_still_parses() {
        // Exactly MAX_IPV6_EXT_HEADERS chained Hop-by-Hop headers, then TCP.
        let mut payload = Vec::new();
        for _ in 0..(MAX_IPV6_EXT_HEADERS - 1) {
            payload.extend_from_slice(&[0, 0, 1, 4, 0, 0, 0, 0]);
        }
        payload.extend_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]);
        payload.extend_from_slice(&tcp_header(80, 8080));
        let frame = ipv6_packet(0, &payload);

        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::Tcp);
        let tcp = TcpPacket::new_checked(packet.payload()).unwrap();
        assert_eq!(tcp.src_port(), 80);
    }

    #[test]
    fn ext_header_chain_past_the_bound_is_ignored() {
        // One more Hop-by-Hop than the walk bound: classified as the
        // unskipped extension header, never as TCP.
        let mut payload = Vec::new();
        for _ in 0..MAX_IPV6_EXT_HEADERS {
            payload.extend_from_slice(&[0, 0, 1, 4, 0, 0, 0, 0]);
        }
        payload.extend_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]);
        payload.extend_from_slice(&tcp_header(80, 8080));
        let frame = ipv6_packet(0, &payload);

        let packet = IpPacket::new_checked(frame.as_slice()).unwrap();
        assert_eq!(packet.protocol(), IpProtocol::HopByHop);
        let _ = packet.payload(); // must not panic
    }
}
