//! Wire-protocol constants and parsing shared between the relay binary and
//! its clients. The new ("dumb forwarder") relay does not speak QUIC; it
//! routes UDP packets by inspecting the QUIC long-header DCID, and accepts a
//! small out-of-band control protocol from sharers who want to register a
//! routing key.

/// Magic prefix that distinguishes our control packets from QUIC. The first
/// byte (0x80) has the "fixed bit" (0x40) clear, so a QUIC parser treats it
/// as malformed and discards it; the next three bytes are an ASCII tag
/// (`spR`) for collision resistance against random data.
pub const CTRL_MAGIC: [u8; 4] = [0x80, b's', b'p', b'R'];

/// Control message types (the byte immediately after `CTRL_MAGIC`).
pub mod ctrl {
    /// Sharer (A) registers at a routing key. Body = 20-byte routing key.
    pub const REGISTER: u8 = 0x01;
}

/// Routing keys are 20 bytes so they fit in a QUIC v1 DCID (max 20 per RFC
/// 9000 §17.2). Mirrors `spora_core::identity::ROUTING_KEY_LEN`.
pub const ROUTING_KEY_LEN: usize = 20;

/// Build a `REGISTER` control packet for the given routing key.
pub fn build_register(routing_key: &[u8; ROUTING_KEY_LEN]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(CTRL_MAGIC.len() + 1 + ROUTING_KEY_LEN);
    pkt.extend_from_slice(&CTRL_MAGIC);
    pkt.push(ctrl::REGISTER);
    pkt.extend_from_slice(routing_key);
    pkt
}

/// Classify an inbound UDP packet for the relay's dispatcher.
#[derive(Debug, PartialEq, Eq)]
pub enum Classified<'a> {
    /// Our control protocol: type byte + body.
    Control { ty: u8, body: &'a [u8] },
    /// A QUIC long-header packet, e.g. Initial. DCID is parseable in cleartext.
    QuicLongHeader { dcid: &'a [u8] },
    /// A QUIC short-header (1-RTT) packet. DCID length isn't on the wire — we
    /// can't extract it without per-connection state, so the relay routes
    /// these by 5-tuple instead.
    QuicShortHeader,
    /// Unrecognized: not our control magic, not a valid QUIC packet shape.
    Unknown,
}

/// Classify a packet by its first byte (and following fields, for long
/// headers). Cheap; no allocations.
pub fn classify(pkt: &[u8]) -> Classified<'_> {
    if pkt.len() > CTRL_MAGIC.len() && pkt[..CTRL_MAGIC.len()] == CTRL_MAGIC {
        return Classified::Control {
            ty: pkt[CTRL_MAGIC.len()],
            body: &pkt[CTRL_MAGIC.len() + 1..],
        };
    }
    if pkt.is_empty() {
        return Classified::Unknown;
    }
    let b0 = pkt[0];
    // QUIC long header: header-form bit (0x80) + fixed bit (0x40) both set.
    if (b0 & 0xC0) == 0xC0 {
        // Layout: type(1) + version(4) + dcid_len(1) + dcid_bytes
        if pkt.len() < 6 {
            return Classified::Unknown;
        }
        let dcid_len = pkt[5] as usize;
        if pkt.len() < 6 + dcid_len {
            return Classified::Unknown;
        }
        return Classified::QuicLongHeader {
            dcid: &pkt[6..6 + dcid_len],
        };
    }
    // QUIC short header: header-form clear, fixed bit set (0x40..=0x7F).
    if (b0 & 0xC0) == 0x40 {
        return Classified::QuicShortHeader;
    }
    Classified::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_roundtrip() {
        let rk: [u8; ROUTING_KEY_LEN] = std::array::from_fn(|i| i as u8);
        let pkt = build_register(&rk);
        match classify(&pkt) {
            Classified::Control { ty, body } => {
                assert_eq!(ty, ctrl::REGISTER);
                assert_eq!(body, &rk[..]);
            }
            other => panic!("expected Control, got {:?}", other),
        }
    }

    #[test]
    fn classifies_long_header() {
        // Initial packet shape: 0xC0, version(4 bytes), dcid_len, dcid_bytes...
        let dcid = [0xAAu8; 20];
        let mut pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 20];
        pkt.extend_from_slice(&dcid);
        pkt.extend_from_slice(&[0xDE, 0xAD]); // trailing payload
        match classify(&pkt) {
            Classified::QuicLongHeader { dcid: got } => assert_eq!(got, &dcid[..]),
            other => panic!("expected QuicLongHeader, got {:?}", other),
        }
    }

    #[test]
    fn classifies_short_header() {
        let pkt = vec![0x40, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(classify(&pkt), Classified::QuicShortHeader);
    }

    #[test]
    fn rejects_truncated_long_header() {
        let pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 20, 0xAA, 0xBB]; // dcid_len=20 but only 2 bytes follow
        assert_eq!(classify(&pkt), Classified::Unknown);
    }

    #[test]
    fn ctrl_magic_first_byte_is_not_valid_quic() {
        // Sanity: 0x80 has the fixed bit clear, so QUIC parsers reject it.
        assert_eq!(CTRL_MAGIC[0] & 0x40, 0);
    }

    #[test]
    fn empty_packet_is_unknown() {
        assert_eq!(classify(&[]), Classified::Unknown);
    }

    #[test]
    fn random_byte_zero_is_unknown() {
        // Bytes 0x00..=0x3F have neither header form nor fixed bit set.
        assert_eq!(classify(&[0x00, 0x01, 0x02]), Classified::Unknown);
    }
}
