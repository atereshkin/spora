//! Wire protocol for the TCP/TLS relay carrier.
//!
//! Unlike the UDP relay (which routes by peeking the QUIC DCID out of a
//! datagram), a TCP peer opens a connection to the relay and sends a fixed
//! preamble naming its role and routing key. The relay then either PARKS the
//! connection (a sharer offering itself) or SPLICES it to a parked sharer
//! connection (a client). Everything after the preamble is the end-to-end TLS
//! the relay blindly forwards — the relay holds no keys and reads no plaintext,
//! exactly like the UDP relay.
//!
//! The routing key rides in the preamble in cleartext — the relay must read it
//! to route, just as the UDP relay reads the DCID. (A camouflage-hardened
//! version would carry it inside the TLS ClientHello SNI, SNI-proxy style; the
//! preamble is the straightforward first cut.)

use crate::protocol::ROUTING_KEY_LEN;

/// Preamble magic: "spT1" (spora TCP v1). Lets the relay reject port scans /
/// garbage before doing anything.
pub const TCP_MAGIC: [u8; 4] = *b"spT1";

/// Connection roles, in the preamble's role byte.
pub mod role {
    /// A sharer parks a connection at its routing key; the relay holds it until
    /// a client arrives to be spliced.
    pub const REGISTER: u8 = 0x01;
    /// A client asks to be spliced to a sharer parked at the routing key.
    pub const CONNECT: u8 = 0x02;
}

/// Preamble layout: `magic(4) | role(1) | routing_key(20)`.
pub const PREAMBLE_LEN: usize = TCP_MAGIC.len() + 1 + ROUTING_KEY_LEN;

/// Build the fixed connection preamble.
pub fn build_preamble(role: u8, routing_key: &[u8; ROUTING_KEY_LEN]) -> [u8; PREAMBLE_LEN] {
    let mut p = [0u8; PREAMBLE_LEN];
    p[..TCP_MAGIC.len()].copy_from_slice(&TCP_MAGIC);
    p[TCP_MAGIC.len()] = role;
    p[TCP_MAGIC.len() + 1..].copy_from_slice(routing_key);
    p
}

/// Parse a preamble into `(role, routing_key)`, or `None` on wrong length/magic.
pub fn parse_preamble(buf: &[u8]) -> Option<(u8, [u8; ROUTING_KEY_LEN])> {
    if buf.len() < PREAMBLE_LEN || buf[..TCP_MAGIC.len()] != TCP_MAGIC {
        return None;
    }
    let mut rk = [0u8; ROUTING_KEY_LEN];
    rk.copy_from_slice(&buf[TCP_MAGIC.len() + 1..PREAMBLE_LEN]);
    Some((buf[TCP_MAGIC.len()], rk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_round_trips() {
        let rk = [0x9Au8; ROUTING_KEY_LEN];
        let p = build_preamble(role::REGISTER, &rk);
        assert_eq!(p.len(), PREAMBLE_LEN);
        assert_eq!(parse_preamble(&p), Some((role::REGISTER, rk)));

        let c = build_preamble(role::CONNECT, &rk);
        assert_eq!(parse_preamble(&c), Some((role::CONNECT, rk)));
    }

    #[test]
    fn rejects_bad_magic_and_short_buffers() {
        let rk = [0x01u8; ROUTING_KEY_LEN];
        let mut p = build_preamble(role::CONNECT, &rk);
        p[0] ^= 0xFF;
        assert_eq!(parse_preamble(&p), None, "bad magic must be rejected");
        assert_eq!(parse_preamble(&p[..PREAMBLE_LEN - 1]), None, "short buffer rejected");
    }
}
