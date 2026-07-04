//! Wire protocol for the TCP/TLS relay carrier.
//!
//! A TCP peer opens a connection to the relay and sends a fixed preamble naming
//! its role and routing key (plus, for a sharer, an optional capability token).
//! The relay then either PARKS the connection (a sharer offering itself) or
//! SPLICES it to a parked sharer connection (a client). Everything after the
//! preamble is the end-to-end TLS the relay blindly forwards — the relay holds
//! no keys and reads no plaintext, exactly like the UDP relay.
//!
//! Authorization: a sharer's REGISTER carries a capability token (see
//! `crate::authz`); the relay verifies it against its configured issuer keys
//! (open mode when it has none). Because the relay blind-splices, it cannot see
//! the E2E TLS handshake, so *key possession* is proven end-to-end (the pinned
//! server cert), not at the relay — the token here gates *authorization* (who
//! may use the relay), which is what a token is for.
//!
//! The routing key rides in the preamble in cleartext — the relay must read it
//! to route, just as the UDP relay reads the DCID. (A camouflage-hardened
//! version would carry it inside the TLS ClientHello SNI, SNI-proxy style.)

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

/// Fixed preamble header: `magic(4) | role(1) | routing_key(20) | token_len(2, BE)`.
/// A capability token of `token_len` bytes follows the header; `token_len == 0`
/// means no token (a CONNECT, or an open-mode REGISTER).
pub const PREAMBLE_HEADER_LEN: usize = TCP_MAGIC.len() + 1 + ROUTING_KEY_LEN + 2;

/// Largest capability token the relay will read after the header (a hard cap so
/// a malicious `token_len` can't make the relay buffer unboundedly).
pub const MAX_TOKEN_LEN: usize = 4096;

/// Build a connection preamble: the header followed by `token` (pass an empty
/// slice for a CONNECT or an open-mode REGISTER).
pub fn build_preamble(role: u8, routing_key: &[u8; ROUTING_KEY_LEN], token: &[u8]) -> Vec<u8> {
    debug_assert!(token.len() <= u16::MAX as usize, "token too large for u16 length");
    let mut p = Vec::with_capacity(PREAMBLE_HEADER_LEN + token.len());
    p.extend_from_slice(&TCP_MAGIC);
    p.push(role);
    p.extend_from_slice(routing_key);
    p.extend_from_slice(&(token.len() as u16).to_be_bytes());
    p.extend_from_slice(token);
    p
}

/// Parse the fixed header into `(role, routing_key, token_len)`, or `None` on
/// wrong length/magic. The caller then reads `token_len` more bytes (which it
/// must bound by [`MAX_TOKEN_LEN`]).
pub fn parse_header(buf: &[u8]) -> Option<(u8, [u8; ROUTING_KEY_LEN], usize)> {
    if buf.len() < PREAMBLE_HEADER_LEN || buf[..TCP_MAGIC.len()] != TCP_MAGIC {
        return None;
    }
    let role = buf[TCP_MAGIC.len()];
    let rk_start = TCP_MAGIC.len() + 1;
    let mut rk = [0u8; ROUTING_KEY_LEN];
    rk.copy_from_slice(&buf[rk_start..rk_start + ROUTING_KEY_LEN]);
    let token_len =
        u16::from_be_bytes([buf[PREAMBLE_HEADER_LEN - 2], buf[PREAMBLE_HEADER_LEN - 1]]) as usize;
    Some((role, rk, token_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_round_trips_with_and_without_token() {
        let rk = [0x9Au8; ROUTING_KEY_LEN];
        let token = vec![0xABu8; 40];
        let p = build_preamble(role::REGISTER, &rk, &token);
        let (role, got_rk, tlen) = parse_header(&p).expect("header parses");
        assert_eq!(role, role::REGISTER);
        assert_eq!(got_rk, rk);
        assert_eq!(tlen, token.len());
        assert_eq!(&p[PREAMBLE_HEADER_LEN..], &token[..], "token follows the header verbatim");

        let c = build_preamble(role::CONNECT, &rk, &[]);
        let (role, _, tlen) = parse_header(&c).expect("header parses");
        assert_eq!(role, role::CONNECT);
        assert_eq!(tlen, 0);
        assert_eq!(c.len(), PREAMBLE_HEADER_LEN, "no token => header only");
    }

    #[test]
    fn rejects_bad_magic_and_short_buffers() {
        let rk = [0x01u8; ROUTING_KEY_LEN];
        let mut p = build_preamble(role::CONNECT, &rk, &[]);
        p[0] ^= 0xFF;
        assert_eq!(parse_header(&p), None, "bad magic must be rejected");
        assert_eq!(parse_header(&p[..PREAMBLE_HEADER_LEN - 1]), None, "short buffer rejected");
    }
}
