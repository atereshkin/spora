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
    /// Sharer (A) registers at a routing key. Body is a *signed* registration
    /// (see [`super::build_signed_register`]); the relay verifies it before
    /// binding the key, so an on-path observer who learns the (public) routing
    /// key cannot rebind it.
    pub const REGISTER: u8 = 0x01;
}

/// Routing keys are 20 bytes so they fit in a QUIC v1 DCID (max 20 per RFC
/// 9000 §17.2). Mirrors `spora_core::identity::ROUTING_KEY_LEN`.
pub const ROUTING_KEY_LEN: usize = 20;

/// Width of the registration timestamp (milliseconds since the Unix epoch).
const REGISTER_TIMESTAMP_LEN: usize = 8;

/// Domain-separation prefix for the registration signature. Binds a signature
/// to *this* use (relay registration) and protocol version so it can never be
/// confused with any other signature the sharer's key might produce.
const REGISTER_SIG_DOMAIN: &[u8] = b"spora-relay-register-v1";

/// The exact bytes a sharer signs (and the relay verifies) for a registration:
/// `domain || routing_key || timestamp`. The routing key is bound in, so a
/// signature for one key cannot be replayed against another; the timestamp is
/// bound in so the relay can reject replays by requiring it to increase.
pub fn register_signing_input(
    routing_key: &[u8; ROUTING_KEY_LEN],
    timestamp_millis: u64,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(REGISTER_SIG_DOMAIN.len() + ROUTING_KEY_LEN + REGISTER_TIMESTAMP_LEN);
    v.extend_from_slice(REGISTER_SIG_DOMAIN);
    v.extend_from_slice(routing_key);
    v.extend_from_slice(&timestamp_millis.to_be_bytes());
    v
}

/// Assemble a signed `REGISTER` control packet. Body layout:
/// `routing_key(20) | timestamp(8, BE) | cert_len(2, BE) | cert_der | sig_len(2, BE) | signature | token`.
/// `signature` is an ECDSA-P256-SHA256 (ASN.1 DER) signature over
/// [`register_signing_input`], made with the key whose self-signed cert is
/// `cert_der`. The relay checks `SHA-256(cert_der)[..20] == routing_key`, so
/// the cert (and thus the verifying key) is pinned by the routing key itself.
///
/// `token` is an optional trailing capability token (see [`crate::authz`]);
/// pass an empty slice for an open-mode (unauthorized) registration. It is
/// length-delimited only by riding at the end of the control packet, so the
/// signature is now explicitly length-prefixed to separate the two.
pub fn build_signed_register(
    routing_key: &[u8; ROUTING_KEY_LEN],
    timestamp_millis: u64,
    cert_der: &[u8],
    signature: &[u8],
    token: &[u8],
) -> Vec<u8> {
    debug_assert!(cert_der.len() <= u16::MAX as usize, "cert too large for u16 length");
    debug_assert!(signature.len() <= u16::MAX as usize, "signature too large for u16 length");
    let mut pkt = Vec::with_capacity(
        CTRL_MAGIC.len()
            + 1
            + ROUTING_KEY_LEN
            + REGISTER_TIMESTAMP_LEN
            + 2
            + cert_der.len()
            + 2
            + signature.len()
            + token.len(),
    );
    pkt.extend_from_slice(&CTRL_MAGIC);
    pkt.push(ctrl::REGISTER);
    pkt.extend_from_slice(routing_key);
    pkt.extend_from_slice(&timestamp_millis.to_be_bytes());
    pkt.extend_from_slice(&(cert_der.len() as u16).to_be_bytes());
    pkt.extend_from_slice(cert_der);
    pkt.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    pkt.extend_from_slice(signature);
    pkt.extend_from_slice(token);
    pkt
}

/// A parsed-but-not-yet-verified signed registration, borrowed from the packet.
struct ParsedRegister<'a> {
    routing_key: [u8; ROUTING_KEY_LEN],
    timestamp_millis: u64,
    cert_der: &'a [u8],
    signature: &'a [u8],
    /// Trailing capability token; empty for an open-mode registration.
    token: &'a [u8],
}

fn parse_signed_register(body: &[u8]) -> Option<ParsedRegister<'_>> {
    const HEAD: usize = ROUTING_KEY_LEN + REGISTER_TIMESTAMP_LEN + 2;
    if body.len() < HEAD {
        return None;
    }
    let mut rk = [0u8; ROUTING_KEY_LEN];
    rk.copy_from_slice(&body[..ROUTING_KEY_LEN]);
    let ts = u64::from_be_bytes(
        body[ROUTING_KEY_LEN..ROUTING_KEY_LEN + REGISTER_TIMESTAMP_LEN]
            .try_into()
            .unwrap(),
    );
    let cert_len =
        u16::from_be_bytes(body[ROUTING_KEY_LEN + REGISTER_TIMESTAMP_LEN..HEAD].try_into().unwrap())
            as usize;
    let cert_end = HEAD.checked_add(cert_len)?;
    // Read the 2-byte signature length that follows the cert.
    let sig_len_end = cert_end.checked_add(2)?;
    if body.len() < sig_len_end {
        return None;
    }
    let sig_len = u16::from_be_bytes(body[cert_end..sig_len_end].try_into().unwrap()) as usize;
    if sig_len == 0 {
        return None; // signature must be present
    }
    let sig_end = sig_len_end.checked_add(sig_len)?;
    if body.len() < sig_end {
        return None;
    }
    Some(ParsedRegister {
        routing_key: rk,
        timestamp_millis: ts,
        cert_der: &body[HEAD..cert_end],
        signature: &body[sig_len_end..sig_end],
        token: &body[sig_end..], // possibly empty
    })
}

/// Why a signed registration was rejected. The relay logs this; it carries no
/// secret-dependent information.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterVerifyError {
    /// Body did not parse as a signed registration.
    Malformed,
    /// `SHA-256(cert)[..20]` did not equal the claimed routing key.
    RoutingKeyMismatch,
    /// The certificate could not be parsed as an end-entity cert.
    BadCert,
    /// The signature did not verify against the cert's public key.
    BadSignature,
}

/// Verify a signed `REGISTER` body and return the `(routing_key, timestamp,
/// token)` it authorizes. The `token` slice (borrowed from `body`, possibly
/// empty) is the trailing capability token; the relay passes it to
/// [`crate::authz::verify_token`] when it is running in authorized mode. The
/// caller still enforces freshness (timestamp must exceed the last accepted one
/// for the key), authorization, and source policy. Holding no secret, the relay
/// can only *verify*: it confirms the routing key commits to the presented cert
/// and that the cert's key signed this exact registration.
pub fn verify_signed_register(
    body: &[u8],
) -> Result<([u8; ROUTING_KEY_LEN], u64, &[u8]), RegisterVerifyError> {
    let parsed = parse_signed_register(body).ok_or(RegisterVerifyError::Malformed)?;

    // The routing key must be the SHA-256 of the cert (truncated to 20 bytes) —
    // the same derivation the client pins on. This binds the verifying key to
    // the routing key, so an attacker cannot substitute their own cert.
    let digest = ring::digest::digest(&ring::digest::SHA256, parsed.cert_der);
    if digest.as_ref()[..ROUTING_KEY_LEN] != parsed.routing_key {
        return Err(RegisterVerifyError::RoutingKeyMismatch);
    }

    let cert = rustls_pki_types::CertificateDer::from(parsed.cert_der);
    let eec = webpki::EndEntityCert::try_from(&cert).map_err(|_| RegisterVerifyError::BadCert)?;
    let input = register_signing_input(&parsed.routing_key, parsed.timestamp_millis);
    eec.verify_signature(webpki::ring::ECDSA_P256_SHA256, &input, parsed.signature)
        .map_err(|_| RegisterVerifyError::BadSignature)?;

    Ok((parsed.routing_key, parsed.timestamp_millis, parsed.token))
}

/// Signs the sharer's periodic registrations with the identity's certificate
/// key. Holds the parsed key pair so each tick is a cheap sign, and guarantees
/// a strictly-increasing timestamp across this process's lifetime (so the
/// relay's replay guard never rejects our own refreshes even if the wall clock
/// stalls or steps backward).
pub struct RegisterSigner {
    key_pair: ring::signature::EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    cert_der: Vec<u8>,
    routing_key: [u8; ROUTING_KEY_LEN],
    last_ts: u64,
    /// Trailing capability token attached to every registration; empty means an
    /// open-mode (unauthorized) registration, which a relay running without
    /// issuer keys still accepts. See [`crate::authz`].
    token: Vec<u8>,
}

impl RegisterSigner {
    /// Build a signer from a self-signed cert DER and its PKCS#8 private key
    /// (exactly the `cert_der_bytes` / `key_der_bytes` an `Identity` holds).
    pub fn new(cert_der: &[u8], key_pkcs8_der: &[u8]) -> Result<Self, String> {
        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            key_pkcs8_der,
            &rng,
        )
        .map_err(|e| format!("register signer: rejected key: {}", e))?;
        let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
        let mut routing_key = [0u8; ROUTING_KEY_LEN];
        routing_key.copy_from_slice(&digest.as_ref()[..ROUTING_KEY_LEN]);
        Ok(Self {
            key_pair,
            rng,
            cert_der: cert_der.to_vec(),
            routing_key,
            last_ts: 0,
            token: Vec::new(),
        })
    }

    /// Attach a capability token to every registration this signer produces
    /// (see [`crate::authz`]). `None` (or an empty token) keeps registrations in
    /// open mode. Builder-style so callers can write
    /// `RegisterSigner::new(..)?.with_token(cfg.relay_token)`.
    pub fn with_token(mut self, token: Option<Vec<u8>>) -> Self {
        self.token = token.unwrap_or_default();
        self
    }

    /// The routing key this signer registers (derived from the cert).
    pub fn routing_key(&self) -> [u8; ROUTING_KEY_LEN] {
        self.routing_key
    }

    /// Produce the next signed REGISTER packet, with a fresh strictly-increasing
    /// timestamp.
    pub fn next_register_packet(&mut self) -> Vec<u8> {
        let ts = now_millis().max(self.last_ts + 1);
        self.last_ts = ts;
        let input = register_signing_input(&self.routing_key, ts);
        let sig = self
            .key_pair
            .sign(&self.rng, &input)
            .expect("ECDSA signing of a fixed-size input does not fail");
        build_signed_register(&self.routing_key, ts, &self.cert_der, sig.as_ref(), &self.token)
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

    /// A self-signed ECDSA-P256 cert + PKCS#8 key, like an `Identity` carries.
    fn test_cert() -> (Vec<u8>, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        (ck.cert.der().to_vec(), ck.key_pair.serialize_der())
    }

    #[test]
    fn signed_register_classifies_as_control() {
        let (cert, key) = test_cert();
        let mut signer = RegisterSigner::new(&cert, &key).unwrap();
        let pkt = signer.next_register_packet();
        match classify(&pkt) {
            Classified::Control { ty, body } => {
                assert_eq!(ty, ctrl::REGISTER);
                let (rk, _ts, token) = verify_signed_register(body).expect("verifies");
                assert_eq!(rk, signer.routing_key());
                assert!(token.is_empty(), "a plain signer registers open-mode (no token)");
            }
            other => panic!("expected Control, got {:?}", other),
        }
    }

    #[test]
    fn signed_register_round_trip_and_timestamp_increases() {
        let (cert, key) = test_cert();
        let mut signer = RegisterSigner::new(&cert, &key).unwrap();
        let body = |pkt: &[u8]| pkt[CTRL_MAGIC.len() + 1..].to_vec();

        let p1 = signer.next_register_packet();
        let p2 = signer.next_register_packet();
        let (rk1, ts1, _) = verify_signed_register(&body(&p1)).unwrap();
        let (rk2, ts2, _) = verify_signed_register(&body(&p2)).unwrap();
        assert_eq!(rk1, signer.routing_key());
        assert_eq!(rk2, signer.routing_key());
        assert!(ts2 > ts1, "timestamps must strictly increase ({ts1} -> {ts2})");
    }

    #[test]
    fn signed_register_carries_and_surfaces_its_token() {
        let (cert, key) = test_cert();
        let token = vec![0xAB; 40];
        let mut signer = RegisterSigner::new(&cert, &key)
            .unwrap()
            .with_token(Some(token.clone()));
        let pkt = signer.next_register_packet();
        let body = &pkt[CTRL_MAGIC.len() + 1..];
        let (rk, _ts, got) = verify_signed_register(body).expect("verifies");
        assert_eq!(rk, signer.routing_key());
        assert_eq!(got, &token[..], "the exact token must round-trip after the signature");
    }

    #[test]
    fn tampered_signed_register_is_rejected() {
        let (cert, key) = test_cert();
        let mut signer = RegisterSigner::new(&cert, &key).unwrap();
        let pkt = signer.next_register_packet();
        let mut body = pkt[CTRL_MAGIC.len() + 1..].to_vec();
        assert!(verify_signed_register(&body).is_ok());

        // Flip a timestamp byte: signature no longer covers the body.
        body[ROUTING_KEY_LEN] ^= 0x01;
        assert_eq!(
            verify_signed_register(&body),
            Err(RegisterVerifyError::BadSignature)
        );
    }

    #[test]
    fn signed_register_with_mismatched_routing_key_is_rejected() {
        // A valid cert+signature, but the routing-key field doesn't commit to
        // the cert — the relay must refuse to bind it.
        let (cert, key) = test_cert();
        let mut signer = RegisterSigner::new(&cert, &key).unwrap();
        let mut body = signer.next_register_packet()[CTRL_MAGIC.len() + 1..].to_vec();
        body[0] ^= 0xFF; // corrupt the routing key only
        assert_eq!(
            verify_signed_register(&body),
            Err(RegisterVerifyError::RoutingKeyMismatch)
        );
    }

    #[test]
    fn truncated_signed_register_is_malformed() {
        let (cert, key) = test_cert();
        let mut signer = RegisterSigner::new(&cert, &key).unwrap();
        let body = signer.next_register_packet()[CTRL_MAGIC.len() + 1..].to_vec();
        assert_eq!(
            verify_signed_register(&body[..ROUTING_KEY_LEN]),
            Err(RegisterVerifyError::Malformed)
        );
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
