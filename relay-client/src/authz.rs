//! Capability-token authorization for relay registration.
//!
//! Authentication (proving possession of the identity key) is handled by the
//! signed REGISTER in [`crate::protocol`]. *Authorization* — whether a given
//! routing key is allowed to use a relay at all — is expressed by a
//! **capability token**: a compact blob signed by an *issuer* (Ed25519) that
//! binds an `allowed` grant to a specific routing key (the token's *subject*).
//!
//! The relay is configured with one or more trusted issuer public keys. If it
//! has none, it runs in **open mode** (any validly self-signed registration is
//! accepted — today's behavior). If it has issuer keys, a registration must
//! carry a token that (a) is signed by a trusted issuer, (b) is marked
//! allowed, and (c) has `subject == the routing key being registered`.
//!
//! The binding to the routing key is what makes the token non-transferable: the
//! existing REGISTER signature already proves the registrant holds that key, so
//! a stolen or shared token is useless to anyone who does not also hold the
//! matching private key. The token says "key K is allowed"; the registration
//! signature proves "I am K". Neither alone authorizes; together they do.
//!
//! The format is deliberately minimal ("allowed" flag only). It is versioned so
//! future fields (expiry, quota tier) can be added without ambiguity.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::protocol::ROUTING_KEY_LEN;

/// Length of an Ed25519 issuer public key.
pub const ISSUER_PUBKEY_LEN: usize = 32;
/// The token's subject is a routing key.
pub const SUBJECT_LEN: usize = ROUTING_KEY_LEN;

const CAP_VERSION: u8 = 1;
/// `flags` bit 0: the subject is allowed to use the relay.
const FLAG_ALLOWED: u8 = 0x01;
const SIG_LEN: usize = 64;
/// `version(1) | flags(1) | subject(20) | issuer_sig(64)`.
const TOKEN_LEN: usize = 1 + 1 + SUBJECT_LEN + SIG_LEN;

/// Domain-separation prefix for the issuer signature: binds a signature to this
/// use (a capability grant) and this version, so it can never be confused with
/// any other signature the issuer key might make.
const CAP_SIG_DOMAIN: &[u8] = b"spora-relay-cap-v1";

/// The exact bytes an issuer signs (and the relay verifies) for a capability:
/// `domain || version || flags || subject`.
fn signing_input(version: u8, flags: u8, subject: &[u8; SUBJECT_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CAP_SIG_DOMAIN.len() + 2 + SUBJECT_LEN);
    v.extend_from_slice(CAP_SIG_DOMAIN);
    v.push(version);
    v.push(flags);
    v.extend_from_slice(subject);
    v
}

/// An issuer's Ed25519 key pair. The *operator* holds this (the relay only ever
/// holds the public half). For a self-hosted relay the operator and the issuer
/// are the same person, so issuing a token is a local signing operation — no
/// online service required.
pub struct IssuerKeyPair {
    kp: Ed25519KeyPair,
    pkcs8: Vec<u8>,
    public: [u8; ISSUER_PUBKEY_LEN],
}

impl IssuerKeyPair {
    /// Generate a fresh issuer key pair.
    pub fn generate() -> Result<Self, String> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "issuer: key generation failed".to_string())?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// Restore an issuer key pair from its PKCS#8 bytes.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, String> {
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|e| format!("issuer: invalid PKCS#8 key: {e}"))?;
        let mut public = [0u8; ISSUER_PUBKEY_LEN];
        let pk = kp.public_key().as_ref();
        if pk.len() != ISSUER_PUBKEY_LEN {
            return Err(format!("issuer: unexpected public key length {}", pk.len()));
        }
        public.copy_from_slice(pk);
        Ok(Self {
            kp,
            pkcs8: pkcs8.to_vec(),
            public,
        })
    }

    /// The PKCS#8 bytes, for persisting the issuer secret.
    pub fn pkcs8_bytes(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The issuer public key, for configuring on the relay.
    pub fn public_key(&self) -> [u8; ISSUER_PUBKEY_LEN] {
        self.public
    }

    /// Mint an "allowed" capability token for `subject` (a routing key).
    pub fn issue(&self, subject: &[u8; SUBJECT_LEN]) -> Vec<u8> {
        let flags = FLAG_ALLOWED;
        let input = signing_input(CAP_VERSION, flags, subject);
        let sig = self.kp.sign(&input);
        let mut token = Vec::with_capacity(TOKEN_LEN);
        token.push(CAP_VERSION);
        token.push(flags);
        token.extend_from_slice(subject);
        token.extend_from_slice(sig.as_ref());
        token
    }
}

/// Why a capability token was rejected. Carries no secret-dependent info.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    /// Wrong length or otherwise unparsable.
    Malformed,
    /// Unsupported token version.
    WrongVersion,
    /// The `allowed` flag is not set.
    NotAllowed,
    /// The token authorizes a different routing key than the one registering.
    WrongSubject,
    /// No configured issuer's key produced this signature.
    BadSignature,
}

/// Verify a capability token authorizes `subject` (the routing key being
/// registered) under one of the trusted `issuers`. Returns `Ok(())` only if the
/// token is well-formed, marked allowed, bound to exactly this subject, and
/// signed by a trusted issuer.
pub fn verify_token(
    token: &[u8],
    subject: &[u8; SUBJECT_LEN],
    issuers: &[[u8; ISSUER_PUBKEY_LEN]],
) -> Result<(), TokenError> {
    if token.len() != TOKEN_LEN {
        return Err(TokenError::Malformed);
    }
    let version = token[0];
    if version != CAP_VERSION {
        return Err(TokenError::WrongVersion);
    }
    let flags = token[1];
    if flags & FLAG_ALLOWED == 0 {
        return Err(TokenError::NotAllowed);
    }
    let tok_subject = &token[2..2 + SUBJECT_LEN];
    if tok_subject != subject {
        return Err(TokenError::WrongSubject);
    }
    let sig = &token[2 + SUBJECT_LEN..];
    let input = signing_input(version, flags, subject);
    for issuer in issuers {
        let pk = UnparsedPublicKey::new(&signature::ED25519, issuer);
        if pk.verify(&input, sig).is_ok() {
            return Ok(());
        }
    }
    Err(TokenError::BadSignature)
}

// ---------- string encodings (for CLIs / config) ----------

/// base64url (no padding), the encoding used for tokens and issuer keys at rest.
pub fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a base64url (no padding) blob.
pub fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| format!("invalid base64: {e}"))
}

/// Decode a base64url issuer public key into a fixed array.
pub fn decode_pubkey(s: &str) -> Result<[u8; ISSUER_PUBKEY_LEN], String> {
    let bytes = decode_b64(s)?;
    if bytes.len() != ISSUER_PUBKEY_LEN {
        return Err(format!(
            "issuer public key must be {ISSUER_PUBKEY_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut pk = [0u8; ISSUER_PUBKEY_LEN];
    pk.copy_from_slice(&bytes);
    Ok(pk)
}

/// Lowercase hex encoding (used for routing keys, matching the session log).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode a lowercase/uppercase hex string.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("hex string has an odd number of digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex: {e}")))
        .collect()
}

/// Decode a hex routing key into a fixed array.
pub fn decode_routing_key(s: &str) -> Result<[u8; SUBJECT_LEN], String> {
    let bytes = hex_decode(s)?;
    if bytes.len() != SUBJECT_LEN {
        return Err(format!(
            "routing key must be {SUBJECT_LEN} bytes ({} hex digits), got {}",
            SUBJECT_LEN * 2,
            bytes.len()
        ));
    }
    let mut rk = [0u8; SUBJECT_LEN];
    rk.copy_from_slice(&bytes);
    Ok(rk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rk(seed: u8) -> [u8; SUBJECT_LEN] {
        [seed; SUBJECT_LEN]
    }

    #[test]
    fn issued_token_verifies_for_its_subject() {
        let issuer = IssuerKeyPair::generate().unwrap();
        let subject = rk(0xAB);
        let token = issuer.issue(&subject);
        assert_eq!(token.len(), TOKEN_LEN);
        assert_eq!(
            verify_token(&token, &subject, &[issuer.public_key()]),
            Ok(())
        );
    }

    #[test]
    fn token_rejected_for_a_different_subject() {
        let issuer = IssuerKeyPair::generate().unwrap();
        let token = issuer.issue(&rk(0x01));
        assert_eq!(
            verify_token(&token, &rk(0x02), &[issuer.public_key()]),
            Err(TokenError::WrongSubject)
        );
    }

    #[test]
    fn token_rejected_under_a_different_issuer() {
        let issuer = IssuerKeyPair::generate().unwrap();
        let other = IssuerKeyPair::generate().unwrap();
        let subject = rk(0x07);
        let token = issuer.issue(&subject);
        assert_eq!(
            verify_token(&token, &subject, &[other.public_key()]),
            Err(TokenError::BadSignature)
        );
        // ...but accepted when the correct issuer is among the trusted set.
        assert_eq!(
            verify_token(&token, &subject, &[other.public_key(), issuer.public_key()]),
            Ok(())
        );
    }

    #[test]
    fn tampered_token_fails_signature() {
        let issuer = IssuerKeyPair::generate().unwrap();
        let subject = rk(0x33);
        let mut token = issuer.issue(&subject);
        // Flip a signature bit.
        let last = token.len() - 1;
        token[last] ^= 0x01;
        assert_eq!(
            verify_token(&token, &subject, &[issuer.public_key()]),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn cleared_allowed_flag_is_rejected() {
        let issuer = IssuerKeyPair::generate().unwrap();
        let subject = rk(0x44);
        let mut token = issuer.issue(&subject);
        token[1] = 0x00; // clear FLAG_ALLOWED
        assert_eq!(
            verify_token(&token, &subject, &[issuer.public_key()]),
            Err(TokenError::NotAllowed)
        );
    }

    #[test]
    fn wrong_length_and_version_are_malformed() {
        let issuer = IssuerKeyPair::generate().unwrap();
        let subject = rk(0x55);
        let token = issuer.issue(&subject);
        assert_eq!(
            verify_token(&token[..TOKEN_LEN - 1], &subject, &[issuer.public_key()]),
            Err(TokenError::Malformed)
        );
        let mut bad_version = token.clone();
        bad_version[0] = 2;
        assert_eq!(
            verify_token(&bad_version, &subject, &[issuer.public_key()]),
            Err(TokenError::WrongVersion)
        );
    }

    #[test]
    fn issuer_key_pair_round_trips_via_pkcs8() {
        let issuer = IssuerKeyPair::generate().unwrap();
        let restored = IssuerKeyPair::from_pkcs8(issuer.pkcs8_bytes()).unwrap();
        assert_eq!(issuer.public_key(), restored.public_key());
        // A token from the restored key verifies under the original's pubkey.
        let subject = rk(0x66);
        let token = restored.issue(&subject);
        assert_eq!(verify_token(&token, &subject, &[issuer.public_key()]), Ok(()));
    }

    #[test]
    fn pubkey_and_routing_key_string_round_trips() {
        let issuer = IssuerKeyPair::generate().unwrap();
        let pk = issuer.public_key();
        assert_eq!(decode_pubkey(&encode_b64(&pk)).unwrap(), pk);

        let subject = rk(0x9E);
        assert_eq!(decode_routing_key(&hex_encode(&subject)).unwrap(), subject);
        assert!(decode_routing_key("abcd").is_err(), "too short must error");
    }
}
