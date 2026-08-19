//! End-to-end Noise handshake for the `nz` (Noise UDP) carrier.
//!
//! This is the crypto core: a `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` handshake
//! plus the identity binding that keeps one 20-byte `routing_key` pin
//! authenticating the sharer across QUIC, TLS *and* Noise — without migrating
//! `Identity` to an X25519 static key.
//!
//! Two factors, exactly mirroring the QUIC/TLS carriers:
//!
//! - **Authorization (the secret):** the PSK is mixed at `psk0` (before the
//!   first ephemeral), so the initiator's first message carries an AEAD tag that
//!   only a holder of the off-wire `secret` can produce. A responder drops a
//!   wrong-secret first message before doing any DH — a cheap probe/DoS filter
//!   and the passive-DPI-resistance property in one, with no `routing_key`-keyed
//!   MAC that a passive censor could recompute.
//! - **Identity (the cert pin):** after the handshake completes, the responder
//!   (the sharer, A) sends a cert-auth message — its self-signed ECDSA cert plus
//!   a signature over the Noise channel-binding hash — as the first transport
//!   message. The initiator (B) checks `SHA-256(cert)[..20] == routing_key` and
//!   verifies the signature. Signing the channel-binding hash binds A's identity
//!   to *this* session's ephemerals, so the signature cannot be replayed into
//!   another session. A URL/secret holder still cannot impersonate A.
//!
//! The wire framing (relay-routing prefix, session indices, counter header
//! protection, padding) lives in [`crate::transport::noise`]; this module is
//! pure crypto over byte buffers so it can be exhaustively unit-tested.

// The data plane (transport::noise) and carrier that consume these land in the
// next commits; until then only the module's own tests exercise them.
#![allow(dead_code)]

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use rustls::pki_types::CertificateDer;

use crate::identity::{Identity, ROUTING_KEY_LEN, SECRET_LEN};
use crate::record::{Fault, Reason};

/// The Noise pattern. `NN` (no static keys) + `psk0` (secret mixed first). A's
/// identity rides in a cert-auth message rather than a Noise static key.
const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
/// Domain separation for the PSK derivation.
const PSK_DOMAIN: &[u8] = b"spora-noise-psk-v1";
/// Prologue prefix; the full prologue is `PROLOGUE_PREFIX || routing_key`, so
/// the routing key (identity + version framing) is authenticated by the
/// handshake even though it also rides in the clear for relay routing.
const PROLOGUE_PREFIX: &[u8] = b"spora-noise-v1";
/// Domain separation for the cert-auth signature over the channel-binding hash.
const AUTH_SIG_DOMAIN: &[u8] = b"spora-noise-auth-v1";

/// Largest handshake message we ever write (NNpsk0 messages are 48 bytes:
/// 32-byte ephemeral + 16-byte tag). Generous headroom.
pub(crate) const NOISE_HS_MAX: usize = 128;

/// PSK = SHA-256(domain || routing_key || secret). Both peers derive it: B from
/// the URL's `routing_key`/`secret`, A from its own `Identity`.
pub(crate) fn derive_psk(
    routing_key: &[u8; ROUTING_KEY_LEN],
    secret: &[u8; SECRET_LEN],
) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(PSK_DOMAIN);
    ctx.update(routing_key);
    ctx.update(secret);
    let mut psk = [0u8; 32];
    psk.copy_from_slice(ctx.finish().as_ref());
    psk
}

fn prologue(routing_key: &[u8; ROUTING_KEY_LEN]) -> Vec<u8> {
    let mut p = Vec::with_capacity(PROLOGUE_PREFIX.len() + ROUTING_KEY_LEN);
    p.extend_from_slice(PROLOGUE_PREFIX);
    p.extend_from_slice(routing_key);
    p
}

/// A Noise handshake in progress. Thin wrapper over `snow` that fixes the
/// pattern, PSK and prologue, and maps errors to the crate's `String` convention.
pub(crate) struct NoiseHandshake {
    hs: snow::HandshakeState,
}

impl NoiseHandshake {
    fn build(
        routing_key: &[u8; ROUTING_KEY_LEN],
        secret: &[u8; SECRET_LEN],
        initiator: bool,
    ) -> Result<Self, Fault> {
        let psk = derive_psk(routing_key, secret);
        let prologue = prologue(routing_key);
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| Fault::new(Reason::CryptoError, format!("noise params: {e}")))?;
        let builder = snow::Builder::new(params)
            .prologue(&prologue)
            .map_err(|e| Fault::new(Reason::CryptoError, format!("noise prologue: {e}")))?
            .psk(0, &psk)
            .map_err(|e| Fault::new(Reason::CryptoError, format!("noise psk: {e}")))?;
        let hs = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|e| Fault::new(Reason::CryptoError, format!("noise handshake build: {e}")))?;
        Ok(Self { hs })
    }

    /// B side: dials the sharer.
    pub(crate) fn initiator(
        routing_key: &[u8; ROUTING_KEY_LEN],
        secret: &[u8; SECRET_LEN],
    ) -> Result<Self, Fault> {
        Self::build(routing_key, secret, true)
    }

    /// A side: derives the PSK from its own identity.
    pub(crate) fn responder(identity: &Identity) -> Result<Self, Fault> {
        Self::build(&identity.routing_key, &identity.secret, false)
    }

    /// Write the next handshake message; returns the bytes to send.
    pub(crate) fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Fault> {
        let mut out = vec![0u8; NOISE_HS_MAX + payload.len()];
        let n = self
            .hs
            .write_message(payload, &mut out)
            .map_err(|e| Fault::new(Reason::CryptoError, format!("noise write: {e}")))?;
        out.truncate(n);
        Ok(out)
    }

    /// Read the next handshake message; returns the decrypted payload (empty for
    /// our handshake messages). A wrong PSK makes this fail on the first message.
    pub(crate) fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, Fault> {
        let mut out = vec![0u8; msg.len().max(NOISE_HS_MAX)];
        let n = self
            .hs
            .read_message(msg, &mut out)
            .map_err(|e| Fault::new(Reason::CryptoError, format!("noise read: {e}")))?;
        out.truncate(n);
        Ok(out)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.hs.is_handshake_finished()
    }

    /// Consume the completed handshake into a stateless transport session (the
    /// data plane supplies an explicit per-packet counter as the nonce).
    pub(crate) fn into_session(self) -> Result<NoiseSession, Fault> {
        let mut handshake_hash = [0u8; 32];
        handshake_hash.copy_from_slice(&self.hs.get_handshake_hash()[..32]);
        let transport = self
            .hs
            .into_stateless_transport_mode()
            .map_err(|e| Fault::new(Reason::CryptoError, format!("noise transport mode: {e}")))?;
        Ok(NoiseSession {
            transport,
            handshake_hash,
        })
    }
}

/// An established end-to-end Noise session. AEAD with an external per-packet
/// counter as the nonce (RFC 6479 replay handling lives in the data plane).
pub(crate) struct NoiseSession {
    transport: snow::StatelessTransportState,
    /// Noise channel-binding hash — signed by A, checked by B, and available to
    /// both for any further binding.
    pub(crate) handshake_hash: [u8; 32],
}

/// AEAD tag length (ChaChaPoly).
pub(crate) const NOISE_TAG_LEN: usize = 16;

impl NoiseSession {
    /// Encrypt `plaintext` under `counter`; returns ciphertext (plaintext + 16).
    pub(crate) fn encrypt(&self, counter: u64, plaintext: &[u8]) -> Result<Vec<u8>, Fault> {
        let mut out = vec![0u8; plaintext.len() + NOISE_TAG_LEN];
        let n = self
            .transport
            .write_message(counter, plaintext, &mut out)
            .map_err(|e| Fault::new(Reason::CryptoError, format!("noise encrypt: {e}")))?;
        out.truncate(n);
        Ok(out)
    }

    /// Decrypt `ciphertext` under `counter`; returns plaintext. Fails on a bad
    /// tag (wrong key, tamper, or wrong counter).
    pub(crate) fn decrypt(&self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, Fault> {
        let mut out = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(counter, ciphertext, &mut out)
            .map_err(|e| Fault::new(Reason::CryptoError, format!("noise decrypt: {e}")))?;
        out.truncate(n);
        Ok(out)
    }
}

/// Build A's cert-auth plaintext: `cert_len(2, BE) || cert_der || signature`,
/// where `signature` is ECDSA-P256-SHA256 (ASN.1 DER) over
/// `AUTH_SIG_DOMAIN || handshake_hash`. The caller encrypts this with the
/// session and sends it as the first transport message.
pub(crate) fn build_cert_auth(
    identity: &Identity,
    handshake_hash: &[u8; 32],
) -> Result<Vec<u8>, Fault> {
    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &identity.key_der_bytes,
        &rng,
    )
    .map_err(|e| {
        Fault::new(
            Reason::CryptoError,
            format!("noise auth: rejected key: {e}"),
        )
    })?;
    let mut input = Vec::with_capacity(AUTH_SIG_DOMAIN.len() + handshake_hash.len());
    input.extend_from_slice(AUTH_SIG_DOMAIN);
    input.extend_from_slice(handshake_hash);
    let sig = key_pair
        .sign(&rng, &input)
        .map_err(|_| Fault::new(Reason::CryptoError, "noise auth: signing failed"))?;

    let cert = &identity.cert_der_bytes;
    debug_assert!(cert.len() <= u16::MAX as usize);
    let mut out = Vec::with_capacity(2 + cert.len() + sig.as_ref().len());
    out.extend_from_slice(&(cert.len() as u16).to_be_bytes());
    out.extend_from_slice(cert);
    out.extend_from_slice(sig.as_ref());
    Ok(out)
}

/// Verify A's cert-auth plaintext against the pinned `routing_key` and the
/// channel-binding `handshake_hash`. Confirms (1) the cert commits to the
/// routing key (`SHA-256(cert)[..20] == routing_key`) and (2) the cert's key
/// signed this session's handshake hash.
pub(crate) fn verify_cert_auth(
    auth: &[u8],
    routing_key: &[u8; ROUTING_KEY_LEN],
    handshake_hash: &[u8; 32],
) -> Result<(), Fault> {
    if auth.len() < 2 {
        return Err(Fault::new(
            Reason::ProtocolViolation,
            "noise auth: truncated",
        ));
    }
    let cert_len = u16::from_be_bytes([auth[0], auth[1]]) as usize;
    if auth.len() < 2 + cert_len + 1 {
        return Err(Fault::new(
            Reason::ProtocolViolation,
            "noise auth: truncated cert/sig",
        ));
    }
    let cert_der = &auth[2..2 + cert_len];
    let signature = &auth[2 + cert_len..];

    // The routing key must commit to this cert — otherwise a valid signature by
    // some *other* identity would be accepted.
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    if digest.as_ref()[..ROUTING_KEY_LEN] != routing_key[..] {
        return Err(Fault::new(
            Reason::CertMismatch,
            "noise auth: routing key does not match cert",
        ));
    }

    let cert = CertificateDer::from(cert_der);
    let eec = webpki::EndEntityCert::try_from(&cert)
        .map_err(|_| Fault::new(Reason::CertMismatch, "noise auth: bad cert"))?;
    let mut input = Vec::with_capacity(AUTH_SIG_DOMAIN.len() + handshake_hash.len());
    input.extend_from_slice(AUTH_SIG_DOMAIN);
    input.extend_from_slice(handshake_hash);
    eec.verify_signature(webpki::ring::ECDSA_P256_SHA256, &input, signature)
        .map_err(|_| Fault::new(Reason::CertMismatch, "noise auth: bad signature"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// Drive a full B<->A handshake in memory and return both sessions.
    fn handshake_pair(
        rk: &[u8; ROUTING_KEY_LEN],
        b_secret: &[u8; SECRET_LEN],
        identity: &Identity,
    ) -> Result<(NoiseSession, NoiseSession), Fault> {
        let mut b = NoiseHandshake::initiator(rk, b_secret)?; // B: URL secret
        let mut a = NoiseHandshake::responder(identity)?; // A: own identity

        let msg1 = b.write_message(&[])?;
        a.read_message(&msg1)?; // fails here on a wrong secret (psk tag)
        let msg2 = a.write_message(&[])?;
        b.read_message(&msg2)?;

        assert!(a.is_finished() && b.is_finished());
        Ok((a.into_session()?, b.into_session()?))
    }

    #[test]
    fn full_handshake_and_cert_auth_succeeds() {
        let identity = Identity::generate();
        let rk = identity.routing_key;
        let (a_sess, b_sess) = handshake_pair(&rk, &identity.secret, &identity).expect("handshake");

        // Same channel binding on both sides.
        assert_eq!(a_sess.handshake_hash, b_sess.handshake_hash);

        // A sends the cert-auth as transport message #0; B decrypts + verifies.
        let auth = build_cert_auth(&identity, &a_sess.handshake_hash).expect("build auth");
        let ct = a_sess.encrypt(0, &auth).expect("encrypt auth");
        let pt = b_sess.decrypt(0, &ct).expect("decrypt auth");
        verify_cert_auth(&pt, &rk, &b_sess.handshake_hash).expect("auth must verify");

        // And the data plane carries bytes both ways under increasing counters.
        let c1 = a_sess.encrypt(1, b"hello from A").unwrap();
        assert_eq!(b_sess.decrypt(1, &c1).unwrap(), b"hello from A");
        let c2 = b_sess.encrypt(1, b"hi from B").unwrap();
        assert_eq!(a_sess.decrypt(1, &c2).unwrap(), b"hi from B");
    }

    #[test]
    fn wrong_secret_fails_the_first_message() {
        let identity = Identity::generate();
        let rk = identity.routing_key;
        // B dials with the wrong secret: the psk0 tag on msg1 won't verify, so A
        // rejects before any DH — never reaching msg2.
        let wrong = [0xABu8; SECRET_LEN];
        let err = match handshake_pair(&rk, &wrong, &identity) {
            Ok(_) => panic!("a wrong secret must not complete the handshake"),
            Err(e) => e,
        };
        assert_eq!(
            err.reason,
            Reason::CryptoError,
            "expected a decryption failure, got: {err}"
        );
    }

    #[test]
    fn cert_auth_rejects_a_routing_key_mismatch() {
        let identity = Identity::generate();
        let (a_sess, b_sess) =
            handshake_pair(&identity.routing_key, &identity.secret, &identity).unwrap();
        let auth = build_cert_auth(&identity, &a_sess.handshake_hash).unwrap();
        let pt = b_sess
            .decrypt(0, &a_sess.encrypt(0, &auth).unwrap())
            .unwrap();
        // Pin to a different routing key than the cert commits to.
        let mut bogus = identity.routing_key;
        bogus[0] ^= 0xFF;
        let err = verify_cert_auth(&pt, &bogus, &b_sess.handshake_hash).unwrap_err();
        assert_eq!(err.reason, Reason::CertMismatch, "{err}");
    }

    #[test]
    fn cert_auth_rejects_a_tampered_signature() {
        let identity = Identity::generate();
        let (a_sess, b_sess) =
            handshake_pair(&identity.routing_key, &identity.secret, &identity).unwrap();
        let mut auth = build_cert_auth(&identity, &a_sess.handshake_hash).unwrap();
        // Flip a byte in the trailing signature.
        let last = auth.len() - 1;
        auth[last] ^= 0x01;
        let ct = a_sess.encrypt(0, &auth).unwrap();
        let pt = b_sess.decrypt(0, &ct).unwrap();
        assert!(verify_cert_auth(&pt, &identity.routing_key, &b_sess.handshake_hash).is_err());
    }

    #[test]
    fn cert_auth_rejects_a_different_sessions_hash() {
        // A signature from one session must not verify against another session's
        // channel binding (replay/relay resistance).
        let identity = Identity::generate();
        let (a1, _b1) = handshake_pair(&identity.routing_key, &identity.secret, &identity).unwrap();
        let (_a2, b2) = handshake_pair(&identity.routing_key, &identity.secret, &identity).unwrap();
        assert_ne!(a1.handshake_hash, b2.handshake_hash, "sessions differ");
        let auth = build_cert_auth(&identity, &a1.handshake_hash).unwrap();
        // Verify against session 2's binding: must fail.
        assert!(verify_cert_auth(&auth, &identity.routing_key, &b2.handshake_hash).is_err());
    }
}
