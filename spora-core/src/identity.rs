//! Sharer identity and the share token / URL.
//!
//! A sharer's `Identity` bundles a fresh per-session TLS cert + key, its
//! `routing_key` (SHA-256 of the cert DER, used by the relay to route packets
//! and by the client to pin the cert), and a random `secret` the client must
//! present over the encrypted channel to be authorized.
//!
//! `Token` is the public projection of that identity (everything the client
//! needs, except the private key and the cert itself which it learns over TLS).
//! It encodes as a share URL of the form
//! `https://spora.to/s/<base64url(routing_key || secret)>?r=<host>:<port>`.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use url::Url;

use crate::transport::quic::{cert_fingerprint, generate_self_signed_cert};

const URL_HOST: &str = "spora.to";
const URL_PATH_PREFIX: &str = "/s/";

/// 20 bytes so it fits in a QUIC v1 DCID (RFC 9000 §17.2 caps at 20). SHA-256
/// truncated to 160 bits still gives ~80-bit collision resistance — fine for
/// pinning, since an attacker must also produce a matching ECDSA key pair.
pub const ROUTING_KEY_LEN: usize = 20;
pub const SECRET_LEN: usize = 16;
const TOKEN_BLOB_LEN: usize = ROUTING_KEY_LEN + SECRET_LEN;

/// Derive the routing key from a DER-encoded certificate: SHA-256, truncated
/// to `ROUTING_KEY_LEN`.
pub fn derive_routing_key(cert_der: &[u8]) -> [u8; ROUTING_KEY_LEN] {
    let full = cert_fingerprint(cert_der);
    let mut rk = [0u8; ROUTING_KEY_LEN];
    rk.copy_from_slice(&full[..ROUTING_KEY_LEN]);
    rk
}

/// A sharer's per-session identity. Cheap to clone (just `Vec<u8>` + arrays);
/// store an `Arc<Identity>` if you want shared ownership without copying.
#[derive(Clone)]
pub struct Identity {
    pub cert_der_bytes: Vec<u8>,
    pub key_der_bytes: Vec<u8>,
    pub routing_key: [u8; ROUTING_KEY_LEN],
    pub secret: [u8; SECRET_LEN],
}

impl Identity {
    /// Generate a fresh identity: ECDSA P-256 self-signed cert, random secret,
    /// routing_key derived from the cert.
    pub fn generate() -> Self {
        let (cert_der, key_der, _full_fp) = generate_self_signed_cert();
        let cert_der_bytes = cert_der.as_ref().to_vec();
        let key_der_bytes = match key_der {
            PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
            PrivateKeyDer::Sec1(k) => k.secret_sec1_der().to_vec(),
            PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der().to_vec(),
            _ => unreachable!("rcgen yields one of the above variants"),
        };
        let routing_key = derive_routing_key(&cert_der_bytes);
        let mut secret = [0u8; SECRET_LEN];
        rand::thread_rng().fill_bytes(&mut secret);
        Self {
            cert_der_bytes,
            key_der_bytes,
            routing_key,
            secret,
        }
    }

    /// Fresh owned `CertificateDer` view of the bytes (clones once).
    pub fn cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der_bytes.clone())
    }

    /// Fresh owned `PrivateKeyDer` view of the bytes (clones once).
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::try_from(self.key_der_bytes.clone())
            .expect("Identity::key_der_bytes were produced by us; must parse")
    }

    /// Build the `Token` to give the client, for this identity reached via the
    /// given relay.
    pub fn token(&self, relay_host: impl Into<String>, relay_port: u16) -> Token {
        Token {
            routing_key: self.routing_key,
            secret: self.secret,
            relay_host: relay_host.into(),
            relay_port,
        }
    }

    /// Serialize for persistence. Layout (all big-endian):
    /// `[MAGIC(4) | VERSION(1) | cert_len(u32) | cert_der | key_len(u32) | key_der | secret(16)]`.
    /// Persist these bytes verbatim; the caller is responsible for storing them
    /// in a platform-appropriate way (file, keystore, SharedPreferences, etc.).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            IDENTITY_MAGIC.len()
                + 1
                + 4
                + self.cert_der_bytes.len()
                + 4
                + self.key_der_bytes.len()
                + SECRET_LEN,
        );
        out.extend_from_slice(&IDENTITY_MAGIC);
        out.push(IDENTITY_VERSION);
        out.extend_from_slice(&(self.cert_der_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.cert_der_bytes);
        out.extend_from_slice(&(self.key_der_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.key_der_bytes);
        out.extend_from_slice(&self.secret);
        out
    }

    /// Restore a previously-persisted identity. Verifies the magic, version,
    /// and structural integrity; recomputes the routing key from the cert.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut cur = 0usize;
        if bytes.len() < IDENTITY_MAGIC.len() + 1 {
            return Err("identity blob: header truncated".into());
        }
        if bytes[..IDENTITY_MAGIC.len()] != IDENTITY_MAGIC {
            return Err("identity blob: bad magic".into());
        }
        cur += IDENTITY_MAGIC.len();
        let version = bytes[cur];
        cur += 1;
        if version != IDENTITY_VERSION {
            return Err(format!(
                "identity blob: unsupported version {} (expected {})",
                version, IDENTITY_VERSION
            ));
        }

        let cert_der_bytes = read_lp_field(bytes, &mut cur, "cert")?;
        let key_der_bytes = read_lp_field(bytes, &mut cur, "key")?;

        if bytes.len() < cur + SECRET_LEN {
            return Err("identity blob: secret truncated".into());
        }
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&bytes[cur..cur + SECRET_LEN]);
        cur += SECRET_LEN;
        if cur != bytes.len() {
            return Err(format!(
                "identity blob: {} trailing bytes after secret",
                bytes.len() - cur
            ));
        }

        // Validate key parses.
        PrivateKeyDer::try_from(key_der_bytes.clone())
            .map_err(|e| format!("identity blob: invalid private key DER: {}", e))?;

        let routing_key = derive_routing_key(&cert_der_bytes);
        Ok(Self {
            cert_der_bytes,
            key_der_bytes,
            routing_key,
            secret,
        })
    }
}

const IDENTITY_MAGIC: [u8; 4] = *b"sIDv";
const IDENTITY_VERSION: u8 = 1;

fn read_lp_field(bytes: &[u8], cur: &mut usize, name: &str) -> Result<Vec<u8>, String> {
    // Checked arithmetic throughout: `len` is an attacker-influenced u32 from the
    // blob, and on 32-bit targets (armv7/i686 Android) usize is 32 bits, so a
    // near-u32::MAX length would overflow `*cur + len` and panic instead of
    // returning Err. from_bytes exists precisely to reject corrupted input.
    let len_end = cur
        .checked_add(4)
        .filter(|e| *e <= bytes.len())
        .ok_or_else(|| format!("identity blob: {} length truncated", name))?;
    let len = u32::from_be_bytes(bytes[*cur..len_end].try_into().unwrap()) as usize;
    let field_end = len_end
        .checked_add(len)
        .filter(|e| *e <= bytes.len())
        .ok_or_else(|| format!("identity blob: {} bytes truncated", name))?;
    let field = bytes[len_end..field_end].to_vec();
    *cur = field_end;
    Ok(field)
}

/// What the client gets out of a share URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub routing_key: [u8; ROUTING_KEY_LEN],
    pub secret: [u8; SECRET_LEN],
    pub relay_host: String,
    pub relay_port: u16,
}

impl Token {
    /// Render as `https://spora.to/s/<base64url>?r=<host>:<port>`.
    pub fn to_url(&self) -> Url {
        let mut blob = [0u8; TOKEN_BLOB_LEN];
        blob[..ROUTING_KEY_LEN].copy_from_slice(&self.routing_key);
        blob[ROUTING_KEY_LEN..].copy_from_slice(&self.secret);
        let encoded = URL_SAFE_NO_PAD.encode(blob);
        let url_str = format!(
            "https://{}{}{}?r={}:{}",
            URL_HOST, URL_PATH_PREFIX, encoded, self.relay_host, self.relay_port
        );
        Url::parse(&url_str).expect("constructed Token URL must parse")
    }

    /// Parse a share URL back into a token.
    pub fn from_url(url: &Url) -> Result<Self, String> {
        let blob_b64 = url
            .path()
            .strip_prefix(URL_PATH_PREFIX)
            .ok_or_else(|| {
                format!(
                    "URL path must start with {}, got {}",
                    URL_PATH_PREFIX,
                    url.path()
                )
            })?;
        if blob_b64.is_empty() {
            return Err("URL path is missing the token after /s/".into());
        }
        let blob = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .map_err(|e| format!("invalid base64 in URL token: {}", e))?;
        if blob.len() != TOKEN_BLOB_LEN {
            return Err(format!(
                "token blob is {} bytes, expected {}",
                blob.len(),
                TOKEN_BLOB_LEN
            ));
        }

        let mut routing_key = [0u8; ROUTING_KEY_LEN];
        routing_key.copy_from_slice(&blob[..ROUTING_KEY_LEN]);
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&blob[ROUTING_KEY_LEN..]);

        let relay = url
            .query_pairs()
            .find(|(k, _)| k == "r")
            .map(|(_, v)| v.into_owned())
            .ok_or("URL is missing required ?r= query parameter")?;
        let (host, port_str) = relay
            .rsplit_once(':')
            .ok_or_else(|| format!("?r= value must be host:port, got {}", relay))?;
        let relay_port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port in ?r= value: {}", port_str))?;

        Ok(Token {
            routing_key,
            secret,
            relay_host: host.to_string(),
            relay_port,
        })
    }
}

/// Server cert verifier that pins the cert's SHA-256 fingerprint to the
/// `routing_key` carried in a `Token`. B installs this on its rustls
/// `ClientConfig` when dialing A through the relay.
#[derive(Debug)]
pub struct RoutingKeyVerifier {
    expected: [u8; ROUTING_KEY_LEN],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl RoutingKeyVerifier {
    pub fn new(
        expected: [u8; ROUTING_KEY_LEN],
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self { expected, provider }
    }
}

impl rustls::client::danger::ServerCertVerifier for RoutingKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual = derive_routing_key(end_entity.as_ref());
        if actual == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "routing key mismatch: expected {:x?}, got {:x?}",
                &self.expected[..4],
                &actual[..4],
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_url_round_trip() {
        let routing_key = [0x42u8; ROUTING_KEY_LEN];
        let secret = [0x99u8; SECRET_LEN];
        let token = Token {
            routing_key,
            secret,
            relay_host: "relay.spora.dev".into(),
            relay_port: 443,
        };

        let url = token.to_url();
        let parsed = Token::from_url(&url).unwrap();

        assert_eq!(parsed, token);
        assert!(url.as_str().starts_with("https://spora.to/s/"));
        assert!(url.as_str().ends_with("?r=relay.spora.dev:443"));
    }

    #[test]
    fn identity_generation_yields_matching_routing_key() {
        let id = Identity::generate();
        assert_eq!(id.routing_key, derive_routing_key(&id.cert_der_bytes));
        assert_eq!(id.routing_key.len(), ROUTING_KEY_LEN);
        assert!(
            id.secret.iter().any(|&b| b != 0),
            "secret should be random, not all zeros"
        );
    }

    #[test]
    fn two_identities_differ() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_ne!(a.routing_key, b.routing_key);
        assert_ne!(a.secret, b.secret);
    }

    #[test]
    fn token_from_identity_round_trip() {
        let id = Identity::generate();
        let token = id.token("relay.example.com", 4242);
        let url = token.to_url();
        let parsed = Token::from_url(&url).unwrap();
        assert_eq!(parsed.routing_key, id.routing_key);
        assert_eq!(parsed.secret, id.secret);
        assert_eq!(parsed.relay_host, "relay.example.com");
        assert_eq!(parsed.relay_port, 4242);
    }

    #[test]
    fn from_url_rejects_short_blob() {
        let bad = Url::parse("https://spora.to/s/aGVsbG8?r=h:1").unwrap();
        let err = Token::from_url(&bad).unwrap_err();
        assert!(err.contains("36"), "got: {}", err);
    }

    #[test]
    fn from_url_rejects_missing_query() {
        let blob = URL_SAFE_NO_PAD.encode([0u8; TOKEN_BLOB_LEN]);
        let bad = Url::parse(&format!("https://spora.to/s/{}", blob)).unwrap();
        let err = Token::from_url(&bad).unwrap_err();
        assert!(err.contains("?r="), "got: {}", err);
    }

    #[test]
    fn from_url_rejects_wrong_path() {
        let blob = URL_SAFE_NO_PAD.encode([0u8; TOKEN_BLOB_LEN]);
        let bad = Url::parse(&format!("https://spora.to/x/{}?r=h:1", blob)).unwrap();
        let err = Token::from_url(&bad).unwrap_err();
        assert!(err.contains("/s/"), "got: {}", err);
    }

    #[test]
    fn from_url_rejects_bad_port() {
        let blob = URL_SAFE_NO_PAD.encode([0u8; TOKEN_BLOB_LEN]);
        let bad = Url::parse(&format!("https://spora.to/s/{}?r=h:notaport", blob)).unwrap();
        let err = Token::from_url(&bad).unwrap_err();
        assert!(err.contains("port"), "got: {}", err);
    }

    #[test]
    fn routing_key_verifier_accepts_matching() {
        use rustls::client::danger::ServerCertVerifier;
        let id = Identity::generate();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = RoutingKeyVerifier::new(id.routing_key, provider);
        let result = verifier.verify_server_cert(
            &id.cert_der(),
            &[],
            &rustls::pki_types::ServerName::try_from("spora.peer").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_ok(), "verifier should accept matching cert");
    }

    #[test]
    fn identity_to_from_bytes_round_trip() {
        let id = Identity::generate();
        let bytes = id.to_bytes();
        let restored = Identity::from_bytes(&bytes).unwrap();
        assert_eq!(restored.cert_der_bytes, id.cert_der_bytes);
        assert_eq!(restored.key_der_bytes, id.key_der_bytes);
        assert_eq!(restored.routing_key, id.routing_key);
        assert_eq!(restored.secret, id.secret);
    }

    #[test]
    fn identity_from_bytes_rejects_bad_magic() {
        let mut bytes = Identity::generate().to_bytes();
        bytes[0] ^= 0xFF;
        let err = match Identity::from_bytes(&bytes) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.contains("magic"), "got: {}", err);
    }

    #[test]
    fn identity_from_bytes_rejects_wrong_version() {
        let mut bytes = Identity::generate().to_bytes();
        bytes[IDENTITY_MAGIC.len()] = 99;
        let err = match Identity::from_bytes(&bytes) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.contains("version"), "got: {}", err);
    }

    #[test]
    fn identity_from_bytes_rejects_truncated() {
        let bytes = Identity::generate().to_bytes();
        let truncated = &bytes[..bytes.len() - 5];
        let err = match Identity::from_bytes(truncated) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.contains("truncated"), "got: {}", err);
    }

    #[test]
    fn identity_from_bytes_rejects_huge_length_field() {
        // A corrupted/attacker blob with an enormous length prefix must return
        // Err, not overflow-panic. (The panic only manifested on 32-bit usize,
        // but the checked arithmetic must reject it on every target; on 64-bit
        // the length simply exceeds the remaining bytes.)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&IDENTITY_MAGIC);
        bytes.push(IDENTITY_VERSION);
        bytes.extend_from_slice(&u32::MAX.to_be_bytes()); // cert_len = 0xFFFFFFFF
        bytes.extend_from_slice(&[0u8; 8]);
        let err = match Identity::from_bytes(&bytes) {
            Ok(_) => panic!("expected error for huge length field"),
            Err(e) => e,
        };
        assert!(err.contains("truncated"), "got: {}", err);
    }

    #[test]
    fn identity_from_bytes_rejects_trailing_garbage() {
        let mut bytes = Identity::generate().to_bytes();
        bytes.extend_from_slice(b"junk");
        let err = match Identity::from_bytes(&bytes) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.contains("trailing"), "got: {}", err);
    }

    #[test]
    fn routing_key_verifier_rejects_mismatched() {
        use rustls::client::danger::ServerCertVerifier;
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = RoutingKeyVerifier::new(id1.routing_key, provider);
        let result = verifier.verify_server_cert(
            &id2.cert_der(),
            &[],
            &rustls::pki_types::ServerName::try_from("spora.peer").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_err(), "verifier should reject mismatched cert");
    }
}
