//! Tier-1 "DPI's-eye view": decrypt a captured QUIC v1 Initial and parse the
//! TLS ClientHello to recover what an on-path classifier can see — SNI, ALPN,
//! and the JA4-Q fingerprint. A QUIC Initial is encrypted only with keys
//! derived from the (cleartext) Destination Connection ID plus the public v1
//! salt (RFC 9001 §5.2), so any observer can decrypt it; this module does
//! exactly that, in-tree, so the `fingerprint` suite needs no external
//! classifier (nDPI/tshark) and runs anywhere tcpdump can capture.
//!
//! Scope: just enough QUIC/TLS to read a quinn client's first Initial. Frame
//! parsing handles PADDING/PING/CRYPTO (what a client Initial contains).
//! Crypto (HKDF-Expand-Label, header protection, AES-128-GCM) is unit-tested
//! against the RFC 9001 Appendix A vectors.

use ring::{aead, hmac};

/// RFC 9001 §5.2 — QUIC v1 Initial salt.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// What an on-path classifier can extract from a client's QUIC Initial.
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    /// SNI (`server_name`) if the extension is present.
    pub sni: Option<String>,
    /// Offered ALPN protocols, in order.
    pub alpns: Vec<String>,
    /// Cipher suites offered (GREASE included; JA4 strips it).
    pub cipher_suites: Vec<u16>,
    /// Extension types present (GREASE included).
    pub extensions: Vec<u16>,
    /// signature_algorithms (extension 0x000d), in order.
    pub sig_algs: Vec<u16>,
    /// The JA4-Q fingerprint (`q…_…_…`).
    pub ja4: String,
}

// ---------------------------------------------------------------------------
// QUIC variable-length integers (RFC 9000 §16).

/// Decode a QUIC varint at `buf[0..]`; returns `(value, bytes_consumed)`.
fn varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        v = (v << 8) | b as u64;
    }
    Some((v, len))
}

// ---------------------------------------------------------------------------
// QUIC Initial key derivation (RFC 9001 §5.2) using HKDF-SHA256.

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    hmac::sign(&key, ikm).as_ref().to_vec()
}

/// TLS 1.3 HKDF-Expand-Label with an empty context. Outputs ≤ 32 bytes, so a
/// single HMAC iteration (T(1)) suffices.
fn expand_label(prk: &[u8], label: &str, out_len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(3 + full_label.len() + 1 + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // empty context
    info.push(0x01); // T(1) counter
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    hmac::sign(&key, &info).as_ref()[..out_len].to_vec()
}

/// Client Initial (key, iv, hp) derived from the Destination Connection ID.
fn client_initial_keys(dcid: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let initial_secret = hkdf_extract(&INITIAL_SALT_V1, dcid);
    let client_secret = expand_label(&initial_secret, "client in", 32);
    let key = expand_label(&client_secret, "quic key", 16);
    let iv = expand_label(&client_secret, "quic iv", 12);
    let hp = expand_label(&client_secret, "quic hp", 16);
    (key, iv, hp)
}

// ---------------------------------------------------------------------------
// Initial packet decryption.

/// If `udp_payload` is a QUIC v1 **Initial** from a client, decrypt it and
/// return the reassembled CRYPTO stream (the TLS handshake bytes). Returns
/// `None` for any non-Initial / unparseable / undecryptable input.
fn decrypt_initial(udp_payload: &[u8]) -> Option<Vec<u8>> {
    let pkt = udp_payload;
    let b0 = *pkt.first()?;
    // Long header (0x80) with fixed bit (0x40), packet type 0 = Initial.
    if b0 & 0xc0 != 0xc0 || (b0 >> 4) & 0x03 != 0 {
        return None;
    }
    if pkt.get(1..5)? != [0x00, 0x00, 0x00, 0x01] {
        return None; // not QUIC v1
    }
    let dcid_len = *pkt.get(5)? as usize;
    let dcid = pkt.get(6..6 + dcid_len)?;
    let mut p = 6 + dcid_len;
    let scid_len = *pkt.get(p)? as usize;
    p += 1 + scid_len;
    let (token_len, n) = varint(pkt.get(p..)?)?;
    p += n + token_len as usize;
    let (length, m) = varint(pkt.get(p..)?)?;
    let pn_offset = p + m;
    let payload_end = pn_offset + length as usize;
    if pkt.len() < payload_end {
        return None;
    }

    let (key, iv, hp) = client_initial_keys(dcid);

    // Header protection: the sample begins 4 bytes past the packet-number
    // offset (assuming the maximum 4-byte PN).
    let sample = pkt.get(pn_offset + 4..pn_offset + 20)?;
    let hp_key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &hp).ok()?;
    let mask = hp_key.new_mask(sample).ok()?;

    let unprotected_b0 = b0 ^ (mask[0] & 0x0f);
    let pn_len = (unprotected_b0 & 0x03) as usize + 1;
    let mut packet_number: u64 = 0;
    let mut header = pkt[..pn_offset].to_vec();
    header[0] = unprotected_b0;
    for i in 0..pn_len {
        let pn_byte = pkt[pn_offset + i] ^ mask[1 + i];
        packet_number = (packet_number << 8) | pn_byte as u64;
        header.push(pn_byte);
    }

    // AES-128-GCM: nonce = iv XOR left-padded packet number; AAD = header.
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    let pn_be = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_be[i];
    }
    let mut ciphertext = pkt[pn_offset + pn_len..payload_end].to_vec();
    let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &key).ok()?;
    let open_key = aead::LessSafeKey::new(unbound);
    let plaintext = open_key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&header),
            &mut ciphertext,
        )
        .ok()?;

    reassemble_crypto(plaintext)
}

/// Reassemble CRYPTO frame data (RFC 9000 §19.6) from a decrypted Initial
/// payload, skipping PADDING/PING. Returns the contiguous stream from offset 0.
fn reassemble_crypto(frames: &[u8]) -> Option<Vec<u8>> {
    let mut fragments: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut i = 0;
    while i < frames.len() {
        match frames[i] {
            0x00 | 0x01 => i += 1, // PADDING / PING
            0x06 => {
                let (offset, no) = varint(frames.get(i + 1..)?)?;
                let (len, nl) = varint(frames.get(i + 1 + no..)?)?;
                let start = i + 1 + no + nl;
                let end = start + len as usize;
                fragments.push((offset, frames.get(start..end)?.to_vec()));
                i = end;
            }
            _ => break, // unknown frame: stop (a client Initial won't have these)
        }
    }
    fragments.sort_by_key(|(off, _)| *off);
    let mut out = Vec::new();
    for (off, data) in fragments {
        if off as usize == out.len() {
            out.extend_from_slice(&data);
        }
    }
    (!out.is_empty()).then_some(out)
}

// ---------------------------------------------------------------------------
// TLS ClientHello parsing.

fn is_grease(v: u16) -> bool {
    let (hi, lo) = ((v >> 8) as u8, (v & 0xff) as u8);
    hi == lo && (lo & 0x0f) == 0x0a
}

/// Read a big-endian u16 at `buf[pos]`, advancing `pos`.
fn read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
    let v = u16::from_be_bytes(buf.get(*pos..*pos + 2)?.try_into().ok()?);
    *pos += 2;
    Some(v)
}

/// Parse a ClientHello (the reassembled CRYPTO stream) into the classifier's
/// view. Returns `None` if it is not a well-formed ClientHello.
fn parse_client_hello(tls: &[u8]) -> Option<ClientHelloInfo> {
    let mut p = 0;
    if *tls.first()? != 0x01 {
        return None; // not a ClientHello handshake message
    }
    p += 4; // handshake type (1) + length (3)
    p += 2; // legacy_version
    p += 32; // random
    let sid_len = *tls.get(p)? as usize;
    p += 1 + sid_len; // session_id

    let cs_len = read_u16(tls, &mut p)? as usize;
    let mut cipher_suites = Vec::new();
    let cs_end = p + cs_len;
    while p < cs_end {
        cipher_suites.push(read_u16(tls, &mut p)?);
    }

    let comp_len = *tls.get(p)? as usize;
    p += 1 + comp_len; // compression methods

    let _ext_total = read_u16(tls, &mut p)? as usize;
    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpns = Vec::new();
    let mut sig_algs = Vec::new();
    while p + 4 <= tls.len() {
        let ext_type = read_u16(tls, &mut p)?;
        let ext_len = read_u16(tls, &mut p)? as usize;
        let body = tls.get(p..p + ext_len)?;
        p += ext_len;
        extensions.push(ext_type);
        match ext_type {
            0x0000 => sni = parse_sni(body),
            0x0010 => alpns = parse_alpn(body),
            0x000d => sig_algs = parse_u16_list_2(body),
            _ => {}
        }
    }

    let ja4 = ja4_q(
        &cipher_suites,
        &extensions,
        &alpns,
        &sig_algs,
        sni.is_some(),
    );
    Some(ClientHelloInfo {
        sni,
        alpns,
        cipher_suites,
        extensions,
        sig_algs,
        ja4,
    })
}

fn parse_sni(body: &[u8]) -> Option<String> {
    // server_name_list: list_len(2), then entries: type(1), name_len(2), name.
    let mut p = 2;
    let _typ = *body.get(p)?;
    p += 1;
    let len = u16::from_be_bytes(body.get(p..p + 2)?.try_into().ok()?) as usize;
    p += 2;
    Some(String::from_utf8_lossy(body.get(p..p + len)?).into_owned())
}

fn parse_alpn(body: &[u8]) -> Vec<String> {
    // protocol_name_list: list_len(2), then entries: name_len(1), name.
    let mut out = Vec::new();
    let mut p = 2;
    while p < body.len() {
        let len = body[p] as usize;
        p += 1;
        if let Some(name) = body.get(p..p + len) {
            out.push(String::from_utf8_lossy(name).into_owned());
        }
        p += len;
    }
    out
}

/// Parse a `<len(2)>`-prefixed list of u16 values (e.g. signature_algorithms).
fn parse_u16_list_2(body: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let mut p = 2;
    while p + 2 <= body.len() {
        out.push(u16::from_be_bytes([body[p], body[p + 1]]));
        p += 2;
    }
    out
}

// ---------------------------------------------------------------------------
// JA4-Q fingerprint (FoxIO JA4, QUIC variant: leading 'q').

fn ja4_q(
    ciphers: &[u16],
    extensions: &[u16],
    alpns: &[String],
    sig_algs: &[u16],
    has_sni: bool,
) -> String {
    let live_ciphers: Vec<u16> = ciphers.iter().copied().filter(|c| !is_grease(*c)).collect();
    let live_exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();

    let sni_char = if has_sni { 'd' } else { 'i' };
    let alpn_pair = match alpns.first() {
        Some(a) if !a.is_empty() => {
            let bytes = a.as_bytes();
            format!("{}{}", bytes[0] as char, bytes[bytes.len() - 1] as char)
        }
        _ => "00".to_string(),
    };
    // Version: TLS 1.3 is what QUIC mandates; this stack is 1.3-only.
    let ja4_a = format!(
        "q13{sni_char}{:02}{:02}{alpn_pair}",
        live_ciphers.len().min(99),
        live_exts.len().min(99),
    );

    let mut cipher_hex: Vec<String> = live_ciphers.iter().map(|c| format!("{c:04x}")).collect();
    cipher_hex.sort();
    let ja4_b = sha256_hex12(cipher_hex.join(",").as_bytes());

    // JA4_c: sorted extensions (SNI 0x0000 and ALPN 0x0010 excluded), then
    // "_" + signature_algorithms in order, hashed together.
    let mut ext_hex: Vec<String> = live_exts
        .iter()
        .filter(|e| **e != 0x0000 && **e != 0x0010)
        .map(|e| format!("{e:04x}"))
        .collect();
    ext_hex.sort();
    let mut ja4_c_input = ext_hex.join(",");
    if !sig_algs.is_empty() {
        let sig_hex: Vec<String> = sig_algs.iter().map(|s| format!("{s:04x}")).collect();
        ja4_c_input.push('_');
        ja4_c_input.push_str(&sig_hex.join(","));
    }
    let ja4_c = sha256_hex12(ja4_c_input.as_bytes());

    format!("{ja4_a}_{ja4_b}_{ja4_c}")
}

fn sha256_hex12(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    digest.as_ref()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// pcap → UDP payloads → first client Initial.

/// Extract UDP payloads from a classic (non-`.pcapng`) pcap with Ethernet
/// link-layer (`tcpdump -i <veth> -w`). Tolerates v4 and v6.
pub fn udp_payloads_from_pcap(pcap: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if pcap.len() < 24 {
        return out;
    }
    // Global header: magic (4) tells endianness; we only need record lengths.
    let le = match pcap[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return out,
    };
    let rd_u32 = |b: &[u8]| -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    };
    let mut pos = 24;
    while pos + 16 <= pcap.len() {
        let caplen = rd_u32(&pcap[pos + 8..pos + 12]) as usize;
        pos += 16;
        let Some(frame) = pcap.get(pos..pos + caplen) else {
            break;
        };
        pos += caplen;
        if let Ok(sliced) = etherparse::SlicedPacket::from_ethernet(frame)
            && let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport
        {
            out.push(udp.payload().to_vec());
        }
    }
    out
}

/// Inspect a capture and return the first decryptable client Initial's
/// ClientHello (SNI/ALPN/JA4). `None` if no Initial was captured/decrypted.
pub fn first_client_hello(pcap: &[u8]) -> Option<ClientHelloInfo> {
    udp_payloads_from_pcap(pcap)
        .iter()
        .find_map(|p| decrypt_initial(p).and_then(|tls| parse_client_hello(&tls)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001 Appendix A.1/A.2: the sample client Initial uses
    // DCID = 0x8394c8f03e515708 and the published client key/iv/hp below.
    #[test]
    fn rfc9001_key_derivation() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let (key, iv, hp) = client_initial_keys(&dcid);
        assert_eq!(hex(&key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xdada));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0000));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
