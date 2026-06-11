use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{Sink, Stream};
use log::{debug, error, info, warn};
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// SHA-256 fingerprint of a DER-encoded certificate.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    let mut fp = [0u8; 32];
    fp.copy_from_slice(digest.as_ref());
    fp
}

/// Generate a self-signed ECDSA P-256 certificate for P2P QUIC.
/// Returns (cert_der, key_der, sha256_fingerprint).
pub fn generate_self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>, [u8; 32]) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("spora.peer".try_into().unwrap()));
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    let fingerprint = cert_fingerprint(cert_der.as_ref());

    (cert_der, key_der, fingerprint)
}

/// A `Transport` that carries IP packets as QUIC datagrams over a P2P connection.
pub struct QuicPeerTransport {
    rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    conn: Connection,
    /// Monotonic IP Identification for outbound fragmented datagrams (see
    /// `fragment_ipv4`), so distinct datagrams never share an id.
    ip_id_ctr: AtomicU16,
    _reader: JoinHandle<()>,
}

impl QuicPeerTransport {
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Returns a clone of the underlying QUIC connection handle.
    /// Useful for reading stats after PMTUD converges.
    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub fn new(conn: Connection) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let read_conn = conn.clone();
        let reader = tokio::spawn(async move {
            loop {
                match read_conn.read_datagram().await {
                    Ok(data) => {
                        if tx.send(Ok(data.to_vec())).is_err() {
                            info!("P2P QUIC reader: channel closed, exiting");
                            break;
                        }
                    }
                    Err(e) => {
                        let stats = read_conn.stats();
                        error!(
                            "P2P QUIC connection died: {}. \
                             Stats: mtu={}, mds={:?}, rtt={:?}, \
                             sent_pkts={}, lost_pkts={}, lost_bytes={}, \
                             pmtud_sent={}, pmtud_lost={}, black_holes={}, \
                             datagrams_tx={}, datagrams_rx={}",
                            e,
                            stats.path.current_mtu,
                            read_conn.max_datagram_size(),
                            stats.path.rtt,
                            stats.path.sent_packets,
                            stats.path.lost_packets,
                            stats.path.lost_bytes,
                            stats.path.sent_plpmtud_probes,
                            stats.path.lost_plpmtud_probes,
                            stats.path.black_holes_detected,
                            stats.frame_tx.datagram,
                            stats.frame_rx.datagram,
                        );
                        let _ = tx.send(Err(io::Error::other(format!(
                            "QUIC read_datagram error: {}",
                            e
                        ))));
                        break;
                    }
                }
            }
        });
        // Periodic path-stats diagnostic (debug-level): rtt climbing and
        // lost_pkts accruing under a sustained transfer is the bufferbloat /
        // congestion-collapse signature. Per-2s deltas for datagrams/loss;
        // stops when the connection closes. Enable with
        // `RUST_LOG=spora_core::transport::quic=debug`.
        let stats_conn = conn.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            let (mut last_tx, mut last_rx, mut last_lost) = (0u64, 0u64, 0u64);
            loop {
                tick.tick().await;
                if stats_conn.close_reason().is_some() {
                    break;
                }
                let s = stats_conn.stats();
                let (txd, rxd, lost) =
                    (s.frame_tx.datagram, s.frame_rx.datagram, s.path.lost_packets);
                debug!(
                    "QUIC path stats: rtt={:?} cwnd={} mtu={} mds={:?} | \
                     datagrams tx={} (+{}) rx={} (+{}) | lost_pkts={} (+{}) black_holes={}",
                    s.path.rtt,
                    s.path.cwnd,
                    s.path.current_mtu,
                    stats_conn.max_datagram_size(),
                    txd,
                    txd.saturating_sub(last_tx),
                    rxd,
                    rxd.saturating_sub(last_rx),
                    lost,
                    lost.saturating_sub(last_lost),
                    s.path.black_holes_detected,
                );
                last_tx = txd;
                last_rx = rxd;
                last_lost = lost;
            }
        });

        Self {
            rx,
            conn,
            ip_id_ctr: AtomicU16::new(0),
            _reader: reader,
        }
    }
}

impl Stream for QuicPeerTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for QuicPeerTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        // A QUIC datagram can't carry more than `max_datagram_size` bytes. Our
        // tunnel MTU (that size) is necessarily a bit below the real path MTU,
        // so a peer that NATs traffic for the other side can produce IP packets
        // larger than it — most importantly inbound UDP datagrams (HTTP/3,
        // QUIC, large DNS), which can't be MSS-clamped the way TCP is. Rather
        // than silently dropping those (which blackholes whole protocols), we
        // IPv4-fragment them so the receiving peer's kernel reassembles.
        match self.conn.max_datagram_size() {
            Some(max) if item.len() > max => {
                let ip_id = self.ip_id_ctr.fetch_add(1, Ordering::Relaxed);
                match fragment_ipv4(&item, max, ip_id) {
                    Some(frags) => {
                        for frag in frags {
                            send_datagram_logged(&self.conn, frag)?;
                        }
                        Ok(())
                    }
                    None => {
                        // Not IPv4 (or unfragmentable) and too large — nothing
                        // we can do but drop. IPv6 would need an ICMPv6 PTB.
                        warn!(
                            "dropping oversized unfragmentable datagram: {} bytes > max {}",
                            item.len(),
                            max
                        );
                        Ok(())
                    }
                }
            }
            _ => send_datagram_logged(&self.conn, item),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.conn.close(0u32.into(), b"close");
        Poll::Ready(Ok(()))
    }
}

impl Drop for QuicPeerTransport {
    fn drop(&mut self) {
        // Close the QUIC connection when this transport goes away — on a
        // direct-upgrade swap (the old relay-via halves are dropped by the
        // transport router), share-side session replacement, or client
        // reconnect. Without this the connection lingers forever: keep-alive
        // (10s) holds it under the 30s idle timeout, and the detached reader and
        // stats tasks each keep a `Connection` clone, so quinn's
        // drop-last-handle auto-close never fires. The orphan then PINGs through
        // the relay for the rest of the process, refreshing its flow entry,
        // waking the mobile radio, and contradicting the documented "old
        // relay-via connection drains and times out". Closing sends
        // CONNECTION_CLOSE and unblocks the reader (`read_datagram` -> Err) and
        // stats (`close_reason()` -> Some) tasks so they exit and release the
        // connection.
        self.conn.close(0u32.into(), b"transport dropped");
        self._reader.abort();
    }
}

/// Send one datagram, logging the failure modes. A `TooLarge` here is benign
/// (treated as a drop) — the caller is responsible for keeping datagrams
/// within `max_datagram_size`.
fn send_datagram_logged(conn: &Connection, pkt: Vec<u8>) -> io::Result<()> {
    let pkt_len = pkt.len();
    match conn.send_datagram(pkt.into()) {
        Ok(()) => Ok(()),
        Err(quinn::SendDatagramError::TooLarge) => {
            warn!(
                "P2P QUIC datagram too large: pkt={} bytes, max_datagram_size={:?}",
                pkt_len,
                conn.max_datagram_size(),
            );
            Ok(())
        }
        Err(e) => {
            let stats = conn.stats();
            error!(
                "P2P QUIC send_datagram failed: {}. \
                 Stats: mtu={}, mds={:?}, lost_pkts={}, pmtud_sent={}, pmtud_lost={}",
                e,
                stats.path.current_mtu,
                conn.max_datagram_size(),
                stats.path.lost_packets,
                stats.path.sent_plpmtud_probes,
                stats.path.lost_plpmtud_probes,
            );
            Err(io::Error::other(format!("QUIC send_datagram error: {}", e)))
        }
    }
}

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
fn fragment_ipv4(pkt: &[u8], max_len: usize, ip_id: u16) -> Option<Vec<Vec<u8>>> {
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

/// Standard IPv4 header checksum (ones'-complement sum of 16-bit words).
fn ipv4_header_checksum(header: &[u8]) -> u16 {
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

/// Build the shared QUIC transport config. `idle_timeout` / `keep_alive`
/// come from [`crate::Timings`] (defaults: 30s / 10s).
pub fn build_transport_config(idle_timeout: Duration, keep_alive: Duration) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(idle_timeout.try_into().unwrap()));
    transport.keep_alive_interval(Some(keep_alive));
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.initial_mtu(1200);
    transport.min_mtu(1200);
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    // A non-trivial cooldown so congestion loss isn't repeatedly misread as an
    // MTU black hole (0s churned the MTU under load).
    mtud.black_hole_cooldown(std::time::Duration::from_secs(30));
    transport.mtu_discovery_config(Some(mtud));
    // BBR — it paces datagrams to the estimated bottleneck bandwidth. We carry
    // IP packets as QUIC datagrams; the previous NoopCc paced nothing (infinite
    // window), so the share-side smoltcp download sender — which, unlike a
    // kernel TCP, does not pace — burst the path into ~10% self-inflicted loss
    // and congestion collapse (download decayed to a fraction of upload). BBR's
    // pacing gives the inner TCP a clean, low-loss pipe; doing congestion
    // control at the tunnel layer (rather than leaning on the inner TCP's,
    // which over a lossless-until-overflow datagram channel gets no clean
    // signal) is the correct shape for a TCP-carrying tunnel.
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid IPv4/UDP packet with `payload_len` bytes of UDP payload.
    fn ipv4_udp(payload_len: usize) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(1234, 5678)
            .write(&mut pkt, &vec![0xABu8; payload_len])
            .unwrap();
        pkt
    }

    /// Reassemble IPv4 fragments back into the original payload bytes, checking
    /// offsets and the MF flag. Returns (reassembled_payload, header_ihl).
    fn reassemble(frags: &[Vec<u8>]) -> Vec<u8> {
        // Order by fragment offset.
        let mut ordered: Vec<&Vec<u8>> = frags.iter().collect();
        ordered.sort_by_key(|f| u16::from_be_bytes([f[6], f[7]]) & 0x1fff);

        let mut out = Vec::new();
        for (i, f) in ordered.iter().enumerate() {
            assert_eq!(f[0] >> 4, 4, "fragment is IPv4");
            let ihl = ((f[0] & 0x0f) as usize) * 4;
            let total = u16::from_be_bytes([f[2], f[3]]) as usize;
            assert_eq!(total, f.len(), "total length matches buffer");
            let mf = (u16::from_be_bytes([f[6], f[7]]) & 0x2000) != 0;
            let off_units = (u16::from_be_bytes([f[6], f[7]]) & 0x1fff) as usize;
            assert_eq!(off_units * 8, out.len(), "fragment offset is contiguous");
            // DF must be cleared on fragments.
            assert_eq!(u16::from_be_bytes([f[6], f[7]]) & 0x4000, 0, "DF cleared");
            // Header checksum must be valid (sum including checksum == 0xffff).
            assert_eq!(ipv4_header_checksum(&f[..ihl]), 0, "valid header checksum");
            let is_last = i == ordered.len() - 1;
            assert_eq!(mf, !is_last, "MF set on all but the last fragment");
            out.extend_from_slice(&f[ihl..]);
        }
        out
    }

    #[test]
    fn fragments_oversized_ipv4_and_reassembles() {
        // 1452-byte UDP payload -> 1480-byte IP packet; tunnel max 1414.
        let pkt = ipv4_udp(1452);
        assert_eq!(pkt.len(), 1480);
        let max = 1414;

        let frags = fragment_ipv4(&pkt, max, 0x4242).expect("should fragment");
        assert!(frags.len() >= 2, "should split into multiple fragments");
        for f in &frags {
            assert!(f.len() <= max, "fragment {} exceeds max {}", f.len(), max);
        }
        // Reassembled IP payload (everything after the 20-byte header) matches.
        assert_eq!(reassemble(&frags), pkt[20..]);
    }

    #[test]
    fn fragments_carry_the_given_ip_id() {
        // All fragments of one datagram share the caller-provided id (so the
        // receiver groups them), and the caller varies it per datagram so
        // distinct datagrams don't collide under id=0 in reassembly.
        let pkt = ipv4_udp(3000);
        for id in [0x0001u16, 0xABCD, 0xFFFF] {
            let frags = fragment_ipv4(&pkt, 1414, id).unwrap();
            assert!(frags.len() >= 2);
            for f in &frags {
                assert_eq!(u16::from_be_bytes([f[4], f[5]]), id, "fragment must carry id {id:#x}");
            }
        }
    }

    #[test]
    fn fragment_data_is_multiple_of_eight() {
        let pkt = ipv4_udp(3000);
        let frags = fragment_ipv4(&pkt, 1414, 0x4242).unwrap();
        // Every fragment but the last carries a data length that's a multiple
        // of 8 (an IPv4 fragmentation requirement).
        for f in &frags[..frags.len() - 1] {
            let ihl = ((f[0] & 0x0f) as usize) * 4;
            assert_eq!((f.len() - ihl) % 8, 0);
        }
        assert_eq!(reassemble(&frags), pkt[20..]);
    }

    #[test]
    fn fitting_packet_yields_single_reassemblable_fragment() {
        // A payload that fits in one fragment yields exactly one fragment that
        // reassembles to the original IP payload. (In production
        // `fragment_ipv4` is only called on oversized packets, so this is the
        // degenerate single-chunk case; DF is cleared and the checksum is
        // recomputed, so it's not byte-identical to the input.)
        let pkt = ipv4_udp(100);
        let frags = fragment_ipv4(&pkt, 1414, 0x4242).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(reassemble(&frags), pkt[20..]);
    }

    #[test]
    fn non_ipv4_returns_none() {
        // IPv6 version nibble.
        let pkt = vec![0x60u8; 100];
        assert!(fragment_ipv4(&pkt, 1414, 0x4242).is_none());
        // Too short to be IPv4.
        assert!(fragment_ipv4(&[0x45, 0x00], 1414, 0x4242).is_none());
    }

    #[test]
    fn tiny_max_len_returns_none() {
        let pkt = ipv4_udp(1000);
        // Can't fit header + 8 bytes.
        assert!(fragment_ipv4(&pkt, 20, 0x4242).is_none());
    }

    #[test]
    fn checksum_matches_etherparse() {
        // etherparse already wrote a correct checksum; ours must agree.
        let pkt = ipv4_udp(40);
        let expected = u16::from_be_bytes([pkt[10], pkt[11]]);
        let mut hdr = pkt[..20].to_vec();
        hdr[10] = 0;
        hdr[11] = 0;
        assert_eq!(ipv4_header_checksum(&hdr), expected);
    }

    // --- Integration: fragmentation over a real QUIC connection ---

    /// Accept any server cert — only for the loopback test pair below.
    #[derive(Debug)]
    struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _s: &rustls::pki_types::ServerName<'_>,
            _o: &[u8],
            _n: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Transport config with a fixed 1200-byte MTU and PMTUD disabled, so
    /// `max_datagram_size` stays small and deterministic.
    fn fixed_small_mtu_config() -> quinn::TransportConfig {
        let mut t = quinn::TransportConfig::default();
        t.initial_mtu(1200);
        t.min_mtu(1200);
        t.mtu_discovery_config(None);
        t.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
        t.datagram_send_buffer_size(8 * 1024 * 1024);
        t.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
        t
    }

    async fn loopback_pair() -> (QuicPeerTransport, QuicPeerTransport) {
        const ALPN: &[u8] = b"frag-test";
        let (cert, key, _fp) = generate_self_signed_cert();

        let mut sc = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        sc.alpn_protocols = vec![ALPN.to_vec()];
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(sc).unwrap(),
        ));
        server_config.transport_config(Arc::new(fixed_small_mtu_config()));
        let server_ep =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cc = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth();
        cc.alpn_protocols = vec![ALPN.to_vec()];
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(cc).unwrap(),
        ));
        client_config.transport_config(Arc::new(fixed_small_mtu_config()));
        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_ep.set_default_client_config(client_config);

        let connecting = client_ep.connect(server_addr, "spora.peer").unwrap();
        let (server_conn, client_conn) = tokio::join!(
            async { server_ep.accept().await.unwrap().await.unwrap() },
            async { connecting.await.unwrap() },
        );
        // Endpoints must outlive the connections for the lifetime of the test.
        Box::leak(Box::new(server_ep));
        Box::leak(Box::new(client_ep));
        (
            QuicPeerTransport::new(server_conn),
            QuicPeerTransport::new(client_conn),
        )
    }

    #[tokio::test]
    async fn oversized_ipv4_fragments_over_real_connection() {
        use futures_util::{SinkExt, StreamExt};

        let (mut a, mut b) = loopback_pair().await;

        let mds = a.max_datagram_size().expect("mds known after handshake");
        // Sanity: our fixed config keeps the tunnel MTU well under the packet.
        assert!(mds < 1400, "expected small mds, got {}", mds);

        // A 3000-byte IPv4/UDP packet — far larger than one datagram.
        let pkt = ipv4_udp(3000 - 28);
        assert_eq!(pkt.len(), 3000);
        a.send(pkt.clone()).await.unwrap();

        // Collect the fragments B receives (each a separate datagram) and
        // reassemble them. QUIC datagrams are unordered; reassemble() sorts.
        let mut frags: Vec<Vec<u8>> = Vec::new();
        let mut reassembled = 0usize;
        while reassembled < pkt.len() - 20 {
            let frag = tokio::time::timeout(Duration::from_secs(2), b.next())
                .await
                .expect("fragment should arrive")
                .expect("stream open")
                .expect("no transport error");
            assert!(frag.len() <= mds, "fragment {} exceeds mds {}", frag.len(), mds);
            reassembled += frag.len() - ((frag[0] & 0x0f) as usize) * 4;
            frags.push(frag);
        }
        assert!(frags.len() >= 2, "packet should have been split");
        assert_eq!(reassemble(&frags), pkt[20..], "fragments reassemble to original");
    }

    // Dropping a QuicPeerTransport must close its connection, so a superseded
    // relay-via connection doesn't linger and keep PINGing through the relay.
    #[tokio::test]
    async fn dropping_transport_closes_the_connection() {
        use futures_util::StreamExt;

        let (server, mut client) = loopback_pair().await;
        // Hold a clone of the server connection to observe its state after drop.
        let server_conn = server.connection();
        assert!(server_conn.close_reason().is_none(), "open before drop");

        drop(server);

        // Local effect: the server side records the close immediately.
        assert!(
            server_conn.close_reason().is_some(),
            "dropping the transport must close its connection"
        );

        // Peer effect: the client observes the connection ending (its datagram
        // stream errors/ends) rather than the connection lingering on keep-alive.
        let ended = tokio::time::timeout(Duration::from_secs(2), client.next()).await;
        match ended {
            Ok(Some(Err(_))) | Ok(None) => {} // errored or closed — both fine
            Ok(Some(Ok(_))) => panic!("expected the connection to close, got a datagram"),
            Err(_) => panic!("client did not observe the connection closing"),
        }
    }
}
