//! spora-lab: network-namespace e2e test lab for spora.
//!
//! See docs/lab.md for the architecture. In short: each test suite
//! (`tests/*.rs`, `harness = false`) enters an unprivileged user namespace
//! plus private mount/net namespaces via [`harness::lab_main`], builds
//! topologies of named network namespaces connected by veths with real
//! iptables NAT, and runs the production sharer/client/relay **in-process**,
//! one pinned OS thread + current-thread tokio runtime per simulated host.

pub mod harness;
pub mod metrics;
pub mod nat;
pub mod netem;
pub mod netns;
pub mod peers;
pub mod services;
pub mod topology;
pub mod traffic;

/// NAT flavor for a peer's gateway namespace, in RFC 4787 terms.
///
/// `PortRestricted` is what plain Linux `MASQUERADE` gives (endpoint-
/// independent mapping thanks to port preservation, address+port-dependent
/// filtering via conntrack). `Symmetric` is `MASQUERADE --random-fully`
/// (endpoint-dependent mapping). `FullCone` adds a catch-all `DNAT` to the
/// single LAN host (endpoint-independent filtering). `Open` gives the peer
/// its own wan leg with a public address — no gateway at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    Open,
    FullCone,
    PortRestricted,
    Symmetric,
}

impl NatKind {
    /// Whether spora's hole punch is expected to succeed for a pairing.
    /// `punch_and_verify` only accepts packets from the *signaled* address,
    /// so any side with endpoint-dependent mapping (Symmetric) breaks the
    /// punch in both directions, full-cone filtering notwithstanding.
    pub fn punchable_with(self, other: NatKind) -> bool {
        self != NatKind::Symmetric && other != NatKind::Symmetric
    }
}

/// The lab "internet": TEST-NET-3, chosen because the share-side netstack's
/// `is_local_address` blocklist (RFC1918, CGNAT, loopback, link-local, ...)
/// does not match it, so tunneled traffic may exit toward it.
pub const WAN_SUBNET: &str = "203.0.113.0/24";
/// Address inside the wan namespace hosting relay/STUN/echo services.
pub const WAN_SERVICES_IP: &str = "203.0.113.100";

pub const RELAY_PORT: u16 = 4000;
pub const STUN_PORT: u16 = 3478;
pub const ECHO_UDP_PORT: u16 = 7;
/// UDP service replying with the observed source `ip:port` as ASCII —
/// used by smoke tests to verify NAT mapping behavior.
pub const WHOAMI_UDP_PORT: u16 = 7001;
pub const ECHO_TCP_PORT: u16 = 7002;
/// Bulk TCP source (download) / sink (upload) services for one-directional
/// throughput measurement; defined next to the other extra wan services.
pub use services::{TCP_SINK_PORT, TCP_SOURCE_PORT};

/// Inner (tunneled) source address the lab client crafts packets from.
pub const CLIENT_INNER_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 200, 0, 2);
