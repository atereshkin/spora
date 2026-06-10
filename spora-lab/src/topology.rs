//! Topology builder: a wan **router** namespace + per-side peer/gateway
//! namespaces on point-to-point /30 legs.
//!
//! ```text
//! [client ns] ── veth ── [natB ns] ──/30 leg──┐
//!                                             [wan ns: ROUTER, ip_forward=1]
//! [sharer ns] ── veth ── [natA ns] ──/30 leg──┘   svc0 dummy: 203.0.113.100/32
//! ```
//!
//! The wan hub is deliberately a router, NOT a bridge: bridged traffic
//! bypasses iptables FORWARD without br_netfilter (unloadable from a userns),
//! which would break the netem/nth-loss/block knobs, and routed legs give
//! per-hop MTU + ICMP frag-needed semantics for PMTUD tests.
//!
//! Implementation contract:
//! - All `ip`/`tc`/`iptables` invocations go through [`crate::netns::Netns`].
//! - Namespace and interface names must embed a unique per-topology id
//!   (interface names ≤ 15 chars) so sequential scenarios never collide:
//!   namespaces `lab<ID>-wan`, `lab<ID>-shr`, `lab<ID>-cli`, `lab<ID>-na`,
//!   `lab<ID>-nb` (+ `lab<ID>-nb2` when `client_alt_gateway`); the id comes
//!   from a process-wide `AtomicUsize`.
//! - wan ns: `net.ipv4.ip_forward=1`; a dummy interface `svc0` carrying
//!   `203.0.113.100/32` ([`crate::WAN_SERVICES_IP`]) where services bind.
//!   Addressing of the /30 legs inside 203.0.113.0/24 (wan side first):
//!   A leg `.1/.2`, B leg `.5/.6`, B2 leg `.9/.10`, open-sharer leg
//!   `.13/.14`, open-client leg `.17/.18`. wan-side leg devices are named
//!   `wa<ID>`, `wb<ID>`, `wb2<ID>`, `ws<ID>`, `wc<ID>` — netem/MTU knobs
//!   attach to these; the far end inside a gateway/open-peer ns is always
//!   named `wan0`.
//! - A side with `NatKind::Open`: the peer namespace gets the leg directly
//!   (e.g. sharer ns owns `wan0` = 203.0.113.14/30, `default via .13`).
//! - A NATed side: gateway ns owns the leg (`wan0`, e.g. 203.0.113.2/30,
//!   `default via .1`) plus a LAN veth `lan0` (`192.168.1.1/24` A side,
//!   `192.168.2.1/24` B side); peer ns gets `lan0` at `.2` with
//!   `default via .1`; `net.ipv4.ip_forward=1` in the gateway (write
//!   `/proc/sys/net/ipv4/ip_forward` via `sh -c` inside the ns); NAT rules
//!   per [`crate::nat::apply_nat`]. The wan router needs NO routes to the
//!   LANs (masquerade hides them).
//! - `client_alt_gateway`: a second gateway ns (same NatKind) at
//!   `192.168.2.3` on the client LAN, wan leg B2, pre-built but unused until
//!   [`Topology::switch_client_gateway`] flips the client's default route —
//!   the roaming primitive (old conntrack state stays on the old gateway).
//!   Mechanically the client gets a second veth `lan1` carrying the same
//!   `192.168.2.2` as a /32 plus a host route to `.3`, so flipping the
//!   default route is the only roaming step.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::nat::apply_nat;
use crate::netns::Netns;
use crate::{NatKind, WAN_SERVICES_IP};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

pub struct TopologySpec {
    pub sharer: NatKind,
    pub client: NatKind,
    /// Build a second client-side gateway for roaming scenarios.
    pub client_alt_gateway: bool,
}

impl TopologySpec {
    pub fn new(sharer: NatKind, client: NatKind) -> Self {
        Self { sharer, client, client_alt_gateway: false }
    }
}

pub struct Topology {
    pub wan: Netns,
    pub sharer: Netns,
    pub client: Netns,
    pub nat_a: Option<Netns>,
    pub nat_b: Option<Netns>,
    pub nat_b2: Option<Netns>,
    /// wan-side device names of the sharer-side and client-side legs —
    /// attach netem / MTU here. The matching far end inside the gateway
    /// (or open peer) namespace is always `wan0`.
    pub wan_if_a: String,
    pub wan_if_b: String,
    /// External (wan-facing) IPv4 of each side: the gateway's leg address,
    /// or the peer's own when Open.
    pub ext_ip_a: std::net::Ipv4Addr,
    pub ext_ip_b: std::net::Ipv4Addr,
    pub id: usize,
}

impl Topology {
    /// Build namespaces, veths, addresses, routes, forwarding and NAT rules
    /// per the spec. Must be fully torn down by dropping (namespaces delete
    /// their veths with them).
    pub fn build(spec: &TopologySpec) -> Result<Topology, String> {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let wan = Netns::add(&format!("lab{id}-wan"))?;
        let sharer = Netns::add(&format!("lab{id}-shr"))?;
        let client = Netns::add(&format!("lab{id}-cli"))?;

        enable_ip_forward(&wan)?;
        wan.run("ip link add svc0 type dummy")?;
        wan.run(&format!("ip addr add {WAN_SERVICES_IP}/32 dev svc0"))?;
        wan.run("ip link set svc0 up")?;

        let (wan_if_a, ext_ip_a, nat_a) = match spec.sharer {
            NatKind::Open => {
                let dev = format!("ws{id}");
                leg(&wan, &sharer, &dev, "203.0.113.13", "203.0.113.14")?;
                (dev, Ipv4Addr::new(203, 0, 113, 14), None)
            }
            kind => {
                let dev = format!("wa{id}");
                let gw = nat_side(
                    &wan,
                    &format!("lab{id}-na"),
                    &sharer,
                    kind,
                    &dev,
                    ("203.0.113.1", "203.0.113.2"),
                    "192.168.1",
                )?;
                (dev, Ipv4Addr::new(203, 0, 113, 2), Some(gw))
            }
        };

        let (wan_if_b, ext_ip_b, nat_b) = match spec.client {
            NatKind::Open => {
                let dev = format!("wc{id}");
                leg(&wan, &client, &dev, "203.0.113.17", "203.0.113.18")?;
                (dev, Ipv4Addr::new(203, 0, 113, 18), None)
            }
            kind => {
                let dev = format!("wb{id}");
                let gw = nat_side(
                    &wan,
                    &format!("lab{id}-nb"),
                    &client,
                    kind,
                    &dev,
                    ("203.0.113.5", "203.0.113.6"),
                    "192.168.2",
                )?;
                (dev, Ipv4Addr::new(203, 0, 113, 6), Some(gw))
            }
        };

        let nat_b2 = if spec.client_alt_gateway {
            if spec.client == NatKind::Open {
                return Err("client_alt_gateway requires a NATed client side".into());
            }
            Some(alt_client_gateway(&wan, &client, spec.client, id)?)
        } else {
            None
        };

        Ok(Topology {
            wan,
            sharer,
            client,
            nat_a,
            nat_b,
            nat_b2,
            wan_if_a,
            wan_if_b,
            ext_ip_a,
            ext_ip_b,
            id,
        })
    }

    /// Point the client's default route at the alt gateway (requires
    /// `client_alt_gateway`). Simulates a network change mid-session.
    pub fn switch_client_gateway(&self) -> Result<(), String> {
        if self.nat_b2.is_none() {
            return Err("topology was built without client_alt_gateway".into());
        }
        self.client
            .run("ip route replace default via 192.168.2.3 dev lan1")?;
        Ok(())
    }
}

/// One /30 point-to-point leg: a veth pair created inside the wan ns (device
/// `wan_dev`, which stays there), far end moved to `far` and renamed `wan0`,
/// with addresses, link-up, and the far side's default route via the wan.
fn leg(wan: &Netns, far: &Netns, wan_dev: &str, wan_ip: &str, far_ip: &str) -> Result<(), String> {
    let tmp = format!("p{wan_dev}");
    wan.run(&format!("ip link add {wan_dev} type veth peer name {tmp}"))?;
    wan.run(&format!("ip link set {tmp} netns {}", far.name()))?;
    wan.run(&format!("ip addr add {wan_ip}/30 dev {wan_dev}"))?;
    wan.run(&format!("ip link set {wan_dev} up"))?;
    far.run(&format!("ip link set {tmp} name wan0"))?;
    far.run(&format!("ip addr add {far_ip}/30 dev wan0"))?;
    far.run("ip link set wan0 up")?;
    far.run(&format!("ip route add default via {wan_ip}"))?;
    Ok(())
}

/// A NATed side: gateway namespace with its wan leg, a LAN veth to the peer
/// (`<lan>.1` gateway / `<lan>.2` peer), forwarding, and NAT rules.
fn nat_side(
    wan: &Netns,
    gw_name: &str,
    peer: &Netns,
    kind: NatKind,
    wan_dev: &str,
    leg_ips: (&str, &str),
    lan: &str,
) -> Result<Netns, String> {
    let gw = Netns::add(gw_name)?;
    leg(wan, &gw, wan_dev, leg_ips.0, leg_ips.1)?;
    enable_ip_forward(&gw)?;

    let tmp = format!("l{wan_dev}");
    gw.run(&format!("ip link add lan0 type veth peer name {tmp}"))?;
    gw.run(&format!("ip link set {tmp} netns {}", peer.name()))?;
    gw.run(&format!("ip addr add {lan}.1/24 dev lan0"))?;
    gw.run("ip link set lan0 up")?;
    peer.run(&format!("ip link set {tmp} name lan0"))?;
    peer.run(&format!("ip addr add {lan}.2/24 dev lan0"))?;
    peer.run("ip link set lan0 up")?;
    peer.run(&format!("ip route add default via {lan}.1"))?;

    let lan_host: Ipv4Addr = format!("{lan}.2")
        .parse()
        .map_err(|e| format!("lan host addr: {e}"))?;
    apply_nat(&gw, kind, "wan0", lan_host)?;
    Ok(gw)
}

/// The roaming alt gateway: wan leg B2, LAN presence at 192.168.2.3, and a
/// second client veth `lan1` carrying 192.168.2.2/32 + a host route to .3.
fn alt_client_gateway(
    wan: &Netns,
    client: &Netns,
    kind: NatKind,
    id: usize,
) -> Result<Netns, String> {
    let gw = Netns::add(&format!("lab{id}-nb2"))?;
    let dev = format!("wb2{id}");
    leg(wan, &gw, &dev, "203.0.113.9", "203.0.113.10")?;
    enable_ip_forward(&gw)?;

    let tmp = format!("l{dev}");
    gw.run(&format!("ip link add lan0 type veth peer name {tmp}"))?;
    gw.run(&format!("ip link set {tmp} netns {}", client.name()))?;
    gw.run("ip addr add 192.168.2.3/24 dev lan0")?;
    gw.run("ip link set lan0 up")?;
    client.run(&format!("ip link set {tmp} name lan1"))?;
    client.run("ip addr add 192.168.2.2/32 dev lan1")?;
    client.run("ip link set lan1 up")?;
    client.run("ip route add 192.168.2.3/32 dev lan1")?;

    apply_nat(&gw, kind, "wan0", Ipv4Addr::new(192, 168, 2, 2))?;
    Ok(gw)
}

fn enable_ip_forward(ns: &Netns) -> Result<(), String> {
    let out = ns
        .command("sh")
        .args(["-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"])
        .output()
        .map_err(|e| format!("[ns {}] spawn sh: {e}", ns.name()))?;
    if !out.status.success() {
        return Err(format!(
            "[ns {}] enable ip_forward: {}",
            ns.name(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
