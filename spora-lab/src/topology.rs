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

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::nat::{apply_nat, apply_nat6};
use crate::netns::Netns;
use crate::{NatKind, WAN_SERVICES_IP, WAN_SERVICES_IP6};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// IPv6 /64 wan legs (inside [`crate::WAN_SUBNET6`], wan side `::1`, far side
/// `::2`) and ULA LAN prefixes — the v6 twins of the hardcoded v4 plan above.
const LEG6_A: &str = "2001:db8:0:a";
const LEG6_B: &str = "2001:db8:0:b";
const LEG6_B2: &str = "2001:db8:0:f";
const LEG6_OPEN_SHARER: &str = "2001:db8:0:5a";
const LEG6_OPEN_CLIENT: &str = "2001:db8:0:5c";
const LAN6_A: &str = "fd00:1";
const LAN6_B: &str = "fd00:2";

/// `Firewalled` LANs are ROUTABLE (no translation hides them): TEST-NET-2
/// halves for v4 (gw `.1`/`.129`, peer `.2`/`.130`), documentation-prefix
/// /64s for v6 (gw `::1`, peer `::2`). The wan router gets an explicit
/// return route per LAN, which masquerade would otherwise make unnecessary.
const FW_LAN_A: (&str, &str, &str) = ("198.51.100.0/25", "198.51.100.1", "198.51.100.2");
const FW_LAN_B: (&str, &str, &str) = ("198.51.100.128/25", "198.51.100.129", "198.51.100.130");
const FW_LAN6_A: &str = "2001:db8:0:1a";
const FW_LAN6_B: &str = "2001:db8:0:1b";

pub struct TopologySpec {
    pub sharer: NatKind,
    pub client: NatKind,
    /// Build a second client-side gateway for roaming scenarios.
    pub client_alt_gateway: bool,
    /// Dual-stack the topology: v6 addresses (documentation-prefix wan legs,
    /// ULA LANs) on the same veths, v6 forwarding, ip6tables NAT recipes,
    /// and a v6 service address on svc0. The v4 plan is unchanged, so a
    /// dual-stack topology runs every existing scenario identically.
    pub ipv6: bool,
}

impl TopologySpec {
    pub fn new(sharer: NatKind, client: NatKind) -> Self {
        Self {
            sharer,
            client,
            client_alt_gateway: false,
            ipv6: false,
        }
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
    /// or the peer's own address when Open or Firewalled (no translation).
    pub ext_ip_a: std::net::Ipv4Addr,
    pub ext_ip_b: std::net::Ipv4Addr,
    /// External (wan-facing) IPv6 of each side; `Some` iff built with
    /// `ipv6: true`.
    pub ext_ip6_a: Option<Ipv6Addr>,
    pub ext_ip6_b: Option<Ipv6Addr>,
    /// Whether the topology was built dual-stack (`TopologySpec::ipv6`).
    ipv6: bool,
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
        if spec.ipv6 {
            wan.run(&format!(
                "ip addr add {WAN_SERVICES_IP6}/128 dev svc0 nodad"
            ))?;
        }
        wan.run("ip link set svc0 up")?;

        let (wan_if_a, ext_ip_a, ext_ip6_a, nat_a) = match spec.sharer {
            NatKind::Open => {
                let dev = format!("ws{id}");
                leg(&wan, &sharer, &dev, "203.0.113.13", "203.0.113.14")?;
                let ip6 = if spec.ipv6 {
                    Some(leg6(&wan, &sharer, &dev, LEG6_OPEN_SHARER)?)
                } else {
                    None
                };
                (dev, Ipv4Addr::new(203, 0, 113, 14), ip6, None)
            }
            NatKind::Firewalled => {
                let dev = format!("wa{id}");
                let (gw, ext) = firewalled_side(
                    &wan,
                    &format!("lab{id}-na"),
                    &sharer,
                    &dev,
                    ("203.0.113.1", "203.0.113.2"),
                    FW_LAN_A,
                )?;
                let ip6 = if spec.ipv6 {
                    Some(firewalled_side6(
                        &wan, &gw, &sharer, &dev, LEG6_A, FW_LAN6_A,
                    )?)
                } else {
                    None
                };
                (dev, ext, ip6, Some(gw))
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
                let ip6 = if spec.ipv6 {
                    Some(nat_side6(&wan, &gw, &sharer, kind, &dev, LEG6_A, LAN6_A)?)
                } else {
                    None
                };
                (dev, Ipv4Addr::new(203, 0, 113, 2), ip6, Some(gw))
            }
        };

        let (wan_if_b, ext_ip_b, ext_ip6_b, nat_b) = match spec.client {
            NatKind::Open => {
                let dev = format!("wc{id}");
                leg(&wan, &client, &dev, "203.0.113.17", "203.0.113.18")?;
                let ip6 = if spec.ipv6 {
                    Some(leg6(&wan, &client, &dev, LEG6_OPEN_CLIENT)?)
                } else {
                    None
                };
                (dev, Ipv4Addr::new(203, 0, 113, 18), ip6, None)
            }
            NatKind::Firewalled => {
                let dev = format!("wb{id}");
                let (gw, ext) = firewalled_side(
                    &wan,
                    &format!("lab{id}-nb"),
                    &client,
                    &dev,
                    ("203.0.113.5", "203.0.113.6"),
                    FW_LAN_B,
                )?;
                let ip6 = if spec.ipv6 {
                    Some(firewalled_side6(
                        &wan, &gw, &client, &dev, LEG6_B, FW_LAN6_B,
                    )?)
                } else {
                    None
                };
                (dev, ext, ip6, Some(gw))
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
                let ip6 = if spec.ipv6 {
                    Some(nat_side6(&wan, &gw, &client, kind, &dev, LEG6_B, LAN6_B)?)
                } else {
                    None
                };
                (dev, Ipv4Addr::new(203, 0, 113, 6), ip6, Some(gw))
            }
        };

        let nat_b2 = if spec.client_alt_gateway {
            if !matches!(
                spec.client,
                NatKind::FullCone | NatKind::PortRestricted | NatKind::Symmetric
            ) {
                return Err("client_alt_gateway requires a NATed client side".into());
            }
            let gw = alt_client_gateway(&wan, &client, spec.client, id)?;
            if spec.ipv6 {
                alt_client_gateway6(&wan, &gw, &client, spec.client, id)?;
            }
            Some(gw)
        } else {
            None
        };

        if spec.ipv6 {
            svc_source_hints(&wan, id, spec)?;
        }

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
            ext_ip6_a,
            ext_ip6_b,
            ipv6: spec.ipv6,
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
        if self.ipv6 {
            self.client.run(&format!(
                "ip -6 route replace default via {LAN6_B}::3 dev lan1"
            ))?;
        }
        Ok(())
    }
}

/// Dual-stack an existing leg: v6 addresses on the same veth pair (`nodad` —
/// fresh netns DAD would leave the address tentative for ~1s, failing binds)
/// plus the far side's v6 default route. `prefix` is the /64 (wan `::1`,
/// far `::2`). Returns the far side's address.
fn leg6(wan: &Netns, far: &Netns, wan_dev: &str, prefix: &str) -> Result<Ipv6Addr, String> {
    wan.run(&format!(
        "ip -6 addr add {prefix}::1/64 dev {wan_dev} nodad"
    ))?;
    far.run(&format!("ip -6 addr add {prefix}::2/64 dev wan0 nodad"))?;
    far.run(&format!("ip -6 route add default via {prefix}::1"))?;
    format!("{prefix}::2")
        .parse()
        .map_err(|e| format!("leg6 far addr: {e}"))
}

/// Dual-stack an existing NATed side (built by [`nat_side`]): v6 on the wan
/// leg, a ULA LAN on the existing `lan0` veths, the peer's v6 default route,
/// and the ip6tables NAT recipe. Returns the gateway's external v6 address.
fn nat_side6(
    wan: &Netns,
    gw: &Netns,
    peer: &Netns,
    kind: NatKind,
    wan_dev: &str,
    leg_prefix: &str,
    lan_prefix: &str,
) -> Result<Ipv6Addr, String> {
    let ext = leg6(wan, gw, wan_dev, leg_prefix)?;
    gw.run(&format!("ip -6 addr add {lan_prefix}::1/64 dev lan0 nodad"))?;
    peer.run(&format!("ip -6 addr add {lan_prefix}::2/64 dev lan0 nodad"))?;
    peer.run(&format!("ip -6 route add default via {lan_prefix}::1"))?;
    let lan_host: Ipv6Addr = format!("{lan_prefix}::2")
        .parse()
        .map_err(|e| format!("lan6 host addr: {e}"))?;
    apply_nat6(gw, kind, "wan0", lan_host)?;
    Ok(ext)
}

/// A `Firewalled` side: structurally a [`nat_side`] (gateway ns, wan leg,
/// LAN veth) but the LAN is ROUTABLE (TEST-NET-2), the gateway applies the
/// RFC 6092 stateful filter instead of masquerade, and the wan router gets
/// an explicit return route (with the service-IP `src` hint the dual-stack
/// relay socket needs — harmless for specifically-bound services). Returns
/// the gateway ns and the peer's own address, which IS the side's external
/// address: nothing translates it.
fn firewalled_side(
    wan: &Netns,
    gw_name: &str,
    peer: &Netns,
    wan_dev: &str,
    leg_ips: (&str, &str),
    lan: (&str, &str, &str),
) -> Result<(Netns, Ipv4Addr), String> {
    let (lan_net, lan_gw, lan_peer) = lan;
    let gw = Netns::add(gw_name)?;
    leg(wan, &gw, wan_dev, leg_ips.0, leg_ips.1)?;
    enable_ip_forward(&gw)?;

    let tmp = format!("l{wan_dev}");
    gw.run(&format!("ip link add lan0 type veth peer name {tmp}"))?;
    gw.run(&format!("ip link set {tmp} netns {}", peer.name()))?;
    gw.run(&format!("ip addr add {lan_gw}/25 dev lan0"))?;
    gw.run("ip link set lan0 up")?;
    peer.run(&format!("ip link set {tmp} name lan0"))?;
    peer.run(&format!("ip addr add {lan_peer}/25 dev lan0"))?;
    peer.run("ip link set lan0 up")?;
    peer.run(&format!("ip route add default via {lan_gw}"))?;

    let ext: Ipv4Addr = lan_peer
        .parse()
        .map_err(|e| format!("fw lan peer addr: {e}"))?;
    apply_nat(&gw, NatKind::Firewalled, "wan0", ext)?;
    wan.run(&format!(
        "ip route add {lan_net} via {} src {WAN_SERVICES_IP}",
        leg_ips.1
    ))?;
    Ok((gw, ext))
}

/// Dual-stack a `Firewalled` side (mirrors [`nat_side6`]): routable
/// documentation-prefix LAN on the existing `lan0` veths, the ip6tables
/// stateful filter, and the wan's v6 return route. Returns the PEER's own
/// v6 address — the side's external address, untranslated.
fn firewalled_side6(
    wan: &Netns,
    gw: &Netns,
    peer: &Netns,
    wan_dev: &str,
    leg_prefix: &str,
    lan_prefix: &str,
) -> Result<Ipv6Addr, String> {
    leg6(wan, gw, wan_dev, leg_prefix)?;
    gw.run(&format!("ip -6 addr add {lan_prefix}::1/64 dev lan0 nodad"))?;
    peer.run(&format!("ip -6 addr add {lan_prefix}::2/64 dev lan0 nodad"))?;
    peer.run(&format!("ip -6 route add default via {lan_prefix}::1"))?;
    let ext: Ipv6Addr = format!("{lan_prefix}::2")
        .parse()
        .map_err(|e| format!("fw lan6 peer addr: {e}"))?;
    apply_nat6(gw, NatKind::Firewalled, "wan0", ext)?;
    wan.run(&format!(
        "ip -6 route add {lan_prefix}::/64 via {leg_prefix}::2 src {WAN_SERVICES_IP6}"
    ))?;
    Ok(ext)
}

/// v6 twin of [`alt_client_gateway`] on the devices it created: wan leg B2,
/// LAN presence at `fd00:2::3`, the client's `fd00:2::2/128` on lan1 plus a
/// host route to `::3` — so [`Topology::switch_client_gateway`] only has to
/// flip the v6 default route.
fn alt_client_gateway6(
    wan: &Netns,
    gw: &Netns,
    client: &Netns,
    kind: NatKind,
    id: usize,
) -> Result<(), String> {
    let dev = format!("wb2{id}");
    leg6(wan, gw, &dev, LEG6_B2)?;
    gw.run(&format!("ip -6 addr add {LAN6_B}::3/64 dev lan0 nodad"))?;
    client.run(&format!("ip -6 addr add {LAN6_B}::2/128 dev lan1 nodad"))?;
    client.run(&format!("ip -6 route add {LAN6_B}::3/128 dev lan1"))?;
    let lan_host: Ipv6Addr = format!("{LAN6_B}::2")
        .parse()
        .map_err(|e| format!("alt lan6 host addr: {e}"))?;
    apply_nat6(gw, kind, "wan0", lan_host)?;
    Ok(())
}

/// Pin the source address of wan-originated traffic on every leg route to
/// the service IPs. The dual-stack relay socket is a wildcard bind (one
/// socket, both families — the production shape), so without an explicit
/// `src` hint the kernel would source its forwards from the leg address
/// (longest-prefix-match wins source selection), which breaks conntrack on
/// the NAT gateways (replies must come from the address the peer sent to)
/// and surprises QUIC. Specific-bound services are unaffected.
fn svc_source_hints(wan: &Netns, id: usize, spec: &TopologySpec) -> Result<(), String> {
    let mut legs: Vec<(String, &str, &str)> = Vec::new();
    match spec.sharer {
        NatKind::Open => legs.push((format!("ws{id}"), "203.0.113.12/30", LEG6_OPEN_SHARER)),
        _ => legs.push((format!("wa{id}"), "203.0.113.0/30", LEG6_A)),
    }
    match spec.client {
        NatKind::Open => legs.push((format!("wc{id}"), "203.0.113.16/30", LEG6_OPEN_CLIENT)),
        _ => legs.push((format!("wb{id}"), "203.0.113.4/30", LEG6_B)),
    }
    if spec.client_alt_gateway {
        legs.push((format!("wb2{id}"), "203.0.113.8/30", LEG6_B2));
    }
    for (dev, net4, prefix6) in legs {
        wan.run(&format!(
            "ip route replace {net4} dev {dev} src {WAN_SERVICES_IP}"
        ))?;
        // v6 routes are keyed by (prefix, metric): without `metric 256` this
        // would ADD a metric-1024 route shadowed by the kernel's connected
        // route instead of replacing it, and the hint would never apply.
        wan.run(&format!(
            "ip -6 route replace {prefix6}::/64 dev {dev} src {WAN_SERVICES_IP6} metric 256"
        ))?;
    }
    Ok(())
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
    // Both families unconditionally: the v6 sysctl always exists and is a
    // no-op for v4-only topologies, so routers/gateways need no flag.
    let out = ns
        .command("sh")
        .args([
            "-c",
            "echo 1 > /proc/sys/net/ipv4/ip_forward && \
             echo 1 > /proc/sys/net/ipv6/conf/all/forwarding",
        ])
        .output()
        .map_err(|e| format!("[ns {}] spawn sh: {e}", ns.name()))?;
    if !out.status.success() {
        return Err(format!(
            "[ns {}] enable ip forwarding: {}",
            ns.name(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
