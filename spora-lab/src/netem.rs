//! Network-condition knobs, applied to wan-side leg interfaces
//! (e.g. [`crate::topology::Topology::wan_if_a`]).
//!
//! Implementation contract:
//! - `netem(ns, dev, spec)`: `tc qdisc replace dev <dev> root netem <spec>`
//!   (e.g. `"delay 100ms 20ms"`, `"loss 5%"`); `clear_netem` removes it.
//!   Note netem shapes traffic *egressing* the device it is attached to —
//!   apply on both ends of a leg for symmetric RTT.
//! - `set_mtu(ns, dev, mtu)`: `ip link set <dev> mtu <mtu>`. For a true
//!   middle-leg MTU constraint set it on both the wan-side device and the
//!   peer veth end facing it.
//! - `nth_packet_loss(ns, every)`: deterministic drop of every Nth *forwarded*
//!   packet in the wan namespace:
//!   `iptables -w -A FORWARD -m statistic --mode nth --every <N> --packet 0 -j DROP`
//!   (netem's probabilistic loss is unseedable; this keeps CI deterministic).
//!   Pairs with [`clear_nth_packet_loss`] (same `every`) to remove the rule.
//! - `block(ns, src_ip, dst_ip)` / `unblock`: targeted
//!   `iptables -w -{A,D} <chain> -s <src> -d <dst> -j DROP` for outage windows
//!   (e.g. cutting a sharer's registrations off from the relay). The rule is
//!   installed in **both** FORWARD and INPUT: traffic that terminates *in*
//!   this namespace (the relay/services live in wan) is delivered locally and
//!   never traverses FORWARD, while transit traffic never traverses INPUT —
//!   covering both chains makes the block direction-complete either way.

use crate::netns::Netns;

pub fn netem(ns: &Netns, dev: &str, spec: &str) -> Result<(), String> {
    ns.run(&format!("tc qdisc replace dev {dev} root netem {spec}"))?;
    Ok(())
}

pub fn clear_netem(ns: &Netns, dev: &str) -> Result<(), String> {
    ns.run(&format!("tc qdisc del dev {dev} root"))?;
    Ok(())
}

pub fn set_mtu(ns: &Netns, dev: &str, mtu: u16) -> Result<(), String> {
    ns.run(&format!("ip link set {dev} mtu {mtu}"))?;
    Ok(())
}

pub fn nth_packet_loss(ns: &Netns, every: u32) -> Result<(), String> {
    ns.run(&format!(
        "iptables -w -A FORWARD -m statistic --mode nth --every {every} --packet 0 -j DROP"
    ))?;
    Ok(())
}

pub fn clear_nth_packet_loss(ns: &Netns, every: u32) -> Result<(), String> {
    ns.run(&format!(
        "iptables -w -D FORWARD -m statistic --mode nth --every {every} --packet 0 -j DROP"
    ))?;
    Ok(())
}

pub fn block(ns: &Netns, src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> Result<(), String> {
    for chain in ["FORWARD", "INPUT"] {
        ns.run(&format!("iptables -w -A {chain} -s {src} -d {dst} -j DROP"))?;
    }
    Ok(())
}

pub fn unblock(ns: &Netns, src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> Result<(), String> {
    for chain in ["FORWARD", "INPUT"] {
        ns.run(&format!("iptables -w -D {chain} -s {src} -d {dst} -j DROP"))?;
    }
    Ok(())
}
