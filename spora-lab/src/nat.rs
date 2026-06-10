//! iptables NAT recipes per [`crate::NatKind`] (this machine ships
//! iptables-legacy; everything below works on both legacy and nft backends).
//!
//! - `PortRestricted`: `iptables -t nat -A POSTROUTING -o <wan_if> -j MASQUERADE`
//!   — Linux conntrack defaults: port-preserving (endpoint-independent
//!   mapping), reply-only conntrack admission (address+port-dependent
//!   filtering).
//! - `Symmetric`: same with `--random-fully` — per-flow randomized ports.
//! - `FullCone`: `PortRestricted` masquerade **plus**
//!   `iptables -t nat -A PREROUTING -i <wan_if> -p udp -j DNAT --to-destination <lan_host>`
//!   so unsolicited inbound UDP to any port reaches the (single) LAN host —
//!   endpoint-independent filtering for that host.
//! - `Open`: no-op (peer sits directly on the wan bridge).
//!
//! Always use `iptables -w` (xtables lock). Forwarding policy stays ACCEPT
//! (fresh namespaces) — no FORWARD rules needed.

use crate::NatKind;
use crate::netns::Netns;

/// Apply NAT rules inside gateway namespace `gw`. `wan_if`/`lan_host` per
/// the recipes above. `Open` is a no-op.
pub fn apply_nat(
    gw: &Netns,
    kind: NatKind,
    wan_if: &str,
    lan_host: std::net::Ipv4Addr,
) -> Result<(), String> {
    match kind {
        NatKind::Open => Ok(()),
        NatKind::PortRestricted => masquerade(gw, wan_if, ""),
        NatKind::Symmetric => masquerade(gw, wan_if, " --random-fully"),
        NatKind::FullCone => {
            masquerade(gw, wan_if, "")?;
            gw.run(&format!(
                "iptables -w -t nat -A PREROUTING -i {wan_if} -p udp -j DNAT --to-destination {lan_host}"
            ))?;
            Ok(())
        }
    }
}

fn masquerade(gw: &Netns, wan_if: &str, extra: &str) -> Result<(), String> {
    gw.run(&format!(
        "iptables -w -t nat -A POSTROUTING -o {wan_if} -j MASQUERADE{extra}"
    ))?;
    Ok(())
}
