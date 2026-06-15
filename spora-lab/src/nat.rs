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
//! - `Firewalled`: stateful filter, NO translation (RFC 6092 "simple
//!   security" — the realistic IPv6 home-router shape):
//!   `FORWARD -i <wan_if> --ctstate ESTABLISHED,RELATED -j ACCEPT` +
//!   `FORWARD -i <wan_if> -j DROP`.
//!
//! Always use `iptables -w` (xtables lock). Forwarding policy stays ACCEPT
//! (fresh namespaces) — only `Firewalled` adds FORWARD rules.

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
    apply_nat_cmd(gw, kind, wan_if, &lan_host.to_string(), "iptables")
}

/// IPv6 twin of [`apply_nat`], via `ip6tables` (NAT66). Conntrack semantics
/// — port preservation, reply-only admission, `--random-fully` — are the
/// same netfilter code as v4, so the RFC 4787 flavor mapping carries over.
/// (Real-world v6 is mostly `Open` or stateful-firewall; NAT66 is here so v6
/// scenarios can reuse the same NatKind matrix.)
pub fn apply_nat6(
    gw: &Netns,
    kind: NatKind,
    wan_if: &str,
    lan_host: std::net::Ipv6Addr,
) -> Result<(), String> {
    apply_nat_cmd(gw, kind, wan_if, &lan_host.to_string(), "ip6tables")
}

fn apply_nat_cmd(
    gw: &Netns,
    kind: NatKind,
    wan_if: &str,
    lan_host: &str,
    tables: &str,
) -> Result<(), String> {
    match kind {
        NatKind::Open => Ok(()),
        NatKind::PortRestricted => masquerade(gw, wan_if, "", tables),
        NatKind::Symmetric => masquerade(gw, wan_if, " --random-fully", tables),
        NatKind::FullCone => {
            masquerade(gw, wan_if, "", tables)?;
            gw.run(&format!(
                "{tables} -w -t nat -A PREROUTING -i {wan_if} -p udp -j DNAT --to-destination {lan_host}"
            ))?;
            Ok(())
        }
        // RFC 6092 "simple security": no translation, forward outbound and
        // its return traffic, drop unsolicited inbound. `-i {wan_if}` keeps
        // the rules off the outbound direction (default ACCEPT). The LAN
        // must be routable and the wan router must hold a return route —
        // `topology::firewalled_side*` set both up.
        NatKind::Firewalled => {
            gw.run(&format!(
                "{tables} -w -A FORWARD -i {wan_if} -m conntrack \
                 --ctstate ESTABLISHED,RELATED -j ACCEPT"
            ))?;
            gw.run(&format!("{tables} -w -A FORWARD -i {wan_if} -j DROP"))?;
            Ok(())
        }
    }
}

fn masquerade(gw: &Netns, wan_if: &str, extra: &str, tables: &str) -> Result<(), String> {
    gw.run(&format!(
        "{tables} -w -t nat -A POSTROUTING -o {wan_if} -j MASQUERADE{extra}"
    ))?;
    Ok(())
}
