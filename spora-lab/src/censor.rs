//! Tier-0 DPI censor: signature-matching DROP rules installed in the wan
//! namespace, modeling the cheapest and most widely deployed censorship
//! primitive — a stateless middlebox that drops packets whose bytes match a
//! fixed pattern. Where [`crate::netem`] shapes a link and [`crate::nat`]
//! translates addresses, this module *detects and drops by packet contents*,
//! so the `censorship` suite can assert that a given Spora on-wire fingerprint
//! is (today) blockable by one trivial rule, and that removing the fingerprint
//! flips a scenario from blocked to connected (the red→green ratchet for the
//! DPI-resistance effort; see docs/lab.md).
//!
//! Implementation contract (iptables-legacy via [`Netns`], always `-w`):
//! - `drop_signature(ns, hex)` / `clear_signature`: Boyer-Moore payload match
//!   `-p udp -m string --algo bm --hex-string |<hex>|` `-j DROP`, installed in
//!   BOTH `FORWARD` and `INPUT` — the same direction-completeness rationale as
//!   [`crate::netem::block`]: lab services (relay/STUN) terminate *in* the wan
//!   ns and arrive via `INPUT`, while peer↔peer punch/direct traffic transits
//!   `FORWARD`. `hex` is bare hex with no spaces ([`Netns::run`] splits on
//!   whitespace, and the `|…|` form needs none).
//! - `drop_quic_v1(ns, dst, dport)` / `clear_quic_v1`: the QUIC v1 long-header
//!   version word `00 00 00 01` (relay-client/src/protocol.rs:243) on UDP to
//!   `<dst>:<dport>`. A faithful-enough stand-in for the deployed TSPU rule
//!   (QUIC version + dst port + size). It kills the handshake: Initial and
//!   Handshake packets are long-header and carry the version; 1-RTT
//!   short-header packets don't, but no flow ever reaches 1-RTT because the
//!   handshake never completes. Scoped to the relay endpoint so only relay
//!   QUIC is hit (REGISTER has the fixed bit clear and no version word).
//! - `string_match_available(ns)`: probe for the kernel `xt_string` match;
//!   the suite green-skips when it is absent (or fails under `SPORA_LAB=require`),
//!   the same self-skip contract the harness uses for missing tools.

use std::net::Ipv4Addr;

use crate::netns::Netns;

/// REGISTER control-packet signature: `CTRL_MAGIC || REGISTER` =
/// `0x80 'spR' 0x01` (relay-client/src/protocol.rs:11,19) — the 5-byte literal
/// a DPI box matches on the first bytes of any UDP payload to flag a sharer.
pub const SIG_REGISTER_MAGIC: &str = "8073705201";

/// Hole-punch marker prefix shared by `sporaHP1P` (PUNCH) and `sporaHP1V`
/// (VERIFY) (spora-core/src/lib.rs:1229) — one signature catches both the
/// punch and the verify packets of the direct-upgrade probe.
pub const SIG_PUNCH_MARKER: &str = "73706f7261485031";

/// The STUN `SOFTWARE` attribute the stunclient crate sends by default,
/// "SimpleRustStunClient" — a near-unique cleartext string in every binding
/// request. spora-core suppresses it via `set_software(None)`; this constant
/// lets the suite regression-guard that it stays gone.
pub const SIG_STUN_SOFTWARE: &str = "53696d706c65527573745374756e436c69656e74";

/// Chains an on-path middlebox would inspect: traffic transiting the router
/// (`FORWARD`) and traffic terminating on it (`INPUT`). See module docs.
const CHAINS: [&str; 2] = ["FORWARD", "INPUT"];

/// Install a Boyer-Moore string DROP for the `hex` byte pattern on UDP, in
/// both inspected chains of `ns`. Pairs with [`clear_signature`].
pub fn drop_signature(ns: &Netns, hex: &str) -> Result<(), String> {
    edit_signature(ns, hex, "-A")
}

/// Remove a rule installed by [`drop_signature`] (same `hex`).
pub fn clear_signature(ns: &Netns, hex: &str) -> Result<(), String> {
    edit_signature(ns, hex, "-D")
}

fn edit_signature(ns: &Netns, hex: &str, op: &str) -> Result<(), String> {
    for chain in CHAINS {
        ns.run(&format!(
            "iptables -w {op} {chain} -p udp -m string --algo bm --hex-string |{hex}| -j DROP"
        ))?;
    }
    Ok(())
}

/// Install a DROP for QUIC v1 long-header packets (the version word
/// `00 00 00 01`) on UDP to `dst:dport`. Pairs with [`clear_quic_v1`].
pub fn drop_quic_v1(ns: &Netns, dst: Ipv4Addr, dport: u16) -> Result<(), String> {
    edit_quic_v1(ns, dst, dport, "-A")
}

/// Remove a rule installed by [`drop_quic_v1`] (same `dst`/`dport`).
pub fn clear_quic_v1(ns: &Netns, dst: Ipv4Addr, dport: u16) -> Result<(), String> {
    edit_quic_v1(ns, dst, dport, "-D")
}

fn edit_quic_v1(ns: &Netns, dst: Ipv4Addr, dport: u16, op: &str) -> Result<(), String> {
    for chain in CHAINS {
        ns.run(&format!(
            "iptables -w {op} {chain} -p udp -d {dst} --dport {dport} \
             -m string --algo bm --hex-string |00000001| -j DROP"
        ))?;
    }
    Ok(())
}

/// Whether the iptables `string` match (`xt_string`) is usable in `ns`. Some
/// kernels/namespaces lack the module; the suite green-skips when it does
/// (matching the harness's self-skip philosophy). Probes by installing and
/// removing a throwaway rule in a dedicated chain — no side effects either way.
pub fn string_match_available(ns: &Netns) -> bool {
    let chain = "SPORA_CENSOR_PROBE";
    // Best-effort create; ignore "exists" on a reused ns.
    let _ = ns.run(&format!("iptables -w -N {chain}"));
    let ok = ns
        .run(&format!(
            "iptables -w -A {chain} -p udp -m string --algo bm --hex-string |2a| -j DROP"
        ))
        .is_ok();
    let _ = ns.run(&format!("iptables -w -F {chain}"));
    let _ = ns.run(&format!("iptables -w -X {chain}"));
    ok
}
