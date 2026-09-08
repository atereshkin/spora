//! Parsers for the output of the host tools the backends drive. Pure text in,
//! values out — compiled and tested on every platform so a macOS-only parser
//! is still exercised by `cargo test` on Linux.

/// The preferences (priorities) of every rule in `ip [-4|-6] rule show`
/// output, e.g. `21327:\tfrom all lookup main suppress_prefixlength 0`.
pub fn ip_rule_prefs(output: &str) -> Vec<u32> {
    ip_rules(output).into_iter().map(|(p, _)| p).collect()
}

/// Every rule in `ip rule show` output as (preference, body).
pub fn ip_rules(output: &str) -> Vec<(u32, String)> {
    output
        .lines()
        .filter_map(|l| l.trim_start().split_once(':'))
        .filter_map(|(pref, body)| Some((pref.trim().parse().ok()?, body.trim().to_string())))
        .collect()
}

/// The interface of the system's `default` route in macOS `netstat -rn -f
/// inet|inet6` output, skipping routes on `exclude` (our own tunnel: once
/// `0.0.0.0/1` is installed, `route get default` would resolve to it, but
/// the uplink's `default` row stays in the table).
pub fn darwin_netstat_default_interface(output: &str, exclude: &str) -> Option<String> {
    darwin_netstat_default_route(output, exclude).map(|(_, netif)| netif)
}

/// The `(gateway, interface)` of the system's `default` route in macOS
/// `netstat -rn -f inet|inet6` output, skipping routes on `exclude`. Columns
/// are `Destination Gateway Flags Netif [Expire]`; the gateway is an
/// address (`192.168.1.1`, `fe80::1%en0`) or a link (`link#11`) for a
/// directly attached default.
pub fn darwin_netstat_default_route(output: &str, exclude: &str) -> Option<(String, String)> {
    let rows: Vec<(String, String, bool)> = darwin_default_rows(output)
        .filter(|(_, netif, _)| netif != exclude)
        .collect();
    // The primary (unscoped) row is the uplink of record; a scoped one (`I`
    // flag) only if that is all there is.
    rows.iter()
        .find(|(_, _, scoped)| !scoped)
        .or_else(|| rows.first())
        .map(|(gateway, netif, _)| (gateway.clone(), netif.clone()))
}

/// The gateway of the `default` route *scoped to* `netif` (Flags carry
/// `I`, RTF_IFSCOPE) in macOS `netstat -rn -f inet|inet6` output, if one is
/// in the table. This is the row bound sockets rely on; the kernel drops it
/// together with the interface's address, so it must be looked up, never
/// remembered.
pub fn darwin_netstat_scoped_default(output: &str, netif: &str) -> Option<String> {
    darwin_default_rows(output)
        .find(|(_, n, scoped)| *scoped && n == netif)
        .map(|(gateway, _, _)| gateway)
}

/// Every `default` row as `(gateway, netif, scoped)`. Columns are
/// `Destination Gateway Flags Netif [Expire]`; a missing Expire column does
/// not shift Netif.
fn darwin_default_rows(output: &str) -> impl Iterator<Item = (String, String, bool)> + '_ {
    output.lines().filter_map(|l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        if cols.first() != Some(&"default") {
            return None;
        }
        let gateway = cols.get(1)?;
        let flags = cols.get(2)?;
        let netif = cols.get(3)?;
        Some((gateway.to_string(), netif.to_string(), flags.contains('I')))
    })
}

/// How macOS `route(8)` answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteOutcome {
    Done,
    /// `File exists`: the route is already in the table.
    Exists,
    /// `not in table`: nothing to change or delete.
    Missing,
}

/// The verdict of a macOS `route(8)` run from its exit status and combined
/// stdout+stderr. `route` exits 0 even when the routing socket refuses the
/// change, so the text is what counts.
pub fn darwin_route_outcome(success: bool, text: &str) -> Result<RouteOutcome, String> {
    if text.contains("File exists") {
        return Ok(RouteOutcome::Exists);
    }
    if text.contains("not in table") {
        return Ok(RouteOutcome::Missing);
    }
    let complained = text
        .lines()
        .any(|l| l.starts_with("route:") || l.contains("writing to routing socket"));
    if !success || complained {
        return Err(text.trim().to_string());
    }
    Ok(RouteOutcome::Done)
}

/// The gateway arguments of a default route scoped to an uplink: the
/// address, or `-interface <netif>` when netstat shows a directly attached
/// default (`link#N`).
pub fn darwin_uplink_route_via(gateway: &str, netif: &str) -> Vec<String> {
    if gateway.starts_with("link#") {
        vec!["-interface".to_string(), netif.to_string()]
    } else {
        vec![gateway.to_string()]
    }
}

/// `route -n <verb> <family> default [<via>] -ifscope <ifscope>`: the
/// scoped default route for an uplink. A delete needs no gateway; the scope
/// alone identifies the route.
pub fn darwin_uplink_route_args(
    verb: &str,
    family: &str,
    via: &[String],
    ifscope: &str,
) -> Vec<String> {
    let mut args = vec![
        "-n".to_string(),
        verb.to_string(),
        family.to_string(),
        "default".to_string(),
    ];
    if verb != "delete" {
        args.extend(via.iter().cloned());
    }
    args.push("-ifscope".to_string());
    args.push(ifscope.to_string());
    args
}

/// The enabled services in macOS `networksetup -listallnetworkservices`
/// output (the first line is a legend; disabled services are prefixed `*`).
pub fn darwin_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("An asterisk") && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

/// The resolver entries in macOS `networksetup -getdnsservers <service>`
/// output: one per line, or a sentence ("There aren't any DNS Servers set
/// on …") meaning the service uses DHCP-supplied ones. Kept as raw strings:
/// forms like `fe80::1%en0` are valid resolver settings that do not parse
/// as plain addresses, and a snapshot that dropped them could not restore
/// them.
pub fn darwin_dns_servers(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains(' '))
        .map(str::to_string)
        .collect()
}

/// Among `(interface index, effective metric)` candidates for a default
/// route, the interface of the cheapest one (Windows: `GetIpForwardTable2`
/// rows with prefix length 0, excluding our own adapter).
pub fn pick_cheapest_uplink(candidates: impl IntoIterator<Item = (u32, u32)>) -> Option<u32> {
    candidates
        .into_iter()
        .min_by_key(|(_, metric)| *metric)
        .map(|(index, _)| index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cheapest_uplink_wins() {
        assert_eq!(
            pick_cheapest_uplink([(7, 281), (12, 25), (3, 4250)]),
            Some(12)
        );
        assert_eq!(pick_cheapest_uplink(Vec::<(u32, u32)>::new()), None);
    }

    #[test]
    fn rule_prefs_are_read_from_ip_rule_show() {
        let out = "0:\tfrom all lookup local\n21327:\tfrom all lookup main suppress_prefixlength 0\n21328:\tnot from all fwmark 0x5350 lookup 21328\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n";
        assert_eq!(ip_rule_prefs(out), vec![0, 21327, 21328, 32766, 32767]);
        assert!(ip_rule_prefs("").is_empty());
    }

    #[test]
    fn darwin_netstat_default_skips_our_tunnel() {
        let out = "Routing tables\n\nInternet:\nDestination        Gateway            Flags           Netif Expire\ndefault            link#22            UCSg            utun4       \ndefault            192.168.1.1        UGScg             en0       \n0/1                utun4              USc             utun4       \n127                127.0.0.1          UCS               lo0       \n";
        assert_eq!(
            darwin_netstat_default_interface(out, "utun4").as_deref(),
            Some("en0")
        );
        assert_eq!(
            darwin_netstat_default_interface(out, "").as_deref(),
            Some("utun4"),
            "without an exclusion the first default row wins"
        );
        let v6 = "Internet6:\nDestination                             Gateway                                 Flags           Netif Expire\ndefault                                 fe80::1%en0                             UGcg              en0       \ndefault                                 fe80::%utun4                            UGcIg           utun4       \n";
        assert_eq!(
            darwin_netstat_default_interface(v6, "utun4").as_deref(),
            Some("en0")
        );
        assert_eq!(
            darwin_netstat_default_interface("Routing tables\n", "utun4"),
            None
        );
    }

    #[test]
    fn darwin_netstat_default_route_carries_the_gateway() {
        let out = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n0/1                utun0              UScg                utun0       \ndefault            192.168.23.254     UGScg                 en0       \ndefault            192.168.23.254     UGScIg                en0       \n127                127.0.0.1          UCS                   lo0       \n";
        assert_eq!(
            darwin_netstat_default_route(out, "utun0"),
            Some(("192.168.23.254".to_string(), "en0".to_string()))
        );
        let ppp = "Internet:\nDestination        Gateway            Flags           Netif Expire\ndefault            link#22            UCSg            utun4       \ndefault            link#14            UCScg           ppp0       \n";
        assert_eq!(
            darwin_netstat_default_route(ppp, "utun4"),
            Some(("link#14".to_string(), "ppp0".to_string()))
        );
        let v6 = "Internet6:\nDestination                             Gateway                                 Flags           Netif Expire\ndefault                                 fe80::1%en0                             UGcg              en0       \n";
        assert_eq!(
            darwin_netstat_default_route(v6, "utun4"),
            Some(("fe80::1%en0".to_string(), "en0".to_string()))
        );
        assert_eq!(
            darwin_netstat_default_route("Routing tables\n", "utun0"),
            None
        );
    }

    #[test]
    fn darwin_netstat_scoped_default_is_the_i_flagged_row_for_the_interface() {
        let out = "Internet:\nDestination        Gateway            Flags               Netif Expire\n0/1                utun0              UScg                utun0       \ndefault            192.168.23.254     UGScg                 en0       \ndefault            192.168.23.1       UGScIg                en0       \ndefault            link#11            UCScIg                en7      !\n";
        assert_eq!(
            darwin_netstat_scoped_default(out, "en0").as_deref(),
            Some("192.168.23.1")
        );
        assert_eq!(
            darwin_netstat_scoped_default(out, "en7").as_deref(),
            Some("link#11")
        );
        assert_eq!(darwin_netstat_scoped_default(out, "utun0"), None);
        // The primary row wins for the uplink of record even when a scoped
        // one is listed first.
        let scoped_first = "Internet:\ndefault            10.0.0.1           UGScIg                en0       \ndefault            10.0.0.254         UGScg                 en0       \n";
        assert_eq!(
            darwin_netstat_default_route(scoped_first, "utun0"),
            Some(("10.0.0.254".to_string(), "en0".to_string()))
        );
        let only_scoped =
            "Internet:\ndefault            10.0.0.1           UGScIg                en0       \n";
        assert_eq!(
            darwin_netstat_default_route(only_scoped, "utun0"),
            Some(("10.0.0.1".to_string(), "en0".to_string()))
        );
    }

    #[test]
    fn darwin_uplink_route_commands_are_scoped_and_gateway_aware() {
        let wifi = darwin_uplink_route_via("192.168.23.254", "en0");
        assert_eq!(wifi, vec!["192.168.23.254"]);
        assert_eq!(
            darwin_uplink_route_args("add", "-inet", &wifi, "en0"),
            vec![
                "-n",
                "add",
                "-inet",
                "default",
                "192.168.23.254",
                "-ifscope",
                "en0"
            ]
        );
        assert_eq!(
            darwin_uplink_route_args("change", "-inet", &wifi, "en0"),
            vec![
                "-n",
                "change",
                "-inet",
                "default",
                "192.168.23.254",
                "-ifscope",
                "en0"
            ]
        );
        assert_eq!(
            darwin_uplink_route_args("delete", "-inet", &wifi, "en0"),
            vec!["-n", "delete", "-inet", "default", "-ifscope", "en0"]
        );
        let ppp = darwin_uplink_route_via("link#14", "ppp0");
        assert_eq!(
            darwin_uplink_route_args("add", "-inet", &ppp, "ppp0"),
            vec![
                "-n",
                "add",
                "-inet",
                "default",
                "-interface",
                "ppp0",
                "-ifscope",
                "ppp0"
            ]
        );
        let v6 = darwin_uplink_route_via("fe80::1%en0", "en0");
        assert_eq!(
            darwin_uplink_route_args("add", "-inet6", &v6, "en0"),
            vec![
                "-n",
                "add",
                "-inet6",
                "default",
                "fe80::1%en0",
                "-ifscope",
                "en0"
            ]
        );
    }

    #[test]
    fn darwin_route_output_is_the_verdict_not_the_exit_status() {
        assert_eq!(
            darwin_route_outcome(true, "add net default: gateway 192.168.23.254\n"),
            Ok(RouteOutcome::Done)
        );
        assert_eq!(
            darwin_route_outcome(
                true,
                "route: writing to routing socket: File exists\nadd net default: gateway 192.168.23.254: File exists\n"
            ),
            Ok(RouteOutcome::Exists)
        );
        assert_eq!(
            darwin_route_outcome(
                true,
                "delete net default: not in table\nroute: writing to routing socket: not in table\n"
            ),
            Ok(RouteOutcome::Missing)
        );
        assert!(
            darwin_route_outcome(
                true,
                "route: writing to routing socket: Network is unreachable\n"
            )
            .is_err()
        );
        assert!(darwin_route_outcome(false, "").is_err());
        assert_eq!(darwin_route_outcome(true, ""), Ok(RouteOutcome::Done));
    }

    #[test]
    fn darwin_services_skip_legend_and_disabled() {
        let out = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nThunderbolt Bridge\n";
        assert_eq!(
            darwin_network_services(out),
            vec!["Wi-Fi", "Thunderbolt Bridge"]
        );
    }

    #[test]
    fn darwin_dns_servers_keep_raw_entries_and_drop_the_sentence() {
        assert_eq!(
            darwin_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            darwin_dns_servers("1.1.1.1\n2606:4700::1111\nfe80::1%en0\n"),
            vec!["1.1.1.1", "2606:4700::1111", "fe80::1%en0"]
        );
    }

    #[test]
    fn ip_rules_carry_bodies() {
        let out = "21328:\tnot from all fwmark 0x5350 lookup 21328\n";
        assert_eq!(
            ip_rules(out),
            vec![(21328, "not from all fwmark 0x5350 lookup 21328".to_string())]
        );
    }
}
