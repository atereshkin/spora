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
/// the uplink's `default` row stays in the table). Columns are
/// `Destination Gateway Flags Netif [Expire]`.
pub fn darwin_netstat_default_interface(output: &str, exclude: &str) -> Option<String> {
    output.lines().find_map(|l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        if cols.first() != Some(&"default") {
            return None;
        }
        // Netif is the 4th column; a missing Expire column does not shift it.
        let netif = cols.get(3)?;
        (*netif != exclude).then(|| netif.to_string())
    })
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
