//! Windows backend: a wintun adapter configured through the IP Helper API.
//!
//! `wintun.dll` (https://www.wintun.net/) is loaded at runtime from next to
//! the executable (or the DLL search path); it is not linked in.
//!
//! Routing: `0.0.0.0/1` + `128.0.0.0/1` (`::/1` + `8000::/1`) on-link via
//! the adapter, metric 0 on an interface whose metric is pinned to 0, so
//! they win by prefix length and the adapter is the preferred DNS source;
//! the uplink's own default route is not touched.
//!
//! Outer-socket bypass: every socket spora-core opens is bound to the uplink
//! interface with `IP_UNICAST_IF` / `IPV6_UNICAST_IF` (what WireGuard and
//! Tailscale do on Windows), so the relay, STUN and punched-peer traffic
//! leaves through the physical adapter whatever its destination. The uplink
//! is the cheapest default route in the forward table that is not ours, and
//! is re-read when the tunnel reconnects.
//!
//! Resolver: `SetInterfaceDnsSettings` on the adapter. Windows may still
//! consult other adapters' resolvers in parallel ("smart multi-homed name
//! resolution"); pinning our interface metric makes ours the preferred one,
//! but a strict no-leak DNS policy would need WFP filters, which this tool
//! does not install.
//!
//! Needs an elevated (Administrator) console.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry,
    InitializeIpForwardEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings,
    SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
    SOCKADDR_INET, setsockopt,
};

use super::{Options, Prefix, Undo, UndoStack, parsers};

const ADAPTER_NAME: &str = "Spora";
const TUNNEL_TYPE: &str = "Spora";
/// A fixed adapter GUID: Windows then reuses one interface profile across
/// runs instead of accumulating "Spora 2", "Spora 3", … in its settings.
const ADAPTER_GUID: u128 = 0x5350_4f52_4143_4c49_a7c1_0000_0000_0001;

pub struct Backend {
    name: String,
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    index: u32,
    luid: NET_LUID_LH,
    uplink4: Arc<AtomicU32>,
    uplink6: Arc<AtomicU32>,
    ipv6: bool,
}

pub type PumpHandle = Arc<wintun::Session>;

// wintun's handles are process-wide kernel objects; the crate already uses
// them from multiple threads (`receive_blocking` is designed for it).
unsafe impl Send for Backend {}
unsafe impl Sync for Backend {}

impl Backend {
    pub fn setup(opts: &Options, _undo: &mut UndoStack) -> Result<Backend, String> {
        let wintun = load_wintun()?;
        let adapter = wintun::Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, Some(ADAPTER_GUID))
            .map_err(|e| {
                format!(
                    "cannot create the wintun adapter ({e}): this needs an elevated (Administrator) console — and only one `spora use` can run at a time (the adapter name is exclusive)"
                )
            })?;
        let index = adapter
            .get_adapter_index()
            .map_err(|e| format!("cannot read the adapter index: {e}"))?;
        let luid = adapter.get_luid();
        let name = adapter
            .get_name()
            .unwrap_or_else(|_| ADAPTER_NAME.to_string());

        add_address(luid, index, IpAddr::V4(opts.tun_addr), opts.tun_prefix)?;
        configure_interface(luid, AF_INET, opts.initial_mtu())?;
        if let Some((a6, p6)) = opts.tun_addr6 {
            add_address(luid, index, IpAddr::V6(a6), p6)?;
            configure_interface(luid, AF_INET6, opts.initial_mtu())?;
        }
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| format!("cannot start the wintun session: {e}"))?,
        );
        let backend = Backend {
            name,
            adapter,
            session,
            index,
            luid,
            uplink4: Arc::new(AtomicU32::new(0)),
            uplink6: Arc::new(AtomicU32::new(0)),
            ipv6: opts.ipv6_enabled(),
        };
        backend.refresh_uplink();
        if backend.uplink4.load(Ordering::Relaxed) == 0 {
            log::warn!(
                "no IPv4 default route found: the tunnel's own sockets cannot be bound to an uplink and may loop into the tunnel"
            );
        }
        log::info!(
            "wintun adapter '{}' (index {index}) up: {}/{} mtu {}",
            backend.name,
            opts.tun_addr,
            opts.tun_prefix,
            opts.initial_mtu()
        );
        Ok(backend)
    }

    pub fn tun_name(&self) -> &str {
        &self.name
    }

    pub fn protector(&self) -> spora_core::SocketProtector {
        let uplink4 = self.uplink4.clone();
        let uplink6 = self.uplink6.clone();
        let exclude = self.index;
        Some(Arc::new(move |sock: spora_core::SocketHandle| {
            let mut refreshed = false;
            loop {
                let idx4 = uplink4.load(Ordering::Relaxed);
                let idx6 = match uplink6.load(Ordering::Relaxed) {
                    0 => idx4,
                    i => i,
                };
                // IP_UNICAST_IF wants the index in network byte order; the v6
                // option takes host order. One of the two applies to a given
                // socket; the other fails and is ignored.
                let ok4 = idx4 != 0 && unicast_if(sock, IPPROTO_IP, IP_UNICAST_IF, idx4.to_be());
                let ok6 = idx6 != 0 && unicast_if(sock, IPPROTO_IPV6, IPV6_UNICAST_IF, idx6);
                if ok4 || ok6 {
                    return;
                }
                if refreshed {
                    log::warn!(
                        "could not bind socket {sock} to the uplink interface: it may be routed into the tunnel"
                    );
                    return;
                }
                // The cached index may name an interface that no longer
                // exists (uplink change since the last refresh): re-detect
                // once and retry.
                refresh_uplinks(exclude, &uplink4, &uplink6);
                refreshed = true;
            }
        }))
    }

    pub fn install_routes(
        &self,
        _opts: &Options,
        routes: &[Prefix],
        undo: &mut UndoStack,
    ) -> Result<(), String> {
        for p in routes {
            for target in half_defaults(*p) {
                let row = self.forward_row(target)?;
                let ret = unsafe { CreateIpForwardEntry2(&row) };
                if ret != NO_ERROR && ret != ERROR_OBJECT_ALREADY_EXISTS {
                    return Err(format!(
                        "cannot route {target} into the adapter: CreateIpForwardEntry2 error {ret}"
                    ));
                }
                undo.push(Undo::Fn(Box::new(move || {
                    let ret = unsafe { DeleteIpForwardEntry2(&row) };
                    if ret != NO_ERROR {
                        log::warn!(
                            "cleanup: DeleteIpForwardEntry2 for {target} failed: error {ret}"
                        );
                    }
                })));
            }
        }
        Ok(())
    }

    pub fn set_dns(&self, opts: &Options, undo: &mut UndoStack) -> Result<&'static str, String> {
        let guid = self.adapter.get_guid();
        let v4: Vec<String> = opts
            .dns
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(ToString::to_string)
            .collect();
        let v6: Vec<String> = opts
            .dns
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(ToString::to_string)
            .collect();
        let mut set_any = false;
        for (servers, v6flag) in [(v4, false), (v6, true)] {
            if servers.is_empty() {
                continue;
            }
            set_interface_dns(guid, &servers.join(","), v6flag)?;
            set_any = true;
            undo.push(Undo::Fn(Box::new(move || {
                if let Err(e) = set_interface_dns(guid, "", v6flag) {
                    log::warn!("cleanup: {e}");
                }
            })));
        }
        if !set_any {
            return Err("no resolver of a family the adapter carries".into());
        }
        Ok("SetInterfaceDnsSettings")
    }

    pub fn set_mtu(&self, mtu: u16) -> Result<(), String> {
        configure_interface(self.luid, AF_INET, mtu)?;
        if self.ipv6 {
            configure_interface(self.luid, AF_INET6, mtu)?;
        }
        Ok(())
    }

    pub fn refresh_uplink(&self) {
        refresh_uplinks(self.index, &self.uplink4, &self.uplink6);
    }

    pub fn pump_handle(&self) -> Result<PumpHandle, String> {
        Ok(self.session.clone())
    }

    pub fn closed(&self) {
        let _ = self.session.shutdown();
    }

    fn forward_row(&self, target: Prefix) -> Result<MIB_IPFORWARD_ROW2, String> {
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = self.luid;
        row.InterfaceIndex = self.index;
        row.DestinationPrefix.Prefix = sockaddr_inet(target.addr);
        row.DestinationPrefix.PrefixLength = target.len;
        // On-link next hop (unspecified address of the same family).
        row.NextHop = sockaddr_inet(if target.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        });
        row.Metric = 0;
        Ok(row)
    }
}

/// Bridge packets between the tunnel transport and the wintun session: two
/// OS threads for the blocking ring I/O, bounded channels to the async side
/// (the same shape as `spora_core::tun_util::start_fd`).
pub async fn run_pump(transport: spora_core::IpTransport, session: PumpHandle) -> io::Result<()> {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio::sync::mpsc;

    let (tun_read_tx, mut tun_read_rx) = mpsc::channel::<Vec<u8>>(256);
    let (tun_write_tx, mut tun_write_rx) = mpsc::channel::<Vec<u8>>(256);

    let reader_session = session.clone();
    let reader = std::thread::Builder::new()
        .name("tun-read".into())
        .spawn(move || {
            loop {
                match reader_session.receive_blocking() {
                    Ok(packet) => {
                        if tun_read_tx.blocking_send(packet.bytes().to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        log::info!("wintun read ended: {e}");
                        break;
                    }
                }
            }
        })
        .map_err(|e| io::Error::other(format!("failed to spawn tun-read thread: {e}")))?;

    let writer_session = session.clone();
    let writer = std::thread::Builder::new()
        .name("tun-write".into())
        .spawn(move || {
            while let Some(pkt) = tun_write_rx.blocking_recv() {
                let Ok(len) = u16::try_from(pkt.len()) else {
                    continue;
                };
                match writer_session.allocate_send_packet(len) {
                    Ok(mut out) => {
                        out.bytes_mut().copy_from_slice(&pkt);
                        writer_session.send_packet(out);
                    }
                    Err(e) => {
                        log::warn!("wintun write: {e}");
                    }
                }
            }
        })
        .map_err(|e| io::Error::other(format!("failed to spawn tun-write thread: {e}")))?;

    let mut transport = transport;
    loop {
        tokio::select! {
            res = transport.next() => match res {
                Some(Ok(pkt)) => {
                    if tun_write_tx.send(pkt).await.is_err() {
                        break;
                    }
                }
                Some(Err(e)) => log::error!("Error reading from transport: {e}"),
                None => {
                    log::info!("Transport stream closed.");
                    break;
                }
            },
            pkt = tun_read_rx.recv() => match pkt {
                Some(data) => {
                    if let Err(e) = transport.send(data).await {
                        log::error!("Error sending packet to remote peer: {e}");
                    }
                }
                None => break,
            },
        }
    }
    drop(tun_write_tx);
    drop(tun_read_rx);
    // Unblock the reader thread's receive_blocking().
    let _ = session.shutdown();
    let _ = reader.join();
    let _ = writer.join();
    Ok(())
}

/// Re-detect the default-route interfaces (excluding our own adapter) into
/// the shared slots the protector reads.
fn refresh_uplinks(exclude: u32, uplink4: &Arc<AtomicU32>, uplink6: &Arc<AtomicU32>) {
    for (family, slot) in [(AF_INET, uplink4), (AF_INET6, uplink6)] {
        let idx = cheapest_default_route(family, exclude).unwrap_or(0);
        let before = slot.swap(idx, Ordering::Relaxed);
        if before != idx {
            log::info!("uplink interface index (family {family}): {before} -> {idx}");
        }
    }
}

fn half_defaults(p: Prefix) -> Vec<Prefix> {
    if !p.is_default() {
        return vec![p];
    }
    if p.is_ipv4() {
        vec![
            Prefix {
                addr: "0.0.0.0".parse().unwrap(),
                len: 1,
            },
            Prefix {
                addr: "128.0.0.0".parse().unwrap(),
                len: 1,
            },
        ]
    } else {
        vec![
            Prefix {
                addr: "::".parse().unwrap(),
                len: 1,
            },
            Prefix {
                addr: "8000::".parse().unwrap(),
                len: 1,
            },
        ]
    }
}

fn load_wintun() -> Result<wintun::Wintun, String> {
    let beside_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")));
    if let Some(path) = &beside_exe
        && path.is_file()
        && let Ok(w) = unsafe { wintun::load_from_path(path) }
    {
        return Ok(w);
    }
    unsafe { wintun::load() }.map_err(|e| {
        format!(
            "cannot load wintun.dll ({e}): download it from https://www.wintun.net/ and place it next to {}",
            beside_exe
                .as_ref()
                .and_then(|p| p.parent())
                .map(|d| d.join("spora.exe").display().to_string())
                .unwrap_or_else(|| "the spora executable".into())
        )
    })
}

fn sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(a) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(a.octets());
        }
        IpAddr::V6(a) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = a.octets();
        }
    }
    sa
}

fn add_address(luid: NET_LUID_LH, index: u32, ip: IpAddr, prefix: u8) -> Result<(), String> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.InterfaceIndex = index;
    row.Address = sockaddr_inet(ip);
    row.OnLinkPrefixLength = prefix;
    let ret = unsafe { CreateUnicastIpAddressEntry(&row) };
    if ret != NO_ERROR && ret != ERROR_OBJECT_ALREADY_EXISTS {
        return Err(format!(
            "cannot assign {ip}/{prefix}: CreateUnicastIpAddressEntry error {ret}"
        ));
    }
    Ok(())
}

/// Set the MTU and pin the interface metric to 0 for one address family.
fn configure_interface(luid: NET_LUID_LH, family: ADDRESS_FAMILY, mtu: u16) -> Result<(), String> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.Family = family;
    row.InterfaceLuid = luid;
    let ret = unsafe { GetIpInterfaceEntry(&mut row) };
    if ret != NO_ERROR {
        return Err(format!("GetIpInterfaceEntry (family {family}) error {ret}"));
    }
    row.NlMtu = u32::from(mtu);
    row.UseAutomaticMetric = 0;
    row.Metric = 0;
    // Required to be 0 for IPv4 on input, per the SetIpInterfaceEntry docs.
    row.SitePrefixLength = 0;
    let ret = unsafe { SetIpInterfaceEntry(&mut row) };
    if ret != NO_ERROR {
        return Err(format!(
            "SetIpInterfaceEntry (family {family}, mtu {mtu}) error {ret}"
        ));
    }
    Ok(())
}

/// The interface index of the cheapest default route that is not on
/// `exclude` (our adapter), per family.
fn cheapest_default_route(family: ADDRESS_FAMILY, exclude: u32) -> Option<u32> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(family, &mut table) } != NO_ERROR || table.is_null() {
        return None;
    }
    let mut candidates = Vec::new();
    unsafe {
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0 || row.InterfaceIndex == exclude {
                continue;
            }
            let mut iface: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            iface.Family = family;
            iface.InterfaceLuid = row.InterfaceLuid;
            let if_metric = if GetIpInterfaceEntry(&mut iface) == NO_ERROR {
                iface.Metric
            } else {
                0
            };
            candidates.push((row.InterfaceIndex, row.Metric.saturating_add(if_metric)));
        }
        FreeMibTable(table as *const _);
    }
    parsers::pick_cheapest_uplink(candidates)
}

fn unicast_if(sock: spora_core::SocketHandle, level: i32, opt: i32, value: u32) -> bool {
    let r = unsafe {
        setsockopt(
            sock as usize,
            level,
            opt,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    r == 0
}

fn set_interface_dns(guid: u128, servers: &str, ipv6: bool) -> Result<(), String> {
    let mut wide: Vec<u16> = servers.encode_utf16().chain(std::iter::once(0)).collect();
    let mut settings: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags =
        u64::from(DNS_SETTING_NAMESERVER) | if ipv6 { u64::from(DNS_SETTING_IPV6) } else { 0 };
    settings.NameServer = wide.as_mut_ptr();
    let ret =
        unsafe { SetInterfaceDnsSettings(windows_sys::core::GUID::from_u128(guid), &settings) };
    if ret != NO_ERROR {
        return Err(format!(
            "SetInterfaceDnsSettings ({servers:?}, ipv6={ipv6}) error {ret}"
        ));
    }
    Ok(())
}
