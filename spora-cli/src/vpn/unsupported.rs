//! Platforms without a VPN backend: `spora use` still works in attach mode
//! (`--tun-name`), everything else reports the gap.

use super::{Options, Prefix, UndoStack};

const MSG: &str = "spora use cannot manage a tunnel interface on this platform; attach to a pre-configured one with --tun-name";

pub struct Backend;
pub type PumpHandle = ();

impl Backend {
    pub fn setup(_opts: &Options, _undo: &mut UndoStack) -> Result<Backend, String> {
        Err(MSG.into())
    }
    pub fn tun_name(&self) -> &str {
        ""
    }
    pub fn protector(&self) -> spora_core::SocketProtector {
        None
    }
    pub fn install_routes(
        &self,
        _o: &Options,
        _r: &[Prefix],
        _u: &mut UndoStack,
    ) -> Result<(), String> {
        Err(MSG.into())
    }
    pub fn set_dns(&self, _o: &Options, _u: &mut UndoStack) -> Result<&'static str, String> {
        Err(MSG.into())
    }
    pub fn set_mtu(&self, _mtu: u16) -> Result<(), String> {
        Err(MSG.into())
    }
    pub fn refresh_uplink(&self) {}
    pub fn pump_handle(&self) -> Result<PumpHandle, String> {
        Err(MSG.into())
    }
    pub fn closed(&self) {}
}

pub async fn run_pump(_t: spora_core::IpTransport, _h: PumpHandle) -> std::io::Result<()> {
    Err(std::io::Error::other(MSG))
}
