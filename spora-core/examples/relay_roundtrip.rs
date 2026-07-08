// Ad-hoc isolation test for the macOS client bring-up: does THIS machine reach
// the relay's QUIC endpoint and complete a share↔connect pairing, over the
// normal network (no NE tunnel, no sandbox)? Distinguishes a relay/network
// problem from a tunnel-plumbing bug in the appex.
//
//   cargo run -p spora-core --example relay_roundtrip
use spora_core::{connect, identity::Identity, share, Config};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_module("quinn", log::LevelFilter::Warn)
        .filter_module("quinn_proto", log::LevelFilter::Warn)
        .filter_module("quinn_udp", log::LevelFilter::Warn)
        .init();

    let identity = Identity::generate();
    let mut config = Config::default();
    // RELAY=host:port overrides the built-in relay (e.g. a local test relay).
    if let Ok(r) = std::env::var("RELAY") {
        let (host, port) = r.rsplit_once(':').expect("RELAY must be host:port");
        config.relays = vec![spora_core::identity::RelayEndpoint::new(
            host.to_string(),
            port.parse().expect("bad port"),
        )];
    }

    eprintln!("== sharing (registering with relay {:?}) ==", config.relays);
    let session = share(identity, config.clone())
        .await
        .expect("share() failed");
    eprintln!("SHARE URL: {}", session.url);

    // Let the REGISTER loop park the sharer at the relay.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    eprintln!("== connecting ==");
    match connect(session.url.clone(), &config).await {
        Ok(_) => eprintln!("RESULT: CONNECT OK — relay reachable + pairing works"),
        Err(e) => eprintln!("RESULT: CONNECT FAILED — {e}"),
    }
    std::process::exit(0);
}
