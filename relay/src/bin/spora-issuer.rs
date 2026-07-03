//! `spora-issuer` — operator tool to mint relay capability tokens.
//!
//! Two steps for a self-hosted relay:
//!   1. `spora-issuer gen` — make an issuer key pair. The secret is written to a
//!      file; the printed public key goes on the relay as `--issuer-key`.
//!   2. `spora-issuer issue --routing-key <hex>` — mint an "allowed" token for a
//!      sharer's routing key (which `spora share` prints). Hand the token to the
//!      sharer, who presents it with `spora share --relay-token <token>`.
//!
//! For a self-hosted relay the operator and the issuer are the same person, so
//! this is a local signing operation — no online service required.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use relay_client::authz::{self, IssuerKeyPair};

#[derive(Parser)]
#[command(name = "spora-issuer", version, about = "Generate a relay issuer key and mint capability tokens")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new issuer key pair. Writes the secret to a file (0600) and
    /// prints the public key to configure on the relay as `--issuer-key`.
    Gen {
        /// Where to write the issuer secret (PKCS#8, base64url).
        #[arg(long, default_value = "issuer.key")]
        out: PathBuf,
    },
    /// Mint an "allowed" capability token for a routing key.
    Issue {
        /// Issuer secret file (written by `gen`).
        #[arg(long, default_value = "issuer.key")]
        issuer_file: PathBuf,
        /// The sharer's routing key as hex (printed by `spora share`).
        #[arg(long)]
        routing_key: String,
    },
}

fn main() {
    let args = Args::parse();
    match args.cmd {
        Cmd::Gen { out } => {
            let issuer = IssuerKeyPair::generate().unwrap_or_else(|e| die(&e));
            write_private(&out, &authz::encode_b64(issuer.pkcs8_bytes()));
            eprintln!("Issuer secret written to {} — keep it private.", out.display());
            eprintln!("Configure the relay with:");
            eprintln!();
            println!("--issuer-key {}", authz::encode_b64(&issuer.public_key()));
        }
        Cmd::Issue {
            issuer_file,
            routing_key,
        } => {
            let secret_b64 = std::fs::read_to_string(&issuer_file)
                .unwrap_or_else(|e| die(&format!("reading {}: {e}", issuer_file.display())));
            let pkcs8 = authz::decode_b64(&secret_b64).unwrap_or_else(|e| die(&e));
            let issuer = IssuerKeyPair::from_pkcs8(&pkcs8).unwrap_or_else(|e| die(&e));
            let rk = authz::decode_routing_key(&routing_key).unwrap_or_else(|e| die(&e));
            let token = issuer.issue(&rk);
            eprintln!("Capability token for routing key {routing_key}:");
            println!("{}", authz::encode_b64(&token));
        }
    }
}

/// Write a sensitive file 0600 on unix (best-effort elsewhere).
fn write_private(path: &PathBuf, contents: &str) {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap_or_else(|e| die(&format!("writing {}: {e}", path.display())));
        f.write_all(contents.as_bytes())
            .unwrap_or_else(|e| die(&format!("writing {}: {e}", path.display())));
    }
    #[cfg(not(unix))]
    std::fs::write(path, contents)
        .unwrap_or_else(|e| die(&format!("writing {}: {e}", path.display())));
}

fn die(msg: &str) -> ! {
    eprintln!("spora-issuer: {msg}");
    std::process::exit(1);
}
