//! The connection record — a machine-readable account of how one connection
//! went.
//!
//! A log line tells a human what happened once. A *record* tells a program
//! what happened ten thousand times, so it can be counted, grouped, compared
//! across builds, and noticed when it changes. That is the whole point of this
//! module, and it drives every decision in it:
//!
//! - **The vocabulary is closed.** Every step is a [`StepKind`]; every failure
//!   is a [`Reason`]. Both are fixed, versioned sets with stable wire codes —
//!   never free text. Human-readable detail may ride along in `detail`, but no
//!   analysis is ever allowed to key on it, because a message that gets
//!   reworded stops being countable.
//! - **It is honest about what it does not know.** [`Reason::Unknown`] exists
//!   and is used. A step whose handle is dropped without a verdict — a
//!   cancelled task, a panic, a future that was simply never polled again —
//!   records [`StepOutcome::Abandoned`] rather than a plausible-looking
//!   failure. A record with no `close` entry is `truncated`, not "finished".
//! - **It is cheap enough to always collect.** Tens of entries per connection,
//!   a handful of quality samples per minute. A diagnostic you have to turn on
//!   before reproducing a problem is a diagnostic you do not have when it
//!   matters. (It is nevertheless *off* by default: writing to a user's disk
//!   is the platform's decision, not the core's.)
//! - **It is versioned.** [`FORMAT_VERSION`] is stamped on every record. Old
//!   records stay readable; unknown codes from a newer writer degrade to
//!   `unknown` in an older reader rather than failing the parse.
//!
//! # Shape
//!
//! One record covers one run of [`crate::connect`] (client) or
//! [`crate::share`] (exit) — from the first action to teardown, reconnects and
//! all. On disk it is an append-only stream of JSON lines
//! (`open`, `step`…, `sample`…, `close`), so a process that is killed mid-run
//! still leaves everything it had learned up to that instant. Readers fold the
//! stream back into a [`Record`] document; [`Recorder::snapshot`] produces the
//! same document in memory without touching the disk.
//!
//! # Who reads it
//!
//! Support ("send logs"), the field lab, and the simulated lab all read the
//! same format — which is exactly why the vocabulary lives here in the core
//! rather than in test scaffolding.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{debug, warn};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Bump when the meaning of existing fields changes. Adding a step kind, a
/// reason code or an optional field does **not** require a bump: readers are
/// required to tolerate both.
pub const FORMAT_VERSION: u32 = 1;

/// Queue depth toward the writer thread. Entry volume is tens per connection,
/// so reaching this means the disk is in trouble; the overflow is counted and
/// surfaced as a [`Gap`] rather than silently losing history.
const CHANNEL_CAPACITY: usize = 1024;

// ---------------------------------------------------------------------------
// the vocabularies

/// Defines a closed vocabulary: a fixed enum with stable wire codes, plus the
/// string conversions and the lossy-forward-compatible serde impls.
///
/// The codes are the format. Never change one; add a variant instead.
macro_rules! vocabulary {
    (
        $(#[$meta:meta])*
        $name:ident, fallback = $fallback:ident, {
            $( $(#[$vmeta:meta])* $variant:ident => $code:literal, )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )*
        }

        impl $name {
            /// Every variant, for exhaustiveness checks and documentation.
            pub const ALL: &'static [$name] = &[ $( $name::$variant, )* ];

            /// The stable wire code.
            pub fn as_str(self) -> &'static str {
                match self { $( $name::$variant => $code, )* }
            }

            /// Parse a wire code. `None` for a code this build does not know
            /// (a record written by a newer version).
            pub fn from_code(code: &str) -> Option<Self> {
                match code { $( $code => Some($name::$variant), )* _ => None }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // `pad`, not `write_str`: these are printed in columns.
                f.pad(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            /// An unknown code degrades to the fallback variant rather than
            /// failing the parse: an old reader must still be able to read a
            /// new writer's record. The raw line keeps the original code.
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Ok($name::from_code(&s).unwrap_or($name::$fallback))
            }
        }
    };
}

vocabulary! {
    /// Which end of the tunnel wrote this record.
    Role, fallback = Client, {
        /// The end that tunnels its traffic through someone else.
        Client => "client",
        /// The end that lends out its internet connection (`share`).
        Exit => "exit",
    }
}

vocabulary! {
    /// How the tunnel is dressed on the wire. Orthogonal to [`PathKind`]:
    /// the same carrier can run through a relay or straight to the peer.
    Carrier, fallback = Unknown, {
        /// End-to-end QUIC (through the dumb UDP relay, or direct).
        Quic => "quic",
        /// End-to-end TLS over a TCP relay (stream-native carrier).
        TcpTls => "tcp_tls",
        /// End-to-end Noise over UDP — the non-QUIC-shaped carrier.
        NoiseUdp => "nz",
        Unknown => "unknown",
    }
}

vocabulary! {
    /// Which way the packets actually travel.
    PathKind, fallback = Unknown, {
        /// Through a relay.
        Relay => "relay",
        /// Straight to an endpoint the exit advertised itself (relay-less).
        DirectAdvertised => "direct_advertised",
        /// Straight to an address discovered and validated by hole punching.
        DirectPunched => "direct_punched",
        Unknown => "unknown",
    }
}

vocabulary! {
    /// What was attempted. One kind per distinguishable piece of machinery —
    /// if two things can fail for different reasons, they are two kinds.
    StepKind, fallback = Unknown, {
        // -- client bootstrap ------------------------------------------------
        /// Parsing the share URL into a routing key, secret and relay list.
        TokenParse => "token_parse",
        /// Turning relay names into addresses (one step per relay list).
        RelayResolve => "relay_resolve",
        /// Binding the local socket a dial will use.
        SocketBind => "socket_bind",
        /// One attempt to reach the peer over one endpoint with one carrier.
        /// Wraps the handshake and authentication steps below.
        RelayDial => "relay_dial",
        /// The cryptographic handshake with the peer — never with the relay,
        /// which is not a party to it — through to proving the shared secret.
        /// The two are one step because one call does both; their reasons
        /// (`cert_mismatch`, `auth_rejected`, …) tell them apart.
        Handshake => "handshake",
        /// A usable tunnel exists.
        SessionUp => "session_up",
        /// The tunnel's packet-size limit settled (path MTU discovery, or a
        /// carrier with a fixed frame size adopting it).
        Mtu => "mtu",
        /// The transport died and a re-dial cycle is starting.
        Reconnect => "reconnect",
        /// The application went dormant (screen off / radio silent): probing
        /// stops and re-dialling parks until it wakes.
        Dormant => "dormant",
        /// The application woke.
        Wake => "wake",

        // -- exit bootstrap --------------------------------------------------
        /// Binding the listening socket clients arrive on.
        ListenerBind => "listener_bind",
        /// Announcing this exit's routing key to a relay so clients can be
        /// routed to it.
        Register => "register",
        /// Parking an outbound connection at a stream relay, ready for a
        /// client (the exit dials out; there is nothing to register). A relay
        /// that refuses the connection and one that reaps it after an idle
        /// spell look the same from here — both simply close.
        RelayPark => "relay_park",
        /// Handing the routing key to a fresh listener so the serving session
        /// keeps its own port.
        ListenerRoll => "listener_roll",
        /// A client connection arrived.
        Accept => "accept",
        /// Starting whatever turns tunnelled packets into real traffic.
        ExitStart => "exit_start",

        // -- the direct upgrade ----------------------------------------------
        /// Asking a STUN server what this machine looks like from outside.
        Stun => "stun",
        /// Trading candidate addresses with the peer over the tunnel's own
        /// signalling channel.
        EndpointExchange => "endpoint_exchange",
        /// Punching: both ends send to each other's candidate to open the
        /// path through their NATs, and confirm it carries packets both ways.
        /// The two halves are one step because they are one operation; their
        /// reasons (`punch_timeout` vs `verify_timeout`) tell them apart.
        Punch => "punch",
        /// The handshake that rebuilds the encrypted session on the punched
        /// socket.
        DirectHandshake => "direct_handshake",
        /// Moving live traffic from the old path onto the new one.
        PathSwap => "path_swap",

        // -- steady state and teardown ---------------------------------------
        /// The liveness probe cycle: a failure here is a tunnel that stopped
        /// carrying traffic without anyone closing it.
        Liveness => "liveness",
        /// A session ended, with the reason it ended.
        SessionEnd => "session_end",

        Unknown => "unknown",
    }
}

vocabulary! {
    /// How a step came out.
    StepOutcome, fallback = Unknown, {
        /// Under way when this entry was written. A later entry with the same
        /// `seq` supersedes it — so a record that ends here is a record of
        /// something that was still running when the process went away, which
        /// is precisely what a hang looks like.
        Started => "started",
        /// It did what it set out to do.
        Ok => "ok",
        /// It failed; the accompanying [`Reason`] says how.
        Failed => "failed",
        /// It was deliberately not attempted (see the [`Reason`]) — which is
        /// a different fact from failing, and often a more interesting one.
        Skipped => "skipped",
        /// Nobody ever concluded it: the task was cancelled, dropped, or the
        /// process went away. Recorded rather than guessed at.
        Abandoned => "abandoned",
        Unknown => "unknown",
    }
}

vocabulary! {
    /// Why something failed or was skipped — the closed vocabulary that makes
    /// failures countable. Grouped by where the trouble was, because "did it
    /// reach the peer at all" is the first question anyone asks.
    Reason, fallback = Unknown, {
        // -- what we were told to do ----------------------------------------
        /// No relay endpoints were configured at all.
        NoRelays => "no_relays",
        /// The share URL is not a usable token.
        BadToken => "bad_token",
        /// Configuration that cannot work (contradictory or incomplete).
        Misconfigured => "misconfigured",

        // -- finding the other end ------------------------------------------
        /// The name resolved to nothing usable.
        DnsNoRecords => "dns_no_records",
        /// Name resolution itself failed.
        DnsFailure => "dns_failure",

        // -- the local network stack -----------------------------------------
        /// Could not bind a local socket.
        BindFailed => "bind_failed",
        /// The operating system has no route to the destination.
        NoRoute => "no_route",
        /// The operating system refused the operation.
        PermissionDenied => "permission_denied",
        /// No usable address of the required family (v4/v6) on this host.
        FamilyUnsupported => "family_unsupported",
        /// Any other socket-level error.
        SocketError => "socket_error",

        // -- reaching the far end --------------------------------------------
        /// Actively refused (a TCP reset to the connect, an ICMP rejection).
        ConnectRefused => "connect_refused",
        /// The connection attempt ran out of time.
        ConnectTimeout => "connect_timeout",
        /// The connection was reset once established.
        ConnectReset => "connect_reset",
        /// We sent and nothing whatsoever came back. On a censored network
        /// this is the signature failure — worth its own code precisely
        /// because it looks like nothing.
        NoResponse => "no_response",

        // -- the cryptographic handshake --------------------------------------
        /// The handshake ran out of time.
        HandshakeTimeout => "handshake_timeout",
        /// The far end refused the handshake.
        HandshakeRejected => "handshake_rejected",
        /// The far end presented a certificate that is not this identity —
        /// wrong exit, stale URL, or something in the middle.
        CertMismatch => "cert_mismatch",
        /// Protocol version negotiation failed.
        VersionMismatch => "version_mismatch",
        /// The peer (or something imitating it) broke the protocol.
        ProtocolViolation => "protocol_violation",
        /// Encryption or decryption failed.
        CryptoError => "crypto_error",

        // -- proving who we are ------------------------------------------------
        /// The shared secret was refused.
        AuthRejected => "auth_rejected",
        /// Authentication was never answered.
        AuthTimeout => "auth_timeout",

        // -- staying alive -----------------------------------------------------
        /// Nothing arrived for long enough that the session was reaped.
        IdleTimeout => "idle_timeout",
        /// Liveness probes stopped being answered while the session was
        /// nominally up — the classic "connected but dead" tunnel.
        KeepaliveTimeout => "keepalive_timeout",
        /// The peer closed the session.
        PeerClosed => "peer_closed",
        /// The transport closed under us for some other reason.
        TransportClosed => "transport_closed",
        /// Sending failed.
        SendFailed => "send_failed",
        /// Receiving failed.
        RecvFailed => "recv_failed",

        // -- the direct upgrade -------------------------------------------------
        /// The STUN server did not answer.
        StunTimeout => "stun_timeout",
        /// The STUN exchange failed or returned something unusable.
        StunFailed => "stun_failed",
        /// The peer never told us where to aim within the time allowed.
        ExchangeTimeout => "exchange_timeout",
        /// The two ends offered addresses of different families — nothing to
        /// punch between.
        FamilyMismatch => "family_mismatch",
        /// The peer's candidate was refused by policy (a local, unroutable or
        /// otherwise unacceptable address).
        TargetRejected => "target_rejected",
        /// Punching ran out of time: the two ends never met.
        PunchTimeout => "punch_timeout",
        /// The punched path was never confirmed in both directions.
        VerifyTimeout => "verify_timeout",
        /// The signalling channel went away mid-negotiation.
        SignalClosed => "signal_closed",
        /// Not attempted: the direct upgrade is disabled by configuration.
        UpgradeDisabled => "upgrade_disabled",
        /// Not attempted: this carrier has no path to upgrade.
        UpgradeUnsupported => "upgrade_unsupported",
        /// The new path was built but could not be put into service.
        SwapFailed => "swap_failed",

        // -- ordinary life ------------------------------------------------------
        /// Cancelled locally (shutdown, or a superseding attempt).
        Cancelled => "cancelled",
        /// Superseded: a newer session took this one's place.
        Replaced => "replaced",
        /// The application asked for the session to end.
        LocalShutdown => "local_shutdown",
        /// Storage the run depends on could not be used.
        StorageError => "storage_error",

        /// We genuinely do not know. Used rather than the nearest plausible
        /// code; `detail` may say more.
        Unknown => "unknown",
    }
}

vocabulary! {
    /// How a run ended, as a whole.
    Outcome, fallback = Unknown, {
        /// Still carrying traffic when the record was closed.
        Connected => "connected",
        /// Never got a usable tunnel at all.
        NeverConnected => "never_connected",
        /// Had one, lost it, did not get it back.
        Lost => "lost",
        /// We closed it.
        ClosedLocally => "closed_locally",
        /// The peer closed it.
        ClosedByPeer => "closed_by_peer",
        /// A newer session replaced it.
        Replaced => "replaced",
        /// The record has no ending — the process went away mid-run. A reader
        /// infers this from a missing `close` entry; nothing writes it.
        Unknown => "unknown",
    }
}

vocabulary! {
    /// Whether a packet-size limit was measured or merely asserted. Reading a
    /// carrier's built-in constant as if it were a discovery is exactly the
    /// kind of mistake that quietly poisons a comparison.
    MtuSource, fallback = Unknown, {
        /// Found by probing the path (QUIC's packetization-layer discovery).
        Discovered => "discovered",
        /// A fixed value this carrier declares; nothing was measured.
        Declared => "declared",
        Unknown => "unknown",
    }
}

vocabulary! {
    /// Where a round-trip figure came from, because they are not comparable:
    /// the carrier's own estimate excludes the tunnel, the probe's includes
    /// everything.
    RttSource, fallback = Unknown, {
        /// The QUIC connection's smoothed round-trip estimate.
        Quic => "quic",
        /// A liveness probe through the tunnel and back.
        Keepalive => "keepalive",
        Unknown => "unknown",
    }
}

// ---------------------------------------------------------------------------
// errors that already know their code

/// An error carrying the vocabulary code for how it failed, alongside the
/// human-readable detail.
///
/// The code is chosen where the error is *produced*, never guessed later from
/// its message: a reworded message must not be able to change what a failure
/// counts as. `Display` prints only the detail, so a `Fault` can stand in
/// wherever the crate previously returned a `String`.
#[derive(Debug, Clone)]
pub struct Fault {
    pub reason: Reason,
    pub detail: String,
}

impl Fault {
    pub fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// An error we could not classify. Deliberately verbose to write: an
    /// `unknown` in the data should mean we really did not know.
    pub fn unknown(detail: impl Into<String>) -> Self {
        Self::new(Reason::Unknown, detail)
    }

    /// Add context to the detail while keeping the code.
    pub fn context(mut self, what: &str) -> Self {
        self.detail = format!("{}: {}", what, self.detail);
        self
    }

    /// Classify a socket-level error.
    pub fn from_io(e: &std::io::Error) -> Self {
        use std::io::ErrorKind::*;
        let reason = match e.kind() {
            ConnectionRefused => Reason::ConnectRefused,
            ConnectionReset | BrokenPipe => Reason::ConnectReset,
            TimedOut => Reason::ConnectTimeout,
            PermissionDenied => Reason::PermissionDenied,
            AddrInUse | AddrNotAvailable => Reason::BindFailed,
            NotFound => Reason::DnsNoRecords,
            _ => Self::from_errno(e).unwrap_or(Reason::SocketError),
        };
        Self::new(reason, e.to_string())
    }

    /// The handful of errno values worth distinguishing that `ErrorKind` did
    /// not stabilise early enough to cover.
    #[cfg(unix)]
    fn from_errno(e: &std::io::Error) -> Option<Reason> {
        match e.raw_os_error()? {
            libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENETDOWN => Some(Reason::NoRoute),
            libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT => Some(Reason::FamilyUnsupported),
            _ => None,
        }
    }

    #[cfg(not(unix))]
    fn from_errno(_e: &std::io::Error) -> Option<Reason> {
        None
    }

    /// Classify a QUIC failure on a connection that was already established.
    pub fn from_quinn(e: &quinn::ConnectionError) -> Self {
        Self::from_quinn_in(e, false)
    }

    /// Classify a QUIC failure during the handshake.
    ///
    /// The distinction is not cosmetic: `TimedOut` before a connection exists
    /// means we never got the far end to agree to one, while the same variant
    /// afterwards means an established session went quiet. Counting those as
    /// one thing would merge "we cannot get through" with "the tunnel died".
    pub fn from_quinn_handshake(e: &quinn::ConnectionError) -> Self {
        Self::from_quinn_in(e, true)
    }

    fn from_quinn_in(e: &quinn::ConnectionError, handshake: bool) -> Self {
        use quinn::ConnectionError as C;
        let reason = match e {
            // Note this is deliberately not `no_response`: quinn cannot tell
            // us here whether *nothing* arrived or whether the exchange
            // stalled part-way, and `no_response` is reserved for the places
            // that can prove the former.
            C::TimedOut if handshake => Reason::HandshakeTimeout,
            C::TimedOut => Reason::IdleTimeout,
            C::VersionMismatch => Reason::VersionMismatch,
            C::ApplicationClosed(_) => Reason::PeerClosed,
            C::ConnectionClosed(_) => Reason::HandshakeRejected,
            C::TransportError(te) => {
                // A TLS alert arrives as a CRYPTO_ERROR transport code; the
                // one we care about is the pinned-certificate rejection.
                if u64::from(te.code) >= 0x0100 {
                    Reason::CertMismatch
                } else {
                    Reason::ProtocolViolation
                }
            }
            C::Reset => Reason::ConnectReset,
            C::LocallyClosed => Reason::LocalShutdown,
            C::CidsExhausted => Reason::ProtocolViolation,
        };
        Self::new(reason, e.to_string())
    }

    /// Classify quinn's refusal to even start a connection — a local or
    /// configuration problem, never something the network did.
    pub fn from_quinn_connect(e: &quinn::ConnectError) -> Self {
        use quinn::ConnectError as C;
        let reason = match e {
            C::InvalidRemoteAddress(_) => Reason::FamilyUnsupported,
            C::UnsupportedVersion => Reason::VersionMismatch,
            C::EndpointStopping => Reason::LocalShutdown,
            C::CidsExhausted => Reason::ProtocolViolation,
            _ => Reason::Misconfigured,
        };
        Self::new(reason, e.to_string())
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for Fault {}

impl From<Fault> for String {
    fn from(f: Fault) -> String {
        f.detail
    }
}

impl From<Fault> for std::io::Error {
    fn from(f: Fault) -> std::io::Error {
        std::io::Error::other(f.detail)
    }
}

/// A plain string error, for the paths that have not been given codes yet.
/// Every one of these is an honest `unknown` in the data rather than a
/// plausible-looking guess.
impl From<String> for Fault {
    fn from(detail: String) -> Self {
        Self::unknown(detail)
    }
}

impl From<std::io::Error> for Fault {
    fn from(e: std::io::Error) -> Self {
        Self::from_io(&e)
    }
}

// ---------------------------------------------------------------------------
// the entries

/// What this build is, stamped on every record. Comparing results across time
/// is worthless without it (and a build with uncommitted changes must say so,
/// or it quietly pollutes comparisons for months).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Build {
    /// Crate version.
    pub version: String,
    /// Source commit, when the build could determine one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// The working tree had uncommitted changes when this was built.
    pub dirty: bool,
    /// Target triple.
    pub target: String,
    /// `debug` or `release`.
    pub profile: String,
}

/// A relay/peer endpoint as configured, before or after resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRef {
    pub host: String,
    pub port: u16,
    pub carrier: Carrier,
    pub path: PathKind,
    /// The resolved address, once known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
}

/// Opens a record: everything that is true of the whole run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Open {
    /// Format version ([`FORMAT_VERSION`]).
    pub v: u32,
    /// Identifier for this record, unique per run.
    pub id: String,
    pub role: Role,
    /// Wall-clock start, milliseconds since the Unix epoch. Every other
    /// timestamp in the record is milliseconds *since this instant*, measured
    /// monotonically — so a clock step mid-run cannot reorder the story.
    pub at_unix_ms: u64,
    pub build: Build,
    /// The identity this run serves or dials, as hex. It is what pairs the
    /// two ends' records with each other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_key: Option<String>,
    /// Endpoints configured for this run, in preference order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<EndpointRef>,
    /// Whether the direct upgrade was allowed to run.
    pub upgrade_enabled: bool,
    /// Operator-supplied label for the machine or installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Operator-supplied identifier tying this run to something outside it —
    /// a support ticket, a test run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// One thing that was attempted, and how it came out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    /// Milliseconds since the record opened — when the step *began*, so the
    /// steps read as a timeline. `dur_ms` says when it ended.
    pub at_ms: u64,
    /// Monotonic sequence number within the record. A later entry with the
    /// same number supersedes an earlier one (a conclusion replacing its own
    /// `started` entry).
    pub seq: u64,
    pub kind: StepKind,
    pub outcome: StepOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// How long the step took, when it is something that takes time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dur_ms: Option<u64>,
    /// Exit side: which accepted session this belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<u32>,
    /// Client side: which dial cycle this belongs to (0 = the first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycle: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier: Option<Carrier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathKind>,
    /// What was being reached through: a relay, a STUN server, a peer's
    /// advertised endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Human-readable extra. **Never** the basis of analysis: it is not
    /// stable and it is not a vocabulary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A measurement taken while the tunnel was up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub id: String,
    pub at_ms: u64,
    pub path: PathKind,
    pub carrier: Carrier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycle: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_src: Option<RttSource>,
    /// Cumulative tunnel traffic since the session started.
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    /// Rates over the interval since the previous sample.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_bps: Option<u64>,
    /// Carrier-reported loss, when the carrier counts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_pkts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwnd: Option<u64>,
    /// The packet-size limit currently in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Whether that limit was measured or merely declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu_src: Option<MtuSource>,
    /// Liveness probes sent and unanswered, cumulative. The only loss figure
    /// available on every carrier — coarse, but comparable across all of
    /// them, and it measures the tunnel rather than one leg of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes_lost: Option<u64>,
}

/// Entries that were dropped because the writer could not keep up. An absence
/// of entries must never be mistakable for an absence of events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gap {
    pub id: String,
    pub at_ms: u64,
    pub dropped: u64,
}

/// Closes a record: the terminal outcome and the summary anyone comparing two
/// runs will reach for first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Close {
    pub id: String,
    pub at_ms: u64,
    pub at_unix_ms: u64,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// How many times a usable tunnel existed during this run.
    pub sessions: u32,
    /// How many re-dial cycles were started.
    pub reconnects: u32,
    /// Time from the first action to the first usable tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_connect_ms: Option<u64>,
    /// Time from the first action to traffic riding a direct path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_ms: Option<u64>,
    /// Total time a usable tunnel existed.
    pub connected_ms: u64,
    /// Total tunnel traffic over the run, from the last sample taken.
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// One line of a record stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Entry {
    Open(Open),
    Step(Step),
    Sample(Sample),
    Gap(Gap),
    Close(Close),
}

impl Entry {
    pub fn at_ms(&self) -> u64 {
        match self {
            Entry::Open(_) => 0,
            Entry::Step(s) => s.at_ms,
            Entry::Sample(s) => s.at_ms,
            Entry::Gap(g) => g.at_ms,
            Entry::Close(c) => c.at_ms,
        }
    }
}

/// A whole record, folded back from its entry stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub open: Open,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default)]
    pub samples: Vec<Sample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<Gap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close: Option<Close>,
    /// The stream ended without a close entry — the process went away
    /// mid-run. Everything above is still true; the ending is simply unknown.
    pub truncated: bool,
}

impl Record {
    /// The terminal outcome, or [`Outcome::Unknown`] for a truncated record.
    pub fn outcome(&self) -> Outcome {
        self.close
            .as_ref()
            .map(|c| c.outcome)
            .unwrap_or(Outcome::Unknown)
    }

    /// The first failing step, which is usually the answer to "why didn't it
    /// work" — later failures tend to be consequences.
    pub fn first_failure(&self) -> Option<&Step> {
        self.steps.iter().find(|s| s.outcome == StepOutcome::Failed)
    }

    /// Every distinct failure reason in the record, in the order first seen.
    pub fn failure_reasons(&self) -> Vec<Reason> {
        let mut out: Vec<Reason> = Vec::new();
        for s in &self.steps {
            if s.outcome == StepOutcome::Failed
                && let Some(r) = s.reason
                && !out.contains(&r)
            {
                out.push(r);
            }
        }
        out
    }

    /// The record as one JSON object.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// The record as one indented JSON object.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// Steps of one kind, oldest first.
    pub fn steps_of(&self, kind: StepKind) -> impl Iterator<Item = &Step> {
        self.steps.iter().filter(move |s| s.kind == kind)
    }
}

// ---------------------------------------------------------------------------
// what this build is

/// This build's identity. `build.rs` supplies the commit and target; all of
/// it degrades to something honest if it could not.
pub fn build_info() -> Build {
    Build {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("SPORA_BUILD_COMMIT")
            .filter(|c| !c.is_empty())
            .map(str::to_string),
        dirty: matches!(option_env!("SPORA_BUILD_DIRTY"), Some("1")),
        target: option_env!("SPORA_BUILD_TARGET")
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)),
        profile: if cfg!(debug_assertions) {
            "debug".into()
        } else {
            "release".into()
        },
    }
}

// ---------------------------------------------------------------------------
// configuration

/// Called inline for every entry as it is produced. **Must not block** — the
/// tunnel's own tasks are the ones calling it. An application that wants to
/// do real work with entries should push them into a channel and return.
pub type RecordSubscriber = Arc<dyn Fn(&Entry) + Send + Sync>;

/// How this process records. `None` on [`crate::Config`] means no recording
/// at all: the core does not write to a user's disk unless the platform asks
/// it to.
#[derive(Clone)]
pub struct RecordConfig {
    /// Directory to append record files to. `None` keeps the record in
    /// memory only, for a caller that reads it through [`Recorder::snapshot`]
    /// or a [`RecordSubscriber`].
    pub dir: Option<PathBuf>,
    /// How often to take a quality sample while a tunnel is up. Zero
    /// disables sampling.
    pub sample_interval: Duration,
    /// Record files to keep in `dir` (oldest deleted first).
    pub keep_files: usize,
    /// Record files older than this are deleted.
    pub max_age: Duration,
    /// Ceiling on one record file. Past it, samples are dropped (and counted
    /// in a [`Gap`]) while steps keep being written: the story survives, the
    /// telemetry is what gets cut.
    pub max_file_bytes: u64,
    /// Entries kept in memory for [`Recorder::snapshot`].
    pub max_entries: usize,
    /// Label for this machine or installation, copied into every record.
    pub label: Option<String>,
    /// Identifier tying this run to something outside it.
    pub correlation_id: Option<String>,
    /// In-process consumer of entries as they happen.
    pub subscriber: Option<RecordSubscriber>,
}

impl Default for RecordConfig {
    fn default() -> Self {
        Self {
            dir: None,
            sample_interval: Duration::from_secs(30),
            keep_files: 100,
            max_age: Duration::from_secs(30 * 24 * 60 * 60),
            max_file_bytes: 32 * 1024 * 1024,
            max_entries: 4096,
            label: None,
            correlation_id: None,
            subscriber: None,
        }
    }
}

impl RecordConfig {
    /// Append records to files in `dir`.
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: Some(dir.into()),
            ..Default::default()
        }
    }

    /// Keep the record in memory only.
    pub fn in_memory() -> Self {
        Self::default()
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    pub fn with_subscriber(mut self, sub: RecordSubscriber) -> Self {
        self.subscriber = Some(sub);
        self
    }
}

// ---------------------------------------------------------------------------
// the recorder

/// The handle instrumentation talks to. Cloning is cheap; a clone can carry
/// extra context (which session, which dial cycle) that every entry it
/// produces inherits.
///
/// A [`Recorder::disabled`] handle accepts every call and does nothing, so
/// instrumentation never needs to ask whether recording is on.
#[derive(Clone)]
pub struct Recorder {
    inner: Option<Arc<Inner>>,
    session: Option<u32>,
    cycle: Option<u32>,
}

struct Inner {
    id: String,
    t0: Instant,
    seq: AtomicU64,
    closed: AtomicBool,
    state: Mutex<State>,
    sink: Option<Sink>,
    subscriber: Option<RecordSubscriber>,
    max_entries: usize,
    sample_interval: Duration,
}

struct State {
    open: Open,
    steps: Vec<Step>,
    samples: std::collections::VecDeque<Sample>,
    gaps: Vec<Gap>,
    close: Option<Close>,
    /// Entries not kept in memory (the disk still has them).
    dropped_in_memory: u64,
    /// Previous sample's (at_ms, tx_bytes, rx_bytes), for interval rates.
    last_sample: Option<(u64, u64, u64)>,
    /// Bookkeeping for the closing summary.
    sessions: u32,
    reconnects: u32,
    first_connect_ms: Option<u64>,
    direct_ms: Option<u64>,
    connected_ms: u64,
    /// When the current session came up, if one is up.
    up_since_ms: Option<u64>,
    tx_bytes: u64,
    rx_bytes: u64,
}

impl Recorder {
    /// A handle that records nothing.
    pub fn disabled() -> Self {
        Self {
            inner: None,
            session: None,
            cycle: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Open a record for one run.
    ///
    /// Recording never gets in the way of connecting: if the directory cannot
    /// be used, this logs and degrades to memory-only rather than failing.
    pub fn start(
        cfg: &RecordConfig,
        role: Role,
        routing_key: Option<&[u8]>,
        endpoints: Vec<EndpointRef>,
        upgrade_enabled: bool,
    ) -> Self {
        let id = new_id();
        let at_unix_ms = unix_ms();
        let open = Open {
            v: FORMAT_VERSION,
            id: id.clone(),
            role,
            at_unix_ms,
            build: build_info(),
            routing_key: routing_key.map(hex),
            endpoints,
            upgrade_enabled,
            label: cfg.label.clone(),
            correlation_id: cfg.correlation_id.clone(),
        };

        let sink = cfg
            .dir
            .as_ref()
            .and_then(|dir| Sink::open(dir, cfg, role, at_unix_ms, &id));

        let inner = Arc::new(Inner {
            id,
            t0: Instant::now(),
            seq: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            state: Mutex::new(State {
                open: open.clone(),
                steps: Vec::new(),
                samples: std::collections::VecDeque::new(),
                gaps: Vec::new(),
                close: None,
                dropped_in_memory: 0,
                last_sample: None,
                sessions: 0,
                reconnects: 0,
                first_connect_ms: None,
                direct_ms: None,
                connected_ms: 0,
                up_since_ms: None,
                tx_bytes: 0,
                rx_bytes: 0,
            }),
            sink,
            subscriber: cfg.subscriber.clone(),
            max_entries: cfg.max_entries.max(64),
            sample_interval: cfg.sample_interval,
        });

        let rec = Self {
            inner: Some(inner),
            session: None,
            cycle: None,
        };
        rec.emit(Entry::Open(open));
        rec
    }

    /// This record's identifier.
    pub fn id(&self) -> Option<&str> {
        self.inner.as_deref().map(|i| i.id.as_str())
    }

    /// Milliseconds since the record opened.
    pub fn elapsed_ms(&self) -> u64 {
        self.inner
            .as_ref()
            .map(|i| i.t0.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }

    /// How often quality samples should be taken.
    pub fn sample_interval(&self) -> Duration {
        self.inner
            .as_ref()
            .map(|i| i.sample_interval)
            .unwrap_or(Duration::ZERO)
    }

    /// A clone whose entries are tagged with an exit-side session number.
    pub fn for_session(&self, session: u32) -> Self {
        Self {
            inner: self.inner.clone(),
            session: Some(session),
            cycle: self.cycle,
        }
    }

    /// A clone whose entries are tagged with a client-side dial cycle
    /// (0 = the first dial, 1 = after the first reconnect, …).
    pub fn for_cycle(&self, cycle: u32) -> Self {
        Self {
            inner: self.inner.clone(),
            session: self.session,
            cycle: Some(cycle),
        }
    }

    /// Begin a step. The returned handle must be concluded — `ok`, `fail`,
    /// `skip` — or it records itself as [`StepOutcome::Abandoned`] when
    /// dropped.
    pub fn step(&self, kind: StepKind) -> StepHandle {
        StepHandle {
            rec: self.clone(),
            kind,
            seq: self.next_seq(),
            start_ms: self.elapsed_ms(),
            t0: Instant::now(),
            timed: true,
            started: false,
            carrier: None,
            path: None,
            via: None,
            local: None,
            peer: None,
            detail: None,
            done: false,
        }
    }

    /// Begin a step and write it out immediately as `started`, so that a
    /// record which stops here shows what was in flight. Worth it for
    /// anything that can hang: without it, a stuck attempt and a killed
    /// process produce identical records.
    pub fn step_now(&self, kind: StepKind) -> StepHandle {
        let mut h = self.step(kind);
        h.started = true;
        h.emit(StepOutcome::Started, None, None);
        h
    }

    /// Record something instantaneous that succeeded.
    pub fn mark(&self, kind: StepKind) -> StepHandle {
        let mut h = self.step(kind);
        h.timed = false;
        h
    }

    /// Take a quality sample.
    pub fn sample(&self, s: SampleInput) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        let at_ms = self.elapsed_ms();
        let (tx_bps, rx_bps) = {
            let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
            st.tx_bytes = s.tx_bytes;
            st.rx_bytes = s.rx_bytes;
            let rates = st.last_sample.and_then(|(prev_ms, prev_tx, prev_rx)| {
                let dt = at_ms.saturating_sub(prev_ms);
                (dt > 0).then(|| {
                    (
                        s.tx_bytes.saturating_sub(prev_tx) * 8 * 1000 / dt,
                        s.rx_bytes.saturating_sub(prev_rx) * 8 * 1000 / dt,
                    )
                })
            });
            st.last_sample = Some((at_ms, s.tx_bytes, s.rx_bytes));
            match rates {
                Some((tx, rx)) => (Some(tx), Some(rx)),
                None => (None, None),
            }
        };
        self.emit(Entry::Sample(Sample {
            id: inner.id.clone(),
            at_ms,
            path: s.path,
            carrier: s.carrier,
            session: self.session,
            cycle: self.cycle,
            rtt_ms: s.rtt_ms,
            rtt_src: s.rtt_src,
            tx_bytes: s.tx_bytes,
            rx_bytes: s.rx_bytes,
            tx_pkts: s.tx_pkts,
            rx_pkts: s.rx_pkts,
            tx_bps,
            rx_bps,
            lost_pkts: s.lost_pkts,
            cwnd: s.cwnd,
            mtu: s.mtu,
            mtu_src: s.mtu_src,
            probes_sent: s.probes_sent,
            probes_lost: s.probes_lost,
        }));
    }

    /// Close the record. The first call wins; later ones are ignored, so
    /// several teardown paths racing each other is harmless.
    pub fn close(&self, outcome: Outcome, reason: Option<Reason>, detail: Option<String>) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        finish(inner, outcome, reason, detail);
    }

    /// Close a record whose run is ending in the ordinary way, deriving the
    /// outcome from what actually happened: a tunnel that was up when the
    /// caller stopped is `closed_locally`, one that came up and went away is
    /// `lost`, one that never came up is `never_connected`.
    pub fn close_shutdown(&self, reason: Option<Reason>) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        let outcome = {
            let st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
            match (st.up_since_ms.is_some(), st.sessions > 0) {
                (true, _) => Outcome::ClosedLocally,
                (false, true) => Outcome::Lost,
                (false, false) => Outcome::NeverConnected,
            }
        };
        self.close(outcome, reason, None);
    }

    /// Whether a usable tunnel has existed at any point in this run.
    pub fn has_connected(&self) -> bool {
        self.inner
            .as_ref()
            .map(|i| i.state.lock().unwrap_or_else(|e| e.into_inner()).sessions > 0)
            .unwrap_or(false)
    }

    /// The record as it stands, without reading anything back from disk.
    pub fn snapshot(&self) -> Option<Record> {
        let inner = self.inner.as_ref()?;
        let st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut gaps = st.gaps.clone();
        if st.dropped_in_memory > 0 {
            gaps.push(Gap {
                id: inner.id.clone(),
                at_ms: self.elapsed_ms(),
                dropped: st.dropped_in_memory,
            });
        }
        Some(Record {
            open: st.open.clone(),
            steps: st.steps.clone(),
            samples: st.samples.iter().cloned().collect(),
            gaps,
            close: st.close.clone(),
            truncated: st.close.is_none(),
        })
    }

    fn next_seq(&self) -> u64 {
        self.inner
            .as_ref()
            .map(|i| i.seq.fetch_add(1, Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Fold a concluded step into the running summary. Kept in one place so
    /// the closing figures cannot drift from the steps that produced them.
    fn account(&self, st: &mut State, step: &Step) {
        Self::account_into(st, step)
    }

    fn account_into(st: &mut State, step: &Step) {
        match (step.kind, step.outcome) {
            (StepKind::SessionUp, StepOutcome::Ok) => {
                st.sessions += 1;
                st.first_connect_ms.get_or_insert(step.at_ms);
                st.up_since_ms.get_or_insert(step.at_ms);
            }
            (StepKind::SessionEnd, _) => {
                if let Some(up) = st.up_since_ms.take() {
                    st.connected_ms += step.at_ms.saturating_sub(up);
                }
            }
            (StepKind::Reconnect, _) => {
                st.reconnects += 1;
                if let Some(up) = st.up_since_ms.take() {
                    st.connected_ms += step.at_ms.saturating_sub(up);
                }
            }
            (StepKind::PathSwap, StepOutcome::Ok) => {
                st.direct_ms.get_or_insert(step.at_ms);
            }
            _ => {}
        }
    }

    fn emit(&self, entry: Entry) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        {
            let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
            match &entry {
                Entry::Step(s) if s.outcome == StepOutcome::Started => {
                    if st.steps.len() < inner.max_entries {
                        st.steps.push(s.clone());
                    } else {
                        st.dropped_in_memory += 1;
                    }
                }
                Entry::Step(s) => {
                    // A conclusion supersedes its own `started` entry rather
                    // than appearing twice.
                    if let Some(prev) = st.steps.iter_mut().rev().find(|p| p.seq == s.seq) {
                        *prev = s.clone();
                        fold_superseding(&mut st, s);
                        drop(st);
                        self.forward(entry);
                        return;
                    }
                    self.account(&mut st, s);
                    if st.steps.len() < inner.max_entries {
                        st.steps.push(s.clone());
                    } else {
                        // Keep the beginning of the story: that is where the
                        // explanation usually is.
                        st.dropped_in_memory += 1;
                    }
                }
                Entry::Sample(s) => {
                    if st.samples.len() >= inner.max_entries {
                        st.samples.pop_front();
                        st.dropped_in_memory += 1;
                    }
                    st.samples.push_back(s.clone());
                }
                Entry::Gap(g) => st.gaps.push(g.clone()),
                Entry::Open(_) | Entry::Close(_) => {}
            }
        }
        self.forward(entry);
    }

    fn forward(&self, entry: Entry) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        if let Some(sink) = inner.sink.as_ref() {
            sink.send(&inner.id, entry.at_ms(), entry.clone());
        }
        if let Some(sub) = inner.subscriber.as_ref() {
            sub(&entry);
        }
    }
}

/// Write a record's ending. The first call wins, so several teardown paths
/// racing each other — an explicit close, a cancelled session, the recorder
/// simply being dropped — produce one ending, not three.
fn finish(inner: &Inner, outcome: Outcome, reason: Option<Reason>, detail: Option<String>) {
    if inner.closed.swap(true, Ordering::SeqCst) {
        return;
    }
    let at_ms = inner.t0.elapsed().as_millis() as u64;
    let close = {
        let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(up) = st.up_since_ms.take() {
            st.connected_ms += at_ms.saturating_sub(up);
        }
        let c = Close {
            id: inner.id.clone(),
            at_ms,
            at_unix_ms: unix_ms(),
            outcome,
            reason,
            detail,
            sessions: st.sessions,
            reconnects: st.reconnects,
            first_connect_ms: st.first_connect_ms,
            direct_ms: st.direct_ms,
            connected_ms: st.connected_ms,
            tx_bytes: st.tx_bytes,
            rx_bytes: st.rx_bytes,
        };
        st.close = Some(c.clone());
        c
    };
    let entry = Entry::Close(close);
    if let Some(sink) = inner.sink.as_ref() {
        sink.send(&inner.id, at_ms, entry.clone());
    }
    if let Some(sub) = inner.subscriber.as_ref() {
        sub(&entry);
    }
}

impl Drop for Inner {
    /// Nobody closed this record explicitly, and the last handle to it has
    /// gone — so the run is over whether or not anyone said so. The outcome
    /// is derived from what happened rather than assumed, and the detail
    /// says plainly that the ending was inferred.
    fn drop(&mut self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let outcome = {
            let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.sessions > 0 {
                Outcome::Lost
            } else {
                Outcome::NeverConnected
            }
        };
        finish(
            self,
            outcome,
            None,
            Some("no explicit ending: the recorder was dropped".into()),
        );
    }
}

/// Fold a superseding step into the summary exactly once: a `started` entry
/// contributes nothing, its conclusion does.
fn fold_superseding(st: &mut State, s: &Step) {
    if s.outcome != StepOutcome::Started {
        Recorder::account_into(st, s);
    }
}

/// The numbers a quality sample is built from. Assembled by whoever has
/// access to the carrier; the recorder adds timing and rates.
#[derive(Debug, Clone)]
pub struct SampleInput {
    pub path: PathKind,
    pub carrier: Carrier,
    pub rtt_ms: Option<f64>,
    pub rtt_src: Option<RttSource>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    pub lost_pkts: Option<u64>,
    pub cwnd: Option<u64>,
    pub mtu: Option<u16>,
    pub mtu_src: Option<MtuSource>,
    pub probes_sent: Option<u64>,
    pub probes_lost: Option<u64>,
}

impl Carrier {
    /// The carrier an endpoint's protocol implies. Kept next to the
    /// vocabulary so the two stay in step when a protocol is added.
    pub fn of_protocol(p: crate::identity::RelayProtocol) -> Carrier {
        use crate::identity::RelayProtocol as P;
        match p {
            P::UdpQuic | P::Direct => Carrier::Quic,
            P::TcpTls => Carrier::TcpTls,
            P::NoiseUdp => Carrier::NoiseUdp,
        }
    }
}

impl PathKind {
    /// Whether an endpoint's protocol goes through a relay. `Direct` here is
    /// an address the exit advertised for itself — not the punched path,
    /// which only exists after an upgrade.
    pub fn of_protocol(p: crate::identity::RelayProtocol) -> PathKind {
        use crate::identity::RelayProtocol as P;
        match p {
            P::UdpQuic | P::TcpTls | P::NoiseUdp => PathKind::Relay,
            P::Direct => PathKind::DirectAdvertised,
        }
    }
}

/// Which path traffic is currently attributed to, shared between whoever
/// swaps paths and whoever samples.
///
/// It is set where a new path is handed to the transport router; the swap
/// itself applies on the router's next poll, so a sample taken in that
/// window may be attributed a few milliseconds early. The `path_swap` step
/// carries the authoritative instant.
#[derive(Debug)]
pub struct PathState(std::sync::atomic::AtomicU8);

impl PathState {
    pub fn new(path: PathKind) -> Self {
        Self(std::sync::atomic::AtomicU8::new(path_code(path)))
    }

    pub fn set(&self, path: PathKind) {
        self.0.store(path_code(path), Ordering::Relaxed);
    }

    pub fn get(&self) -> PathKind {
        match self.0.load(Ordering::Relaxed) {
            1 => PathKind::Relay,
            2 => PathKind::DirectAdvertised,
            3 => PathKind::DirectPunched,
            _ => PathKind::Unknown,
        }
    }
}

fn path_code(path: PathKind) -> u8 {
    match path {
        PathKind::Relay => 1,
        PathKind::DirectAdvertised => 2,
        PathKind::DirectPunched => 3,
        PathKind::Unknown => 0,
    }
}

impl Default for SampleInput {
    /// Everything unknown until someone fills it in — which is the honest
    /// starting point, and means a carrier that cannot report a figure
    /// simply leaves it absent rather than reporting a zero.
    fn default() -> Self {
        Self {
            path: PathKind::Unknown,
            carrier: Carrier::Unknown,
            rtt_ms: None,
            rtt_src: None,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_pkts: 0,
            rx_pkts: 0,
            lost_pkts: None,
            cwnd: None,
            mtu: None,
            mtu_src: None,
            probes_sent: None,
            probes_lost: None,
        }
    }
}

/// A step in progress. Conclude it, or dropping it records that nobody did.
#[must_use = "a step that is never concluded records itself as abandoned"]
pub struct StepHandle {
    rec: Recorder,
    kind: StepKind,
    seq: u64,
    /// When this step began, relative to the record's start.
    start_ms: u64,
    t0: Instant,
    timed: bool,
    /// Whether a `started` entry was already written for this step.
    started: bool,
    carrier: Option<Carrier>,
    path: Option<PathKind>,
    via: Option<String>,
    local: Option<String>,
    peer: Option<String>,
    detail: Option<String>,
    done: bool,
}

impl StepHandle {
    /// What this step was reaching through or aiming at.
    pub fn via(mut self, via: impl fmt::Display) -> Self {
        self.via = Some(via.to_string());
        self
    }

    pub fn local(mut self, addr: impl fmt::Display) -> Self {
        self.local = Some(addr.to_string());
        self
    }

    pub fn peer(mut self, addr: impl fmt::Display) -> Self {
        self.peer = Some(addr.to_string());
        self
    }

    pub fn carrier(mut self, carrier: Carrier) -> Self {
        self.carrier = Some(carrier);
        self
    }

    pub fn path(mut self, path: PathKind) -> Self {
        self.path = Some(path);
        self
    }

    /// Human-readable extra. Not a vocabulary; never analysed.
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn ok(self) {
        self.finish(StepOutcome::Ok, None, None)
    }

    pub fn fail(self, reason: Reason, detail: impl Into<String>) {
        self.finish(StepOutcome::Failed, Some(reason), Some(detail.into()))
    }

    /// Conclude from an error that already knows its code.
    pub fn fail_with(self, f: &Fault) {
        self.finish(StepOutcome::Failed, Some(f.reason), Some(f.detail.clone()))
    }

    /// Deliberately not attempted — a different fact from failing.
    pub fn skip(self, reason: Reason, detail: impl Into<String>) {
        self.finish(StepOutcome::Skipped, Some(reason), Some(detail.into()))
    }

    /// Conclude from a `Result`, which is what most call sites have.
    pub fn result<T>(self, r: &Result<T, Fault>) {
        match r {
            Ok(_) => self.ok(),
            Err(f) => self.fail_with(f),
        }
    }

    fn finish(mut self, outcome: StepOutcome, reason: Option<Reason>, detail: Option<String>) {
        self.done = true;
        self.emit(outcome, reason, detail);
    }

    fn emit(&self, outcome: StepOutcome, reason: Option<Reason>, detail: Option<String>) {
        let Some(inner) = self.rec.inner.as_ref() else {
            return;
        };
        let step = Step {
            id: inner.id.clone(),
            // A timed step is stamped with when it started; an instantaneous
            // one with now. Otherwise a slow step would appear to happen
            // after everything it in fact preceded.
            at_ms: if self.timed {
                self.start_ms
            } else {
                self.rec.elapsed_ms()
            },
            seq: self.seq,
            kind: self.kind,
            outcome,
            reason,
            dur_ms: self.timed.then(|| self.t0.elapsed().as_millis() as u64),
            session: self.rec.session,
            cycle: self.rec.cycle,
            carrier: self.carrier,
            path: self.path,
            via: self.via.clone(),
            local: self.local.clone(),
            peer: self.peer.clone(),
            detail: detail.or_else(|| self.detail.clone()),
        };
        self.rec.emit(Entry::Step(step));
    }
}

impl Drop for StepHandle {
    fn drop(&mut self) {
        if !self.done {
            self.emit(StepOutcome::Abandoned, None, None);
        }
    }
}

// ---------------------------------------------------------------------------
// the writer

/// The handle the async side holds: a bounded queue toward a writer thread.
/// Recording must never block a tunnel, so a full queue drops the entry and
/// counts it — and the count is written out as a [`Gap`] as soon as there is
/// room, because an absence of entries that cannot be told apart from an
/// absence of events would quietly destroy the record's value.
struct Sink {
    tx: Option<SyncSender<Entry>>,
    dropped: AtomicU64,
    /// A dead writer thread cannot write its own gap marker, so it has to be
    /// said out loud once instead.
    complained: AtomicBool,
    writer: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Sink {
    fn drop(&mut self) {
        // Close the queue so the writer drains and exits, then wait for it: a
        // record still in flight when the process ends is a record nobody
        // has, and the ending is the part most worth having.
        self.tx.take();
        if let Some(h) = self.writer.take() {
            let _ = h.join();
        }
    }
}

impl Sink {
    fn open(dir: &Path, cfg: &RecordConfig, role: Role, at_unix_ms: u64, id: &str) -> Option<Sink> {
        if let Err(e) = std::fs::create_dir_all(dir) {
            warn!(
                "record: cannot create {} ({e}); keeping the record in memory only",
                dir.display()
            );
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        sweep(dir, cfg.keep_files, cfg.max_age);

        let name = format!(
            "{}-{}-{}.jsonl",
            utc_stamp(at_unix_ms),
            role.as_str(),
            &id[..8.min(id.len())]
        );
        let path = dir.join(name);
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    "record: cannot write {} ({e}); keeping the record in memory only",
                    path.display()
                );
                return None;
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_CAPACITY);
        let max_bytes = cfg.max_file_bytes;
        let display = path.display().to_string();
        let writer = match std::thread::Builder::new()
            .name("spora-record".into())
            .spawn(move || writer_loop(file, rx, max_bytes, &display))
        {
            Ok(h) => h,
            Err(e) => {
                warn!("record: cannot start the writer thread ({e}); memory only");
                return None;
            }
        };
        debug!("record: writing {}", path.display());
        Some(Sink {
            tx: Some(tx),
            dropped: AtomicU64::new(0),
            complained: AtomicBool::new(false),
            writer: Some(writer),
        })
    }

    fn send(&self, id: &str, at_ms: u64, entry: Entry) {
        let Some(tx) = self.tx.as_ref() else {
            return;
        };
        let pending = self.dropped.load(Ordering::Relaxed);
        if pending > 0 {
            let gap = Entry::Gap(Gap {
                id: id.to_string(),
                at_ms,
                dropped: pending,
            });
            if tx.try_send(gap).is_ok() {
                self.dropped.fetch_sub(pending, Ordering::Relaxed);
            }
        }
        match tx.try_send(entry) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                if !self.complained.swap(true, Ordering::Relaxed) {
                    warn!("record: the writer thread is gone; this record stops here on disk");
                }
            }
        }
    }
}

fn writer_loop(file: std::fs::File, rx: Receiver<Entry>, max_bytes: u64, path: &str) {
    use std::io::Write;
    let mut out = std::io::BufWriter::new(file);
    let mut written: u64 = out.get_ref().metadata().map(|m| m.len()).unwrap_or(0);
    let mut dropped_by_size: u64 = 0;
    let mut complained = false;

    while let Ok(entry) = rx.recv() {
        let is_sample = matches!(entry, Entry::Sample(_));
        // A run that lasts for months must not fill a disk. Steps are the
        // story and keep being written; the periodic telemetry is what gets
        // cut, and the cut is recorded.
        if written >= max_bytes && is_sample {
            dropped_by_size += 1;
            continue;
        }
        if dropped_by_size > 0 && !is_sample {
            let gap = Entry::Gap(Gap {
                id: String::new(),
                at_ms: entry.at_ms(),
                dropped: dropped_by_size,
            });
            if let Ok(line) = serde_json::to_string(&gap) {
                let _ = writeln!(out, "{line}");
                written += line.len() as u64 + 1;
            }
            dropped_by_size = 0;
        }
        let line = match serde_json::to_string(&entry) {
            Ok(l) => l,
            Err(e) => {
                warn!("record: cannot serialize an entry ({e})");
                continue;
            }
        };
        if let Err(e) = writeln!(out, "{line}") {
            if !complained {
                warn!("record: writing {path} failed ({e}); the record will be incomplete");
                complained = true;
            }
            continue;
        }
        written += line.len() as u64 + 1;
        // Volume is a handful of lines a minute: flush every one so a record
        // survives the process being killed, which is exactly when it is
        // most worth having.
        let _ = out.flush();
    }
    let _ = out.flush();
}

/// Delete the oldest record files beyond `keep`, and anything past `max_age`.
fn sweep(dir: &Path, keep: usize, max_age: Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            Some((m.modified().ok()?, e.path()))
        })
        .collect();
    files.sort_by_key(|(t, _)| *t);
    let now = SystemTime::now();
    let excess = files.len().saturating_sub(keep);
    for (i, (modified, path)) in files.iter().enumerate() {
        let too_old = now
            .duration_since(*modified)
            .map(|age| age > max_age)
            .unwrap_or(false);
        if i < excess || too_old {
            let _ = std::fs::remove_file(path);
        }
    }
}

// ---------------------------------------------------------------------------
// reading records back

/// Record files in `dir`, newest first.
pub fn list_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files: Vec<(SystemTime, PathBuf)> = std::fs::read_dir(dir)?
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            Some((m.modified().ok()?, e.path()))
        })
        .collect();
    files.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    Ok(files.into_iter().map(|(_, p)| p).collect())
}

impl Record {
    /// Fold an entry stream back into records. Unparseable lines are skipped:
    /// a torn last line (the process died mid-write) must not cost the rest.
    pub fn read_stream(reader: impl std::io::BufRead) -> Vec<Record> {
        let mut out: Vec<Record> = Vec::new();
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<Entry>(line) else {
                continue;
            };
            match entry {
                Entry::Open(open) => out.push(Record {
                    open,
                    steps: Vec::new(),
                    samples: Vec::new(),
                    gaps: Vec::new(),
                    close: None,
                    truncated: true,
                }),
                other => {
                    let Some(rec) = out.last_mut() else { continue };
                    match other {
                        Entry::Step(s) => match rec.steps.iter_mut().rev().find(|p| p.seq == s.seq)
                        {
                            // The conclusion of a step replaces the `started`
                            // entry written when it began.
                            Some(prev) => *prev = s,
                            None => rec.steps.push(s),
                        },
                        Entry::Sample(s) => rec.samples.push(s),
                        Entry::Gap(g) => rec.gaps.push(g),
                        Entry::Close(c) => {
                            rec.close = Some(c);
                            rec.truncated = false;
                        }
                        Entry::Open(_) => unreachable!(),
                    }
                }
            }
        }
        out
    }

    /// Read one record file.
    pub fn read_file(path: &Path) -> std::io::Result<Vec<Record>> {
        let file = std::fs::File::open(path)?;
        Ok(Self::read_stream(std::io::BufReader::new(file)))
    }

    /// Read every record in a directory, newest file first.
    pub fn read_dir(dir: &Path) -> std::io::Result<Vec<(PathBuf, Record)>> {
        let mut out = Vec::new();
        for path in list_files(dir)? {
            for rec in Self::read_file(&path)? {
                out.push((path.clone(), rec));
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// small helpers

fn new_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `YYYYmmddTHHMMSSZ`, so file names sort chronologically.
fn utc_stamp(unix_ms: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_unix_ms(unix_ms);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// `YYYY-MM-DD HH:MM:SSZ`, for reading.
pub fn utc_timestamp(unix_ms: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_unix_ms(unix_ms);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}Z")
}

/// Hand-rolled to avoid a date dependency for two format strings (Howard
/// Hinnant's civil-from-days).
fn civil_from_unix_ms(unix_ms: u64) -> (i64, i64, i64, i64, i64, i64) {
    let secs = (unix_ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, tod / 3600, (tod % 3600) / 60, tod % 60)
}

/// Several records as one JSON array — what to hand to someone else.
pub fn records_to_json(records: &[Record]) -> String {
    serde_json::to_string_pretty(records).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire codes are the format. A duplicate would silently merge two
    /// distinct facts in every count anyone ever runs.
    #[test]
    fn codes_are_unique_within_each_vocabulary() {
        fn unique<T: Copy + Ord + fmt::Debug>(all: &[T], code: impl Fn(T) -> &'static str) {
            let mut codes: Vec<&str> = all.iter().map(|v| code(*v)).collect();
            let before = codes.len();
            codes.sort_unstable();
            codes.dedup();
            assert_eq!(before, codes.len(), "duplicate wire code");
        }
        unique(Reason::ALL, Reason::as_str);
        unique(StepKind::ALL, StepKind::as_str);
        unique(StepOutcome::ALL, StepOutcome::as_str);
        unique(Outcome::ALL, Outcome::as_str);
        unique(Carrier::ALL, Carrier::as_str);
        unique(PathKind::ALL, PathKind::as_str);
        unique(Role::ALL, Role::as_str);
        unique(RttSource::ALL, RttSource::as_str);
    }

    #[test]
    fn every_code_round_trips() {
        for r in Reason::ALL {
            assert_eq!(Reason::from_code(r.as_str()), Some(*r));
        }
        for k in StepKind::ALL {
            assert_eq!(StepKind::from_code(k.as_str()), Some(*k));
        }
    }

    /// A record written by a newer build must still be readable here.
    #[test]
    fn unknown_codes_degrade_instead_of_failing() {
        let json = r#"{"t":"step","id":"a","at_ms":1,"seq":0,"kind":"time_travel","outcome":"ok","reason":"gravity"}"#;
        let entry: Entry = serde_json::from_str(json).expect("parses");
        let Entry::Step(step) = entry else {
            panic!("expected a step")
        };
        assert_eq!(step.kind, StepKind::Unknown);
        assert_eq!(step.reason, Some(Reason::Unknown));
    }

    #[test]
    fn entries_round_trip_through_json() {
        let rec = Recorder::start(
            &RecordConfig::in_memory(),
            Role::Client,
            Some(&[0xab, 0xcd]),
            vec![EndpointRef {
                host: "relay.example".into(),
                port: 443,
                carrier: Carrier::Quic,
                path: PathKind::Relay,
                addr: Some("192.0.2.1:443".into()),
            }],
            true,
        );
        let snapshot = rec.snapshot().expect("enabled");
        let json = serde_json::to_string(&snapshot.open).unwrap();
        let back: Open = serde_json::from_str(&json).unwrap();
        assert_eq!(back.v, FORMAT_VERSION);
        assert_eq!(back.routing_key.as_deref(), Some("abcd"));
        assert_eq!(back.endpoints.len(), 1);
    }

    #[test]
    fn a_dropped_step_records_that_nobody_concluded_it() {
        let rec = Recorder::start(&RecordConfig::in_memory(), Role::Client, None, vec![], true);
        {
            let _abandoned = rec.step(StepKind::Punch).via("192.0.2.9:1234");
        }
        let snap = rec.snapshot().unwrap();
        assert_eq!(snap.steps.len(), 1);
        assert_eq!(snap.steps[0].outcome, StepOutcome::Abandoned);
        assert_eq!(snap.steps[0].reason, None);
    }

    #[test]
    fn the_closing_summary_is_folded_from_the_steps() {
        let rec = Recorder::start(&RecordConfig::in_memory(), Role::Client, None, vec![], true);
        rec.step(StepKind::RelayDial)
            .via("192.0.2.1:443")
            .carrier(Carrier::Quic)
            .fail_with(&Fault::new(Reason::NoResponse, "nothing came back"));
        rec.mark(StepKind::SessionUp).path(PathKind::Relay).ok();
        rec.mark(StepKind::PathSwap)
            .path(PathKind::DirectPunched)
            .ok();
        rec.mark(StepKind::Reconnect).ok();
        rec.mark(StepKind::SessionUp).ok();
        rec.close(Outcome::Connected, None, None);

        let snap = rec.snapshot().unwrap();
        let close = snap.close.as_ref().expect("closed");
        assert_eq!(close.sessions, 2);
        assert_eq!(close.reconnects, 1);
        assert!(close.first_connect_ms.is_some());
        assert!(close.direct_ms.is_some());
        assert!(!snap.truncated);
        assert_eq!(
            snap.first_failure().map(|s| s.kind),
            Some(StepKind::RelayDial)
        );
        assert_eq!(snap.failure_reasons(), vec![Reason::NoResponse]);
    }

    /// Closing twice must not produce two endings — several teardown paths
    /// racing each other is normal.
    #[test]
    fn closing_is_idempotent() {
        let rec = Recorder::start(&RecordConfig::in_memory(), Role::Client, None, vec![], true);
        rec.close(Outcome::NeverConnected, Some(Reason::NoResponse), None);
        rec.close(Outcome::Connected, None, None);
        let snap = rec.snapshot().unwrap();
        assert_eq!(snap.close.unwrap().outcome, Outcome::NeverConnected);
    }

    #[test]
    fn a_written_record_reads_back_the_same() {
        let dir = std::env::temp_dir().join(format!("spora-record-test-{}", new_id()));
        let cfg = RecordConfig::in_dir(&dir);
        let rec = Recorder::start(&cfg, Role::Exit, Some(&[1, 2, 3]), vec![], false);
        rec.mark(StepKind::ListenerBind).local("0.0.0.0:41234").ok();
        rec.step(StepKind::Register)
            .via("192.0.2.1:443")
            .fail(Reason::NoResponse, "no ack");
        rec.sample(SampleInput {
            path: PathKind::Relay,
            carrier: Carrier::Quic,
            rtt_ms: Some(42.0),
            rtt_src: Some(RttSource::Quic),
            tx_bytes: 1000,
            rx_bytes: 2000,
            tx_pkts: 10,
            rx_pkts: 20,
            ..Default::default()
        });
        rec.close(Outcome::ClosedLocally, None, None);
        let snapshot = rec.snapshot().unwrap();
        drop(rec);

        // The writer thread is asynchronous; give it a moment to drain.
        let deadline = Instant::now() + Duration::from_secs(5);
        let read = loop {
            let read = Record::read_dir(&dir).expect("read dir");
            if read.first().is_some_and(|(_, r)| r.close.is_some()) || Instant::now() > deadline {
                break read;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(read.len(), 1, "one record file");
        let (_, from_disk) = &read[0];
        assert_eq!(from_disk.open.id, snapshot.open.id);
        assert_eq!(from_disk.steps.len(), snapshot.steps.len());
        assert_eq!(from_disk.samples.len(), 1);
        assert_eq!(from_disk.samples[0].rtt_ms, Some(42.0));
        assert!(!from_disk.truncated);
        assert_eq!(from_disk.open.role, Role::Exit);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record with no ending says so, rather than inventing one.
    #[test]
    fn a_stream_without_a_close_is_truncated() {
        let lines = concat!(
            r#"{"t":"open","v":1,"id":"deadbeef","role":"client","at_unix_ms":0,"#,
            r#""build":{"version":"0","dirty":false,"target":"x","profile":"debug"},"#,
            r#""upgrade_enabled":true}"#,
            "\n",
            r#"{"t":"step","id":"deadbeef","at_ms":5,"seq":0,"kind":"relay_dial","outcome":"failed","reason":"no_response"}"#,
            "\n",
            r#"{"garbage"#,
        );
        let recs = Record::read_stream(std::io::BufReader::new(lines.as_bytes()));
        assert_eq!(recs.len(), 1);
        assert!(recs[0].truncated);
        assert_eq!(recs[0].outcome(), Outcome::Unknown);
        assert_eq!(recs[0].failure_reasons(), vec![Reason::NoResponse]);
    }

    /// A run that nobody closed still gets an ending when its last handle
    /// goes: a process that simply stops must not leave a record that reads
    /// as "still running".
    #[test]
    fn dropping_the_last_handle_writes_an_ending() {
        let entries = Arc::new(Mutex::new(Vec::new()));
        let sink = entries.clone();
        let cfg = RecordConfig::in_memory().with_subscriber(Arc::new(move |e: &Entry| {
            sink.lock().unwrap().push(e.clone());
        }));
        let rec = Recorder::start(&cfg, Role::Client, None, vec![], true);
        rec.mark(StepKind::SessionUp).ok();
        drop(rec);

        let seen = entries.lock().unwrap();
        let close = seen
            .iter()
            .find_map(|e| match e {
                Entry::Close(c) => Some(c),
                _ => None,
            })
            .expect("an ending was written");
        assert_eq!(close.outcome, Outcome::Lost);
        assert_eq!(close.sessions, 1);
        assert!(close.detail.as_deref().unwrap_or("").contains("dropped"));
    }

    #[test]
    fn disabled_recording_costs_nothing_and_says_nothing() {
        let rec = Recorder::disabled();
        assert!(!rec.is_enabled());
        rec.step(StepKind::RelayDial).ok();
        rec.for_session(1).mark(StepKind::Accept).ok();
        rec.close(Outcome::Connected, None, None);
        assert!(rec.snapshot().is_none());
    }

    #[test]
    fn utc_stamps_are_sortable_and_correct() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(1_755_000_000_000), "20250812T120000Z");
        assert!(utc_stamp(1_755_000_000_000) < utc_stamp(1_760_000_000_000));
    }
}
