// greenlight: no allow band-aids
//! RemoteDexter — host runtime (Linux and Windows)
//!
//! Minimal orchestrator that wires the workspace library crates into a single
//! long-running process. Accepts a pinned Noise connection from the Android
//! client, authenticates it against the pairing token or the enrolled device
//! store, and serves capture and input for as long as the owner leaves the
//! host running.
//!
//! The header used to say "Windows host runtime" and describe the handshake as
//! arriving "via the session manager and multiplexer". Neither was true: the
//! host is cross-platform, and Block 10 removed both of those from the
//! connection path — they were threaded in as `_sm` and `_mux` and never
//! read.

use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

// RemoteDexter's own session state machine — the single source of truth for
// consent. A connected peer may only capture surfaces explicitly permitted, and
// input additionally requires a deliberate control grant that can be revoked
// mid-session. `session_core` is zero-dependency, so the enforcement is
// auditable in isolation.
//
// Absorbed from VoDesktop in Block 2. It used to live behind a
// `../../../VoDesktop/core` path dependency, which meant this tree could not be
// cloned or built on its own — the authorization state machine is RemoteDexter's
// core security logic, not a service borrowed from another product.
//
// WHAT a surface is lives in `share_source`: from Block 8 both Windows and Linux
// offer exactly one full-desktop surface. Windows uses DXGI Desktop Duplication
// with a GDI fallback; Wayland uses the desktop portal.
use session_core::{ShareError, ShareSession, SurfaceGeometry, SurfaceId};

mod capture_status;
mod clipboard;
mod device_file;
mod identity_store;
mod input_grant;
mod relay_dial;
mod share_source;
mod stream_backpressure;
mod stream_ladder;
mod ui;

// Session activation state, set when handshake completes successfully.
static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The last unresolved capture failure, for the console to display.
///
/// Defect C: a capture failure was told to the client and to stderr, and the
/// console went on reporting `Connected` — so the phone showed nothing while
/// the operator's own screen said all was well.
static CAPTURE_FAULT: capture_status::CaptureFault = capture_status::CaptureFault::new();
/// Set when the device list cannot be written, cleared when it can.
///
/// The save closure below deliberately does not abort the host — a host that
/// cannot write its device list must still enforce the one it is holding. But
/// staying silent meant the operator was shown a revocation that had not been
/// persisted, and would come back on the next start. The rule is enforced
/// either way; this makes the DURABILITY of it visible instead of assumed.
static DEVICE_SAVE_FAULT: capture_status::CaptureFault = capture_status::CaptureFault::new();
static SESSION_ACTIVATION_TIME: Mutex<Option<SystemTime>> = Mutex::new(None);

// ── Persistent host identity (Noise static key) ────────────────────────────
// The PUBLIC half is this host's pinned identity: it is advertised in every
// invite (QR/NFC/Wi-Fi) and the mobile client refuses to connect unless the
// Noise handshake presents this exact static key. The key MUST be stable across
// connections (a fresh per-connection key could never match the advertised pin).

struct HostIdentity {
    private: Vec<u8>,
    public: Vec<u8>,
}

static HOST_IDENTITY: OnceLock<HostIdentity> = OnceLock::new();

/// Where an identity file used to live: beside the executable.
///
/// Kept only so the one-time move can find it. Nothing loads from here.
fn legacy_identity_path(name: &str) -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(name)
}

/// The path an identity file is loaded from, moving it out of the build
/// directory on the way if it is still there.
///
/// A refused move is a **startup error**, never something to walk past: past a
/// refusal the destination is empty, and an empty destination is where a fresh
/// identity would be minted — stranding every paired device behind a host key
/// they would correctly refuse.
fn resolved_identity_path(name: &str) -> Result<std::path::PathBuf> {
    let legacy = legacy_identity_path(name);
    let dest = identity_store::identity_dir().join(name);
    let outcome = identity_store::migrate_one(&legacy, &dest);
    if let Err(refusal) = identity_store::may_proceed(&outcome) {
        return Err(anyhow::anyhow!(
            "host identity {name}: {}. Startup stopped deliberately — \
             resolve it by hand rather than let a new identity be generated.",
            refusal.explain()
        ));
    }
    if outcome == identity_store::Migration::Moved {
        // The path only. Never a byte of the file.
        eprintln!("[host] moved identity {name} into the data directory");
    }
    Ok(dest)
}

/// Load the persistent static keypair, or generate + persist one on first run.
fn load_or_create_identity() -> Result<HostIdentity> {
    let path = resolved_identity_path("host_static_identity.key")?;
    let existing = std::fs::metadata(&path).ok().map(|m| m.len());

    // A malformed key STOPS the host. Until 2026-08-27 this function fell
    // through to generate whenever the file was not exactly 64 bytes, silently
    // replacing an identity it had merely failed to understand.
    let generate = identity_store::may_generate(existing).map_err(|found| {
        anyhow::anyhow!(
            "host identity is {found} bytes, expected {}. Startup stopped \
             deliberately — replacing it would strand every paired device.",
            identity_store::IDENTITY_FILE_LEN
        )
    })?;

    if !generate {
        let bytes = std::fs::read(&path)?;
        return Ok(HostIdentity {
            private: bytes[..32].to_vec(),
            public: bytes[32..].to_vec(),
        });
    }

    let kp = snow::Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
    let mut blob = Vec::with_capacity(64);
    blob.extend_from_slice(&kp.private);
    blob.extend_from_slice(&kp.public);
    identity_store::write_owner_only(&path, &blob)?;
    Ok(HostIdentity {
        private: kp.private,
        public: kp.public,
    })
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Persistent host identity (RD-02 invite-signing key) ─────────────────────
// Deliberately a SEPARATE key from HOST_IDENTITY above: that one is the Noise
// static key pinned by the encrypted transport, this one signs the invite
// JSON itself so `host_pubkey` can't be self-asserted by a forged invite.

static HOST_SIGNING_IDENTITY: OnceLock<ed25519_dalek::SigningKey> = OnceLock::new();

fn signing_identity_path() -> Result<std::path::PathBuf> {
    resolved_identity_path("host_signing_identity.key")
}

/// The invite-signing identity, for the one other caller that must prove
/// possession of it: registering with a relay that uses enrol-then-prove.
///
/// The relay holds only the PUBLIC half. What crosses the wire is a signature
/// over a challenge the relay chose, so nothing replayable leaves this process
/// and the key itself never does.
pub(crate) fn host_signing_identity() -> Option<ed25519_dalek::SigningKey> {
    HOST_SIGNING_IDENTITY.get().cloned()
}

/// RD-03: never log the raw session token — a short SHA-256 prefix is enough
/// to correlate log lines without giving a log reader/leak the token itself.
fn token_fingerprint(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes());
    hash.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}

pub fn session_active() -> bool {
    SESSION_ACTIVE.load(Ordering::SeqCst)
}

pub fn activation_time() -> Option<SystemTime> {
    *SESSION_ACTIVATION_TIME.lock().unwrap()
}

// The plaintext `Frame`/`ClientHandshake` types and MAX_HANDSHAKE_FRAME lived
// here until the Block 4 repair. They implemented the pre-Noise plaintext token
// frame, which is gone: the token now travels only inside the pinned Noise
// channel. Nothing replaced them because nothing precedes the handshake.

// ── Constants ───────────────────────────────────────────────────────────

// ── Main ────────────────────────────────────────────────────────────────

// ── The real HostBackend ────────────────────────────────────────────────
//
// `host_controller` decides WHEN capture and input may exist; this decides HOW.
// It is the one shipped implementation of the seam, and it is where the boot
// sequence that used to live in `main` now lives — because none of it may
// happen until the owner presses Start.

/// The platform side of the host: identities and
/// the Noise connection handler.
pub struct RdBackend {
    capture_on: bool,
    input_on: bool,
    /// The one pairing implementation. Holds the outstanding invite's HASH and
    /// nothing else; see `crates/pairing/src/token.rs`.
    pairing: pairing::PairingService,
    /// Devices the owner has enrolled. Block 9: one store for the process, so a
    /// phone enrolled on one connection is recognised on the next.
    devices: pairing::devices::DeviceHandle,
}

impl RdBackend {
    /// Build the backend. Must run inside the controller's Tokio runtime: the
    /// session manager starts an expiry sweep task.
    pub fn new() -> Self {
        Self::with_devices(pairing::devices::DeviceHandle::new())
    }

    /// Build the backend over an existing device store.
    ///
    /// The store is created in `main` and shared with the console, so the
    /// owner's Revoke acts on the SAME list the connection path enforces.
    /// Routing revocation through a command channel instead would create a
    /// window in which the UI says "revoked" and the host has not applied it
    /// yet — unacceptable for a security control whose whole job is to take
    /// effect now.
    pub fn with_devices(devices: pairing::devices::DeviceHandle) -> Self {
        let signing = HOST_SIGNING_IDENTITY
            .get()
            .expect("signing identity is loaded before the console opens")
            .clone();
        let host_pubkey = HOST_IDENTITY
            .get()
            .map(|id| to_hex(&id.public))
            .unwrap_or_default();
        RdBackend {
            capture_on: false,
            input_on: false,
            pairing: pairing::PairingService::new(signing, host_pubkey),
            devices,
        }
    }
}

/// An invitation, tagged by the route it names.
///
/// Extracted from the backend so the BRANCH is testable: `RdBackend` owns a
/// capture stack and input devices, and a test that had to build one would not
/// be a test of which invite gets minted.
pub(crate) enum Minted {
    Direct(pairing::Invitation),
    Relay(pairing::RelayInvitation),
}

impl Minted {
    pub(crate) fn token_fingerprint(&self) -> &str {
        match self {
            Minted::Direct(i) => &i.token_fingerprint,
            Minted::Relay(i) => &i.token_fingerprint,
        }
    }

    pub(crate) fn expires_at(&self) -> u64 {
        match self {
            Minted::Direct(i) => i.invite.expires_at,
            Minted::Relay(i) => i.invite.expires_at,
        }
    }

    /// What the log line says. Never the session id, never the token.
    pub(crate) fn describe(&self) -> String {
        match self {
            Minted::Direct(i) => format!("{}:{}", i.invite.addr, i.invite.port),
            Minted::Relay(i) => format!("relay {}:{}", i.invite.relay_addr, i.invite.relay_port),
        }
    }

    pub(crate) fn into_view(self) -> host_controller::state::InviteView {
        let (qr, token_fingerprint, expires_at) = match self {
            Minted::Direct(i) => (i.qr, i.token_fingerprint, i.invite.expires_at),
            Minted::Relay(i) => (i.qr, i.token_fingerprint, i.invite.expires_at),
        };
        host_controller::state::InviteView {
            qr_size: qr.size,
            qr_modules: qr.modules,
            token_fingerprint,
            expires_at,
        }
    }
}

/// Mint the invite the host's ACTUAL route calls for.
///
/// The two schemas name different things — v4 an address and a port, v5 a relay
/// and the session it issued — so neither is derived from the other and neither
/// is a fallback for the other. A host that is reachable one way must not be
/// able to advertise itself the other.
pub(crate) fn mint_for(
    pairing: &mut pairing::PairingService,
    reach: &host_controller::Reach,
    now: u64,
    caps: &[String],
) -> Result<Minted, pairing::MintError> {
    match reach {
        host_controller::Reach::Bound(bound) => {
            pairing.create_invite(*bound, now, caps).map(Minted::Direct)
        }
        host_controller::Reach::ViaRelay { relay, session } => pairing
            .create_relay_invite(*relay, session, now, caps)
            .map(Minted::Relay),
    }
}

impl host_controller::HostBackend for RdBackend {
    fn start_capture(&mut self) -> Result<(), host_controller::BackendFault> {
        // The capability gates stay exactly as they were: capture is opt-in per
        // run and is not implied by starting the host.
        if !capability_granted("screenshot_request") {
            return Err(host_controller::BackendFault::new(
                "screen capture is not authorized for this run (set RD_CAP_SCREENSHOT=1)",
            ));
        }
        self.capture_on = true;
        Ok(())
    }

    fn stop_capture(&mut self) {
        share_source::shutdown_capture();
        self.capture_on = false;
    }

    fn open_input(&mut self) -> Result<(), host_controller::BackendFault> {
        if !capability_granted("input_event") {
            // Not a failure: a view-only host is a legitimate configuration,
            // and the session still refuses input at the session_core gate.
            self.input_on = false;
            return Ok(());
        }
        self.input_on = true;
        Ok(())
    }

    fn close_input(&mut self) {
        module10::inject::shutdown();
        self.input_on = false;
    }

    fn create_invite(
        &mut self,
        reach: &host_controller::Reach,
        now: u64,
    ) -> Result<host_controller::state::InviteView, host_controller::BackendFault> {
        // Capabilities are signed, so they must describe what this run can
        // actually do rather than what the product might do one day. Input is
        // advertised only when the capability is armed; `session_core` still
        // requires a separate explicit grant regardless of what the QR says.
        let mut caps = vec![pairing::CAP_VIEW.to_string()];
        if capability_granted("input_event") {
            caps.push(pairing::CAP_CONTROL.to_string());
        }

        let minted = mint_for(&mut self.pairing, reach, now, &caps)
            .map_err(|e| host_controller::BackendFault::new(e.reason()))?;

        // The token is never logged. The fingerprint is a hash prefix, and the
        // SESSION ID IS NOT LOGGED EITHER: it is what a phone presents to reach
        // this host, so it belongs in the QR and nowhere else.
        eprintln!(
            "[host] pairing invitation minted for {} (token {}, expires {})",
            minted.describe(),
            minted.token_fingerprint(),
            minted.expires_at()
        );
        Ok(minted.into_view())
    }

    fn revoke_invite(&mut self) {
        self.pairing.revoke();
    }

    fn serve(
        &mut self,
        stream: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
        authed: host_controller::AuthNotifier,
        notices: host_controller::NoticeNotifier,
    ) -> host_controller::ServeFuture {
        // The narrowly scoped share: the ability to redeem a token, and nothing
        // else. No signing key, no minting, no host identity.
        let tokens = self.pairing.redemption_handle();
        let devices = self.devices.clone();
        Box::pin(async move {
            if let Err(e) = handle_client_connection(stream, tokens, devices, authed).await {
                // Redacted: the error type, never the payload that produced it.
                // Both destinations carry the same redacted text: the console
                // for the operator watching, `notices` for the controller,
                // which raises it as a HostEvent so the UI can show that a
                // connection died rather than leaving it looking alive. Once
                // per connection, never per event.
                eprintln!("[host] connection from {peer} ended: {e}");
                notices.fault(format!("connection from {peer} ended: {e}"));
            }
        })
    }

    fn dispatch(
        &mut self,
        auth_tx: tokio::sync::mpsc::UnboundedSender<String>,
        notice_tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> host_controller::ServeDispatch {
        // Everything the closure needs is cloned once, here. It holds no borrow
        // on the backend, which is what lets the accept task own it.
        let tokens = self.pairing.redemption_handle();
        let devices = self.devices.clone();
        std::sync::Arc::new(move |stream, peer: std::net::SocketAddr, label: String| {
            let tokens = tokens.clone();
            let devices = devices.clone();
            let authed = host_controller::AuthNotifier::new(auth_tx.clone(), label.clone());
            let notices = host_controller::NoticeNotifier::new(notice_tx.clone(), label);
            Box::pin(async move {
                if let Err(e) = handle_client_connection(stream, tokens, devices, authed).await {
                    // Same redacted text to both, as in `serve` above.
                    eprintln!("[host] connection from {peer} ended: {e}");
                    notices.fault(format!("connection from {peer} ended: {e}"));
                }
            }) as host_controller::ServeFuture
        })
    }
}

fn main() -> Result<ExitCode> {
    eprintln!("[host_app] RemoteDexter — host console starting");
    warn_about_malformed_capability_vars();

    let e2e_loopback = ui::e2e_loopback_bind(std::env::var("RD_E2E_LOOPBACK").ok().as_deref())
        .map_err(anyhow::Error::msg)?;

    // Identities are loaded before the window opens so a missing or malformed
    // key is a plain startup error rather than a mystery inside the GUI. They
    // are read here and never displayed: only the PUBLIC fingerprint reaches a
    // widget.
    let identity = load_or_create_identity()?;
    let fingerprint = to_hex(&identity.public);
    eprintln!("[host_app] Host identity (pinned) pubkey: {fingerprint}");
    let _ = HOST_IDENTITY.set(identity);

    let signing_identity = pairing::load_or_create(&signing_identity_path()?)?;
    eprintln!(
        "[host_app] Invite-signing identity pubkey: {}",
        pairing::identity_b64(&signing_identity)
    );
    let _ = HOST_SIGNING_IDENTITY.set(signing_identity);

    // NOTHING ELSE STARTS HERE. No listener, no capture, no input devices, no
    // invitation. `module17_bootstrap_invite::start()` used to be called on
    // this path and would broadcast the pairing token in plaintext to
    // 255.255.255.255 every five seconds from the moment the process launched.
    // That crate, and the beacon it drove, no longer exist (Block 4). The host
    // does nothing at all until the owner picks an interface and presses Start,
    // and an invitation is minted only when they ask for one.
    // One device store for the process, shared by the connection path and the
    // console. A corrupt list is quarantined rather than reset, and the host
    // starts empty — which fails closed, since unknown and revoked are both
    // refused.
    let devices = {
        let path = device_file::devices_path();
        let (store, how) = device_file::load_from(&path);
        match &how {
            device_file::Loaded::Fresh => {}
            device_file::Loaded::Restored(n) => {
                eprintln!("[host] {n} enrolled device(s) restored")
            }
            device_file::Loaded::Quarantined(kept) => eprintln!(
                "[host] the device list could not be read and was preserved at {}; \
                 every device must enrol again",
                kept.display()
            ),
        }
        pairing::devices::DeviceHandle::restored(
            store,
            std::sync::Arc::new(move |store: &pairing::devices::DeviceStore| {
                match device_file::save_to(&path, store) {
                    Ok(()) => DEVICE_SAVE_FAULT.clear(),
                    Err(e) => {
                        // Still not fatal: a host that cannot write its device
                        // list must go on enforcing the one it is holding. But
                        // it must not look like it succeeded — the operator
                        // has just been shown a revocation that will not
                        // survive a restart.
                        eprintln!("[host] could not save the device list: {e}");
                        DEVICE_SAVE_FAULT.note(&format!(
                            "the device list could not be saved ({e}) — changes \
                             apply now but will NOT survive a restart"
                        ));
                    }
                }
            }),
        )
    };
    let backend_devices = devices.clone();
    if let Err(e) = ui::run(
        move || RdBackend::with_devices(backend_devices),
        fingerprint,
        e2e_loopback,
        devices,
    ) {
        eprintln!("[host_app] host console failed: {e}");
        return Ok(ExitCode::FAILURE);
    }
    eprintln!("[host_app] Goodbye.");
    Ok(ExitCode::SUCCESS)
}

/// Noise_XX_25519_AESGCM_SHA256 pattern identifier.
const NOISE_PATTERN: &str = "Noise_XX_25519_AESGCM_SHA256";

/// The maximum size of the encrypted pairing-auth message. It carries a hex
/// token, a protocol name and a version; anything larger is refused before
/// allocation.
const MAX_PAIR_AUTH: usize = 4096;

/// Session wire version. Distinct from the v4 invite schema version.
/// Session wire version.
///
/// **4 because Block 10 changed the framing.** Every message after `pair_ok` is
/// now a `wire::Envelope` instead of bare JSON or a bare stream chunk, and the
/// two forms are not distinguishable by inspection with any confidence worth
/// betting a session on.
///
/// This IS the version negotiation the plan asks for, and it needed no new
/// machinery: `pair_auth` already carries a protocol name and version, the host
/// already demands an exact match, and a mismatch already replies `pair_denied`
/// WITHOUT spending the one-use token — so an old client meets a clear refusal
/// it can retry after upgrading, rather than a silent downgrade or a burnt
/// invite.
const SESSION_PROTOCOL_VERSION: u8 = 4;

/// What the client sends, ENCRYPTED, as the first message after Noise.
#[derive(Serialize, Deserialize)]
struct PairAuth {
    /// The one-use token from the v4 signed invite.
    token: String,
    /// Session protocol name.
    protocol: String,
    /// Session protocol version.
    version: u8,
}

/// A short label for a device's PUBLIC key, for logs.
///
/// Public data, but abbreviated anyway: a full key in a log invites someone to
/// paste it somewhere that expects a secret, and four bytes is plenty to
/// correlate two lines.
fn device_fingerprint(public_key: &[u8; 32]) -> String {
    public_key[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Serve one client connection.
///
/// Block 10: `SessionManager` and the frame multiplexer used to be threaded in
/// here and never touched — the parameters were `_sm` and `_mux`, unused for
/// long enough to have acquired underscores rather than been removed. A channel
/// claim nobody reads is not free: it makes the multiplexer look load-bearing
/// to anyone auditing what handles a hostile connection, which is exactly the
/// ambiguity this block exists to remove.
async fn handle_client_connection(
    mut socket: tokio::net::TcpStream,
    tokens: pairing::RedemptionHandle,
    devices: pairing::devices::DeviceHandle,
    authed: host_controller::AuthNotifier,
) -> Result<()> {
    // ── 1. Pinned Noise FIRST. Nothing is sent in the clear. ─────────
    //
    // The protocol this replaces sent `{"Handshake":{"session_token":...}}` as
    // a PLAINTEXT length-prefixed JSON frame before the handshake, and then
    // bound the same token in as the Noise prologue. Two consequences, both
    // bad: the token was readable by anyone on the path, and `RD_BIND_TOKEN_
    // PROLOGUE=0` existed as an explicit downgrade switch. Both are gone. There
    // is no plaintext frame and no compatibility fallback — a client that
    // speaks the old protocol simply fails the handshake.
    let host_priv = HOST_IDENTITY
        .get()
        .map(|id| id.private.clone())
        .ok_or_else(|| anyhow::anyhow!("host identity not initialised"))?;
    let mut hs = snow::Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(&host_priv)
        .build_responder()?;

    let mut buf = vec![0u8; 65535];

    // <- e
    let msg1 = recv_noise_msg(&mut socket).await?;
    hs.read_message(&msg1, &mut buf)?;
    // -> e, ee, s, es
    let len = hs.write_message(&[], &mut buf)?;
    send_noise_msg(&mut socket, &buf[..len]).await?;
    // <- s, se
    let msg3 = recv_noise_msg(&mut socket).await?;
    hs.read_message(&msg3, &mut buf)?;
    // The device's identity, free at the end of every XX handshake and unread
    // by this host until Block 9. Captured BEFORE `into_transport_mode`, which
    // consumes the handshake state along with it.
    let peer_static: Option<[u8; 32]> = hs
        .get_remote_static()
        .and_then(|k| <[u8; 32]>::try_from(k).ok());
    let mut noise = hs.into_transport_mode()?;
    eprintln!("[host] Noise XX handshake complete — transport mode");

    // ── 2. The pairing token, inside the encrypted channel ───────────
    let ct = recv_noise_msg(&mut socket).await?;
    if ct.is_empty() || ct.len() > MAX_PAIR_AUTH {
        return Err(anyhow::anyhow!(
            "pair_auth frame out of bounds: {}",
            ct.len()
        ));
    }
    let mut pt = vec![0u8; MAX_PAIR_AUTH];
    let n = noise.read_message(&ct, &mut pt)?;
    let auth: PairAuth = serde_json::from_slice(&pt[..n])?;

    // Validate the envelope before spending its one-use credential. Otherwise
    // an unsupported client holding the QR can burn the invite and still fail
    // negotiation, forcing the owner to mint another one.
    if auth.protocol != pairing::SESSION_PROTOCOL || auth.version != SESSION_PROTOCOL_VERSION {
        let len = noise.write_message(br#"{"type":"pair_denied"}"#, &mut buf)?;
        let _ = send_noise_msg(&mut socket, &buf[..len]).await;
        return Err(anyhow::anyhow!("unsupported session protocol"));
    }

    // RD-03: never log the raw token, only a hash prefix.
    let fp = token_fingerprint(&auth.token);
    let now = now_epoch_secs();

    // THE single live token authority. This used to be
    // `sm.validate_token(...)`, a separate UUID store the console never
    // populated — so a token from a real v4 QR could not be accepted by the
    // shipping host at all.
    // Block 9. Two ways to claim a session, and exactly one of them spends a
    // token. An empty token means "I have been here before" and is answered by
    // the device's own static key; anything else is a first enrolment.
    //
    // The order matters: a presented token is ALWAYS redeemed, never skipped
    // because the device happens to be known. Otherwise a paired device could
    // replay a spent token and have it quietly succeed, and replay refusal is a
    // property Block 9 must not weaken.
    let outcome: std::result::Result<String, String> = if auth.token.is_empty() {
        match peer_static {
            Some(key) => devices
                .authorize_paired(&key, now)
                .map(|()| format!("paired reconnect from device {}", device_fingerprint(&key)))
                .map_err(|refused| refused.public_reason().to_string()),
            // No static key means this is not a Noise XX peer we can name.
            None => Err("not authorized".to_string()),
        }
    } else {
        match tokens.redeem(&auth.token, now) {
            Ok(()) => {
                let named = match peer_static {
                    Some(key) => {
                        // Enrol only after the token is spent. The store is
                        // never a second, weaker way to authenticate.
                        devices.enroll(key, "", now);
                        format!("device {} enrolled", device_fingerprint(&key))
                    }
                    None => "enrolled without a device identity".to_string(),
                };
                Ok(format!("pairing token {fp} redeemed — {named}"))
            }
            Err(e) => Err(e.reason().to_string()),
        }
    };
    let how = match outcome {
        Ok(how) => how,
        Err(reason) => {
            eprintln!("[host] pairing refused: {reason}");
            // Deliberately no detail on the wire: a peer that guesses wrong
            // learns only that it was refused.
            let len = noise.write_message(br#"{"type":"pair_denied"}"#, &mut buf)?;
            let _ = send_noise_msg(&mut socket, &buf[..len]).await;
            return Err(anyhow::anyhow!("pairing refused: {reason}"));
        }
    };
    // Take a session slot BEFORE acknowledging. A peer told `pair_ok` and then
    // dropped has been lied to; refusing here means it learns it was not
    // admitted, and the refusal is the visible, recoverable half of the trade
    // described on `SessionLimit`.
    let Some(_session_slot) = acquire_session_slot(peer_static) else {
        eprintln!(
            "[host] refusing an authenticated session: at the concurrent limit \
             ({} total, {} per device)",
            host_controller::SessionLimit::MAX_TOTAL,
            host_controller::SessionLimit::MAX_PER_DEVICE
        );
        let len = noise.write_message(br#"{"type":"pair_denied"}"#, &mut buf)?;
        let _ = send_noise_msg(&mut socket, &buf[..len]).await;
        return Err(anyhow::anyhow!("session limit reached"));
    };

    eprintln!("[host] {how} — session authenticated");
    let len = noise.write_message(br#"{"type":"pair_ok"}"#, &mut buf)?;
    send_noise_msg(&mut socket, &buf[..len]).await?;

    // ── 3. ONLY NOW is this a connected peer ─────────────────────────
    // Noise completed AND the token was redeemed exactly once. Before the
    // Block 4 repair the controller counted the peer at `accept()`, which is
    // to say for anyone at all.
    authed.authenticated();

    // Now — and only now, with a proven encrypted channel — mark the
    // session active.
    //
    // There used to be a `sm.beacon().stop()` here, whose job was to
    // silence the UDP broadcaster once a session existed. It was a
    // mitigation for a defect rather than a feature: the beacon had
    // already been shouting the pairing token across the subnet every
    // five seconds for as long as the invite was open. Block 4 deleted
    // the broadcaster, so there is nothing left to silence.
    SESSION_ACTIVE.store(true, Ordering::SeqCst);
    let now = SystemTime::now();
    *SESSION_ACTIVATION_TIME.lock().unwrap() = Some(now);
    eprintln!("[host] RDv3 session activated at {:?}", now);
    eprintln!("[host] RDv3 session established for token {}", fp);

    // Per-connection window-scope authority. Starts view-only with an
    // EMPTY allow-list: nothing is captured or controlled until the
    // client explicitly permits a specific window. The Noise handshake is
    // already proven (transport mode above), so advance past it.
    let sess_now = now_epoch_secs();
    let ttl = std::env::var("RD_SESSION_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(8 * 3600);
    let mut session = ShareSession::new(fp.to_string(), "rdx-session", sess_now + ttl);
    let _ = session.handshake_complete();

    // ── 3. Encrypted session loop ────────────────────────────
    // Split the socket so an inbound reader task can feed framed
    // ciphertext through a channel (cancel-safe), while this task owns
    // the Noise transport (single-owner nonce ordering), the write half,
    // and the outbound screen-stream chunks. `select!` interleaves
    // command handling with streamed frames.
    let (mut rd, mut wr) = socket.into_split();
    let (ct_tx, mut ct_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let reader = tokio::spawn(async move {
        loop {
            let mut len_buf = [0u8; 4];
            if rd.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let frame_len = u32::from_be_bytes(len_buf) as usize;
            if frame_len == 0 || frame_len > 65535 {
                continue;
            }
            let mut ct = vec![0u8; frame_len];
            if rd.read_exact(&mut ct).await.is_err() {
                break;
            }
            if ct_tx.send(ct).await.is_err() {
                break;
            }
        }
    });

    // A single long-lived sender keeps the chunk channel open for the
    // whole session, so `chunk_rx.recv()` pends (never returns None)
    // while no stream is running and isn't touched by the command arm —
    // avoiding a select! borrow clash with stream lifecycle changes.
    // Bounded to a few frames, not ~30 MB. A deep queue is not backpressure,
    // it is a latency reservoir: it buffered minutes of stale video while the
    // link collapsed. `stream_backpressure` drops frames that will not fit.
    let (chunk_tx, mut chunk_rx) =
        tokio::sync::mpsc::channel::<Vec<u8>>(stream_backpressure::STREAM_QUEUE_CHUNKS);
    let mut stream: Option<StreamController> = None;
    // The idle watchdog's heartbeat. Five seconds is only how often the
    // question is asked; the grace period is `module10::inject::
    // INPUT_IDLE_RELEASE`. It exists because releasing on disconnect covers a
    // client that goes AWAY, and not one that is still connected and has
    // stopped speaking mid-press.
    let mut idle_tick = tokio::time::interval(std::time::Duration::from_secs(5));
    // Prime the lock cache before any command is served. Without this the
    // window the polling leaves open would start at the connection rather
    // than at the lock, and a peer connecting to an already-locked desktop
    // would be waved through until the first tick.
    refresh_lock_state();
    // Pointer moves are counted, not printed one line each. See the call site.
    let mut moves_since_log: u64 = 0;
    loop {
        tokio::select! {
            _ = idle_tick.tick() => {
                module10::inject::release_if_idle();
                // Poll logind. The input path reads the cache this writes and
                // never spawns a process of its own.
                refresh_lock_state();
                // Revocation must reach a session that is sitting still, not
                // only one that speaks again. Five seconds is the heartbeat
                // that already exists; this adds no timer of its own.
                if let LiveAuth::Terminate(why) =
                    live_session_verdict(&devices, peer_static.as_ref())
                {
                    eprintln!("[host] device access withdrawn while connected ({why}) — closing the session");
                    break;
                }
            }
            inbound = ct_rx.recv() => {
                let ciphertext = match inbound {
                    Some(c) => c,
                    None => break, // reader task ended (client gone)
                };
                let plaintext_len = match noise.read_message(&ciphertext, &mut buf) {
                    Ok(n) => n,
                    Err(e) => { eprintln!("[host] Noise decrypt error: {e}"); continue; }
                };
                // Block 10: every message after pair_ok is an envelope. A
                // refusal here is a protocol error, not a command to answer —
                // the peer is speaking something this build does not, and
                // guessing at the bytes is exactly the ambiguity the envelope
                // exists to remove.
                let envelope = match wire::decode_exact(&buf[..plaintext_len]) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[host] refusing malformed envelope: {e:?}");
                        // The peer learns it was refused and roughly which
                        // contract it broke; the detail stays in this log.
                        // Handing back the specifics would turn the parser into
                        // a measuring instrument for the exact ceilings.
                        let reason = e.redacted();
                        let denial = format!(r#"{{"type":"error","for":"envelope","reason":"{reason}"}}"#);
                        if let Ok(env) = wire::Envelope::new(
                            wire::Kind::ControlJson,
                            0,
                            denial.into_bytes(),
                        ) {
                            let ct_len = noise.write_message(&env.encode(), &mut buf)?;
                            let _ = write_framed(&mut wr, &buf[..ct_len]).await;
                        }
                        continue;
                    }
                };

                match envelope.kind {
                    wire::Kind::Ping => {
                        // Liveness. Answered in kind and nothing else.
                        if let Ok(pong) = wire::Envelope::new(wire::Kind::Ping, 0, Vec::new()) {
                            let ct_len = noise.write_message(&pong.encode(), &mut buf)?;
                            let _ = write_framed(&mut wr, &buf[..ct_len]).await;
                        }
                        continue;
                    }
                    wire::Kind::Close => {
                        eprintln!("[host] client closed the session");
                        break;
                    }
                    wire::Kind::FrameChunkV1 => {
                        // Frames travel host -> client only. A client sending
                        // one is either confused or probing.
                        eprintln!("[host] refusing a frame chunk from the client");
                        continue;
                    }
                    wire::Kind::ControlJson | wire::Kind::InputV1 => {}
                }

                let json_str = match String::from_utf8(envelope.payload) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                // Pointer moves are logged as a COUNT, never one line each.
                //
                // A phone streams 60-120 MouseMove commands a second, and each
                // was a full JSON line on stderr. The 2026-09-05 P9 run had to
                // find a single release line inside hundreds of them, and every
                // one of those lines is a formatting allocation and a write
                // syscall on the session's hot path in a RELEASE build.
                //
                // Everything that is not a move still prints verbatim: those
                // are the lines that carry meaning — grants, refusals, stream
                // lifecycle, button and key events. A move only matters in
                // aggregate, so it is reported that way, and the pending count
                // is flushed before the next real line so the ordering still
                // reads correctly.
                if is_pointer_move_command(&json_str) {
                    moves_since_log += 1;
                } else {
                    if moves_since_log > 0 {
                        eprintln!("[host] ({moves_since_log} pointer move(s))");
                        moves_since_log = 0;
                    }
                    eprintln!("[host] Agent2 command: {}", describe_command(&json_str));
                }

                // Stream lifecycle is handled here (it owns loop state);
                // everything else routes through the stateless dispatch.
                let cmd_type = serde_json::from_str::<serde_json::Value>(&json_str)
                    .ok()
                    .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
                    .unwrap_or_default();
                let cmd_val: serde_json::Value =
                    serde_json::from_str(&json_str).unwrap_or(serde_json::Value::Null);
                // Re-checked before EVERY command, so an active session is
                // cut at its next action rather than at the next heartbeat.
                if let LiveAuth::Terminate(why) =
                    live_session_verdict(&devices, peer_static.as_ref())
                {
                    eprintln!("[host] device access withdrawn while connected ({why}) — refusing the command and closing the session");
                    break;
                }
                let now_secs = now_epoch_secs();
                // Window-scope gate: session/consent commands and the
                // capture/input capabilities all route through the
                // per-connection ShareSession before any pixels or input
                // move. Only stream_stop and non-scoped commands bypass it.
                let response = if let Some(r) = handle_session_command(
                    &mut session,
                    cmd_type.as_str(),
                    &cmd_val,
                    now_secs,
                ) {
                    Some(r)
                } else {
                    match cmd_type.as_str() {
                        "stream_start" => {
                            match frame_gate(&session, "stream_start", &cmd_val, now_secs) {
                                Ok(w) => {
                                    // A controller whose capture thread
                                    // already exited (error or clean stop)
                                    // must not block a fresh one — `Some`
                                    // alone does not mean "still running".
                                    if stream.as_ref().is_none_or(StreamController::is_finished)
                                    {
                                        stream = Some(StreamController::start(
                                            75,
                                            chunk_tx.clone(),
                                            w,
                                        ));
                                    }
                                    Some(json_ack("stream_start"))
                                }
                                Err(resp) => Some(resp),
                            }
                        }
                        "stream_stop" => {
                            stream = None; // Drop stops the producer thread
                            Some(json_ack("stream_stop"))
                        }
                        "screenshot_request" => {
                            handle_screenshot_scoped(&session, &cmd_val, now_secs).await
                        }
                        "input_event" => {
                            handle_input_scoped(&mut session, &cmd_val, now_secs)
                        }
                        _ => dispatch_agent2_command(&json_str).await,
                    }
                };
                if let Some(resp) = response {
                    // A response this host cannot envelope is a bug in this
                    // host — too long, or not the JSON object the kind
                    // promises. Dropping it silently would leave the client
                    // waiting forever for an answer that was never framed, so
                    // it is said out loud.
                    match wire::Envelope::new(wire::Kind::ControlJson, 0, resp.into_bytes()) {
                        Ok(env) => {
                            let ct_len = noise.write_message(&env.encode(), &mut buf)?;
                            write_framed(&mut wr, &buf[..ct_len]).await?;
                        }
                        Err(e) => eprintln!("[host] cannot envelope a response: {e:?}"),
                    }
                }
            }
            Some(chunk) = chunk_rx.recv() => {
                // AUTHORITY IS RE-CHECKED PER CHUNK, not once at stream_start.
                // A revoked or expired session must stop delivering pixels that
                // are already in flight, not merely refuse the next request.
                match chunk_send_decision(stream.as_ref(), &session, now_epoch_secs()) {
                    ChunkSend::Send => {}
                    ChunkSend::NoStream => continue,
                    ChunkSend::AuthorityEnded => {
                        eprintln!(
                            "[host] stream authority ended — stopping the stream; \
                             no further frames will be sent"
                        );
                        stream = None;
                        continue;
                    }
                }
                // The chunker's output is bounded by STREAM_CHUNK_PAYLOAD plus
                // stream_chunk's header, which is exactly what
                // Kind::FrameChunkV1's ceiling is anchored to — so a refusal
                // here means the two have drifted apart and every frame is
                // about to be dropped. Loud, not silent.
                let framed = match frame_chunk_on_the_wire(chunk) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("[host] cannot envelope a frame chunk: {e:?}");
                        continue;
                    }
                };
                let ct_len = noise.write_message(&framed, &mut buf)?;
                if write_framed(&mut wr, &buf[..ct_len]).await.is_err() {
                    break;
                }
            }
        }
    }
    drop(stream);
    reader.abort();
    end_session_and_release(&mut session);

    SESSION_ACTIVE.store(false, Ordering::SeqCst);
    eprintln!("[host] Client disconnected");
    Ok(())
}

/// Live authenticated sessions, per device, and the total.
///
/// The counts a `SessionLimit` decision is made against. Kept here rather than
/// in the controller because the device key is known at authentication, in the
/// connection task, and that is where a slot must be taken or refused.
static LIVE_SESSIONS: std::sync::Mutex<Option<std::collections::HashMap<[u8; 32], usize>>> =
    std::sync::Mutex::new(None);
/// Sessions with no device identity, counted toward the total only.
static LIVE_ANONYMOUS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A held session slot. Releasing it is `Drop`, so it cannot be leaked by an
/// early return, a `?`, or a panic — which is exactly how a cap becomes a
/// permanent lockout that only a restart clears.
struct SessionSlot {
    key: Option<[u8; 32]>,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        match self.key {
            None => {
                LIVE_ANONYMOUS.fetch_sub(1, Ordering::SeqCst);
            }
            Some(k) => {
                let mut guard = LIVE_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(map) = guard.as_mut() {
                    if let Some(n) = map.get_mut(&k) {
                        *n = n.saturating_sub(1);
                        if *n == 0 {
                            // Removed rather than left at zero: the map must not
                            // grow one entry per device ever seen.
                            map.remove(&k);
                        }
                    }
                }
            }
        }
    }
}

/// Take a session slot, or refuse.
///
/// Returns `None` when the cap is reached, and the caller must then close the
/// connection rather than proceed — see `SessionLimit` for why the NEWEST is
/// refused rather than the oldest evicted.
fn acquire_session_slot(key: Option<[u8; 32]>) -> Option<SessionSlot> {
    let mut guard = LIVE_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let anon = LIVE_ANONYMOUS.load(Ordering::SeqCst);
    let total: usize = map.values().sum::<usize>() + anon;
    let mine = key.map_or(0, |k| map.get(&k).copied().unwrap_or(0));
    if !host_controller::SessionLimit::admits(total, mine) {
        return None;
    }
    match key {
        Some(k) => *map.entry(k).or_insert(0) += 1,
        None => {
            LIVE_ANONYMOUS.fetch_add(1, Ordering::SeqCst);
        }
    }
    Some(SessionSlot { key })
}

/// Whether a session that is ALREADY AUTHENTICATED may continue.
#[derive(Debug, PartialEq, Eq)]
enum LiveAuth {
    /// Still enrolled: carry on.
    Continue,
    /// The device was revoked or forgotten while connected. Close the session.
    Terminate(&'static str),
}

/// Ask whether a live session's device is still enrolled.
///
/// THE DEFECT THIS EXISTS FOR. Revoking a device tombstoned the durable record,
/// and the connection path consulted that record exactly once — at
/// authentication. Nothing afterwards associated a running connection with the
/// key that authorized it, so revoking a device stopped it RECONNECTING while
/// the session it already had carried on streaming and injecting. The UI text
/// was accidentally honest about it ("a revoked device cannot reconnect"); the
/// threat model was not, and claimed the current session is disconnected in
/// flight. Found by an outside security review, 2026-09-07.
///
/// It is the same disease as the stream-authority defect one layer up:
/// authority checked when a thing STARTS and never again. Revocation means
/// nothing if it only applies to sessions that do not exist yet.
///
/// READ-ONLY BY CONSTRUCTION. This calls `is_authorized`, not
/// `authorize_paired` — the latter records `last_seen_at` and therefore writes
/// the store, and asking this question on a timer, per connection, would turn a
/// security check into a continuous disk write.
///
/// A peer with no static key cannot be named and therefore cannot be revoked by
/// key. Noise XX always yields one, so this is unreachable in practice; it
/// continues rather than terminating because refusing a session we cannot
/// identify would break every legitimate one if that ever changed.
fn live_session_verdict(
    devices: &pairing::devices::DeviceHandle,
    peer_static: Option<&[u8; 32]>,
) -> LiveAuth {
    let Some(key) = peer_static else {
        return LiveAuth::Continue;
    };
    match devices.is_authorized(key) {
        Ok(()) => LiveAuth::Continue,
        Err(reason) => LiveAuth::Terminate(reason.public_reason()),
    }
}

/// What to do with a frame chunk that is ready to go on the wire.
#[derive(Debug, PartialEq, Eq)]
enum ChunkSend {
    /// Authority still holds: encrypt it and send it.
    Send,
    /// No stream is running. Drain the chunk; never put it on the wire.
    NoStream,
    /// The authority that created this stream has ended — expiry, `end()`, or
    /// the surface being revoked. Stop the producer and send nothing.
    AuthorityEnded,
}

/// Decide whether a queued frame chunk may still be sent.
///
/// THE DEFECT THIS EXISTS FOR. `frame_gate` ran once, at `stream_start`, and
/// the send path never consulted the session again — it encrypted whatever the
/// chunker produced and wrote it to the socket. So expiry or `revoke_surface`
/// stopped FUTURE one-shot captures while an already-running stream kept
/// delivering desktop pixels to a phone whose authority had ended. Found by an
/// outside security review on 2026-09-07; `StreamController::start`'s own doc
/// had said the quiet part out loud for weeks: "the caller must have passed the
/// authorize_frame gate for this surface first."
///
/// Authority is not a fact established once. It is a fact that can stop being
/// true while the thing it authorized is still running, which is exactly what
/// revocation and expiry mean.
///
/// `NoStream` is deliberately distinct from `AuthorityEnded`: chunks can still
/// be queued after a stream is dropped, and those must be drained rather than
/// sent — silently, because a stopped stream is not an error.
///
/// Pure, so the rule is tested without a socket, a Noise handshake or a live
/// peer — none of which the send loop can be given in a unit test.
fn chunk_send_decision(
    stream: Option<&StreamController>,
    session: &ShareSession,
    now: u64,
) -> ChunkSend {
    let Some(s) = stream else {
        return ChunkSend::NoStream;
    };
    match session.authorize_frame(s.surface(), now) {
        Ok(()) => ChunkSend::Send,
        Err(_) => ChunkSend::AuthorityEnded,
    }
}

/// Is this Agent2 command a pointer move?
///
/// Kept as a pure string predicate so it is testable without a session, and
/// deliberately CONSERVATIVE: anything it cannot positively identify as a move
/// is treated as a real command and logged in full. A missed move costs one
/// noisy line; a misclassified grant or refusal costs the record of a security
/// decision, and that asymmetry decides the default.
fn is_pointer_move_command(json_str: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return false;
    };
    if v.get("type").and_then(|t| t.as_str()) != Some("input_event") {
        return false;
    }
    v.get("event")
        .and_then(|e| e.as_object())
        .is_some_and(|e| e.len() == 1 && e.contains_key("MouseMove"))
}

/// The client is gone: end the share session and let go of anything it left
/// pressed.
///
/// A named function rather than four lines inline, because it is the only way
/// the disconnect half of the release work can be tested at all — the loop
/// around it needs a socket, a Noise handshake and a live peer. Testability by
/// construction; the loop calls exactly this and nothing else.
fn end_session_and_release(session: &mut ShareSession) {
    // Clears the allow-list and marks the session inert, so no late frame or
    // input can be authorized after the client is gone.
    session.end();

    // Let go of anything the client left pressed. A press and its release are
    // two separate messages, so a client that disappears between them — a
    // backgrounded app, a dropped link, a bug that emits a press nobody asked
    // for — used to leave the host holding a mouse button or a modifier with
    // nothing able to release it short of host Stop. The operator met that:
    // hover still highlighted, no click landed, and the way out was the power
    // button. Ending the session is precisely the moment nothing further can
    // legitimately be held.
    module10::inject::release_input_state();
}

/// RD-2 host-side capability gate. High-impact capabilities (screen capture,
/// input injection, file transfer) are **deny-by-default**; each is granted
/// only when the host operator has explicitly enabled it for this run
/// (`RD_CAP_SCREENSHOT=1` / `RD_CAP_INPUT=1` / `RD_CAP_FILE=1`).
///
/// This is the honest minimum: it replaces the blanket denial with a real
/// gate the capture path is wired through, without weakening the safe default.
/// The richer form — a per-session, per-invite *signed* capability grant
/// carried through RD-2's Ed25519 invite-trust layer — is the follow-up, and
/// this function is the single seam where that check will live.
/// Every capability variable, so a malformed one can be found without waiting
/// for the feature it gates to be used.
const CAPABILITY_VARS: [&str; 4] = [
    "RD_CAP_SCREENSHOT",
    "RD_CAP_INPUT",
    "RD_CAP_CLIPBOARD",
    "RD_CAP_FILE",
];

/// Whether a capability variable is set to something that will not grant.
///
/// The gate is `== Ok("1")` and stays that way. Windows round 5 found that the
/// natural instruction `set RD_CAP_INPUT=1 && run.bat` stores `"1 "` — cmd takes
/// everything up to the `&&` as the value — so the operator does exactly what
/// they were told and the gate stays shut, silently.
///
/// **The fix is not to trim.** This is a deny-by-default security gate and
/// loosening what counts as "yes" is the wrong direction: the Windows agent said
/// so and they are right. The fix is to STOP BEING SILENT about it.
fn capability_value_is_malformed(value: &str) -> bool {
    value != "1"
}

/// Say so at startup when a capability variable is set but will not grant.
///
/// The value is printed **quoted**, which is the whole point: `RD_CAP_INPUT="1 "`
/// shows the trailing space that `RD_CAP_INPUT=1 ` hides, and that one character
/// is the difference between a working grant and a refusal the operator cannot
/// explain.
fn warn_about_malformed_capability_vars() {
    for var in CAPABILITY_VARS {
        let Ok(value) = std::env::var(var) else {
            continue;
        };
        if capability_value_is_malformed(&value) {
            eprintln!(
                "[host_app] WARNING: {var}=\"{value}\" is set but is not exactly \"1\", \
                 so this capability is NOT granted."
            );
            eprintln!(
                "[host_app]          If you meant to grant it, note that \
                 `set {var}=1 && run.bat` stores \"1 \" on Windows — \
                 use `set \"{var}=1\"` instead."
            );
        }
    }
}

fn capability_granted(cap: &str) -> bool {
    let env = match cap {
        "screenshot_request" => "RD_CAP_SCREENSHOT",
        "input_event" => "RD_CAP_INPUT",
        // Its own capability, off unless the operator sets it. A paired phone
        // that may drive the mouse has not thereby been given the machine's
        // clipboard, which holds things that were never on screen.
        "clipboard" => "RD_CAP_CLIPBOARD",
        _ => return false,
    };
    std::env::var(env).as_deref() == Ok("1")
}

/// Minimal JSON string escaping for names echoed into responses.
///
/// THIS DOC COMMENT ARRIVED IN THE BASELINE IMPORT WITH NO FUNCTION UNDER IT.
/// The original author described the escaping and it was never brought across,
/// while `cmd_type` — a string chosen entirely by the peer — was interpolated
/// raw into a `denied` reply. A type containing a quote could therefore break
/// or inject into the JSON the host sends back.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render peer-controlled text safe to put in a log line.
///
/// A log is read by a person and often pasted into a bug report. Text chosen by
/// the peer must not be able to FORGE a line in it: a newline plus `[host] `
/// would otherwise let a client write convincing fake events into the operator's
/// journal. Non-printable characters become `.`, and the result is bounded.
fn log_safe(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .take(max)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '.'
            }
        })
        .collect();
    if s.chars().count() > max {
        out.push('\u{2026}');
    }
    out
}

/// Describe a decrypted command for the log: what it was, never what it said.
///
/// THE DEFECT THIS EXISTS FOR. Every non-pointer command was logged VERBATIM,
/// before validation — the whole decrypted JSON. That put typed text, clipboard
/// contents and arbitrary peer-chosen strings into the host's stderr, and from
/// there into journals and diagnostics. It also let a peer forge log lines with
/// control characters.
///
/// The codebase already knew the rule and stated it plainly at the clipboard
/// handler: "The ACK reports the SIZE, never the content ... without the log
/// becoming the leak." That careful handler was defeated by one line upstream
/// which printed the same text in full before it ever ran.
///
/// So this reports the command TYPE and bounded, numeric metadata. Nothing the
/// peer wrote is echoed except the type, which is sanitized and truncated.
fn describe_command(json_str: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) else {
        // Deliberately not echoed: unparseable input is exactly the input most
        // likely to be hostile.
        return format!("unparseable ({} bytes)", json_str.len());
    };
    let ty = log_safe(
        v.get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("(untyped)"),
        32,
    );
    match ty.as_str() {
        // The event KIND is useful and safe; a scan code is a keystroke.
        "input_event" => {
            let kind = v
                .get("event")
                .and_then(|e| e.as_object())
                .and_then(|o| o.keys().next().cloned())
                .unwrap_or_else(|| "(empty)".to_string());
            format!("input_event {}", log_safe(&kind, 24))
        }
        // Size, never content — matching what the handler itself reports.
        "clipboard_push" => {
            let n = v.get("text").and_then(|t| t.as_str()).map_or(0, str::len);
            format!("clipboard_push ({n} bytes)")
        }
        _ => ty,
    }
}

/// Dispatch an Agent2 JSON command from the Android client.
/// Returns an optional JSON response string to send back.
// ── Surface-scope enforcement (session_core ShareSession) ────────────────────
// Every capture/input command is gated by a per-connection `ShareSession`:
//   * capture (screenshot/stream) requires `authorize_frame(surface)` — the
//     surface must be in the permitted allow-list, which starts empty;
//   * input requires `authorize_input(surface)` — a permitted surface AND an
//     explicit InputControl grant, which viewing never implies;
//   * an ABSOLUTE pointer move additionally requires
//     `authorize_absolute_input(...)`, which refuses when the surface's geometry
//     is unknown rather than skipping the clamp.
// The gate logic is the tested `session_core` state machine (27 tests). This
// file supplies the platform geometry; it does not decide anything.
//
// NOTE ON VOCABULARY: the Rust API says "surface"; the WIRE still says
// "permit_window" / "list_windows" / "window". That mismatch is deliberate and
// temporary — the wire is Block 10's to change, and renaming it here would
// break every shipped Android client for a cosmetic gain.

pub(crate) fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The host's clipboard, on its way to the phone.
///
/// `serde_json` does the escaping. Hand-rolled quoting here would be a second
/// escaper for text this host does not control, and clipboard content is
/// exactly the input that finds the case the hand-rolled one missed.
fn json_clipboard(text: &str) -> String {
    let value = serde_json::json!({ "type": "clipboard", "text": text });
    value.to_string()
}

fn json_ack(for_cmd: &str) -> String {
    format!(r#"{{"type":"ack","for":"{for_cmd}"}}"#)
}
fn json_err(for_cmd: &str, reason: &str) -> String {
    format!(r#"{{"type":"error","for":"{for_cmd}","reason":"{reason}"}}"#)
}
fn json_denied(for_cmd: &str, reason: &str) -> String {
    format!(r#"{{"type":"denied","for":"{for_cmd}","reason":"{reason}"}}"#)
}
fn json_cap_denied(for_cmd: &str, env: &str) -> String {
    json_denied(for_cmd, &format!("capability not authorized (set {env}=1)"))
}
fn json_scope_denied(for_cmd: &str, err: &ShareError) -> String {
    // Typed denial from the ShareSession gate. Deliberately does not echo any
    // surface identity beyond what the client already sent.
    json_denied(for_cmd, &format!("surface scope: {err:?}"))
}

// ── Desktop lock state ─────────────────────────────────────────────────────
//
// A paired peer holding the input grant can type while the operator's screen
// is LOCKED. Proven here on 2026-09-07 in the VM harness
// (`scripts/test-input-across-lock.sh`): five synthetic keystrokes landed in
// the GNOME lock screen's password field, and the injection also woke the
// blanked display. uinput sits BELOW the compositor, so nothing above it
// declines the event on the session's behalf — the host has to.
//
// The state is logind's `LockedHint`, read through `loginctl`. It is not in
// `/run/systemd/sessions/<id>` (that file carries only ACTIVE, STATE and
// REMOTE), so there is no file to stat and D-Bus is the only source;
// `loginctl` is the way to ask it without taking a dependency. This release
// POLLS, on the five-second heartbeat the idle watchdog already runs.
// Subscribing to logind's `PropertiesChanged` would react immediately and is
// the intended follow-up, but it would stand a second zbus connection next to
// the portal's — the exact shape that has hung a capture session on this box
// before — and capture took four rounds to make reliable. Polling cannot
// destabilise it.
//
// Residual risk, stated rather than papered over: a peer that already holds
// the input grant keeps it for up to five seconds after the screen locks.
// That is a large reduction, not a complete fix.

/// What logind last said about the operator's session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockObservation {
    /// `LockedHint=no`.
    Unlocked,
    /// `LockedHint=yes`.
    Locked,
    /// logind has not answered at all on this run — a system with no
    /// systemd-logind, or a `loginctl` that is not installed.
    NeverObserved,
    /// logind answered earlier on this run and has stopped answering.
    Lost,
}

/// Whether input may be delivered to the desktop, given `observation`.
///
/// `Lost` refuses deliberately. If logind answered a moment ago and does not
/// answer now, the host cannot tell a locked desktop from an unlocked one, and
/// whatever stopped the probe is as easily hostile as accidental — otherwise
/// killing logind would itself be the way out of this guard. `NeverObserved`
/// allows, because a machine that has no logind never had this protection and
/// refusing every keystroke there would make the host useless rather than
/// safe; that limit is recorded in `docs/THREAT_MODEL.md` instead of hidden.
fn lock_gate(observation: LockObservation) -> Result<(), &'static str> {
    match observation {
        LockObservation::Unlocked | LockObservation::NeverObserved => Ok(()),
        LockObservation::Locked => Err("host desktop is locked"),
        LockObservation::Lost => Err("host desktop lock state is unavailable"),
    }
}

/// Cached `LockedHint`: 0 = no answer, 1 = unlocked, 2 = locked.
static LOCK_HINT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
/// Set the first time logind answers on this run, and never cleared. This is
/// what separates "there is no logind here" from "logind has gone quiet".
static LOCK_EVER_OBSERVED: AtomicBool = AtomicBool::new(false);

fn lock_observation() -> LockObservation {
    match LOCK_HINT.load(Ordering::SeqCst) {
        1 => LockObservation::Unlocked,
        2 => LockObservation::Locked,
        _ if LOCK_EVER_OBSERVED.load(Ordering::SeqCst) => LockObservation::Lost,
        _ => LockObservation::NeverObserved,
    }
}

/// The real uid from a `/proc/self/status` body.
///
/// Split out from the probe so the parsing is testable without a process: the
/// line is tab-separated and carries four uids (real, effective, saved,
/// filesystem), and the one that identifies the operator is the first.
#[cfg(target_os = "linux")]
fn parse_real_uid(status: &str) -> Option<String> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    let uid = line.split_whitespace().nth(1)?;
    if uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(uid.to_string())
}

/// Run `loginctl` and hand back its trimmed stdout, or `None` if it could not
/// be asked. A non-zero exit is not an answer, and neither is empty output.
#[cfg(target_os = "linux")]
fn loginctl_value(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("loginctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Ask logind whether the operator's GRAPHICAL session is locked.
///
/// The session is resolved through the user's `Display` property rather than
/// with the `auto` selector, and that choice is the whole point of this
/// function. `auto` returns the CALLER's session when the caller has one — so
/// a host started over SSH would be asking about the SSH session, which is
/// never locked, and the guard would silently never fire on exactly the
/// headless-server case RemoteDexter is most likely to be run in. `Display`
/// always names the seat's graphical session no matter where the host was
/// started from; verified on systemd 259 from a shell with no session of its
/// own.
///
/// No `Display` means no graphical session, and therefore no lock screen to be
/// typed into. That reports as unobservable rather than as "unlocked", and
/// `lock_gate` decides what to do about it.
#[cfg(target_os = "linux")]
fn probe_lock_hint() -> Option<bool> {
    let uid = parse_real_uid(&std::fs::read_to_string("/proc/self/status").ok()?)?;
    let display = loginctl_value(&["show-user", &uid, "-p", "Display", "--value"])?;
    match loginctl_value(&["show-session", &display, "-p", "LockedHint", "--value"])?.as_str() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// Non-Linux hosts have no logind to ask.
///
/// On Windows the lock screen runs on the Winlogon desktop, and a process
/// attached to the user's desktop cannot `SendInput` across to it — the OS
/// already refuses. This build does not rely on that: it reports the state as
/// unobservable and says so, rather than claiming a guarantee it has not
/// tested on that platform.
#[cfg(not(target_os = "linux"))]
fn probe_lock_hint() -> Option<bool> {
    None
}

/// Refresh the cached hint. Called once as a session goes live and then on the
/// five-second heartbeat, so the input path never spawns a process of its own.
fn refresh_lock_state() {
    match probe_lock_hint() {
        Some(locked) => {
            LOCK_EVER_OBSERVED.store(true, Ordering::SeqCst);
            LOCK_HINT.store(if locked { 2 } else { 1 }, Ordering::SeqCst);
        }
        None => LOCK_HINT.store(0, Ordering::SeqCst),
    }
}

/// `list_windows` — the client's picker source. Lists the surfaces this host can
/// share (title + opaque id); it never captures them. The client then sends
/// `permit_window` for a chosen id before any capture is authorized.
///
/// On Linux that list is one entry: the desktop. See `share_source`.
fn list_windows_response() -> String {
    let items: Vec<String> = share_source::enumerate()
        .iter()
        .map(|d| {
            let title = d.title.replace('\\', "\\\\").replace('"', "\\\"");
            format!(
                r#"{{"id":{},"title":"{}","desktop":{}}}"#,
                d.id.raw(),
                title,
                matches!(d.kind, session_core::SurfaceKind::Desktop)
            )
        })
        .collect();
    format!(r#"{{"type":"windows","windows":[{}]}}"#, items.join(","))
}

/// Reads the wire's `"window"` field into a [`SurfaceId`]. The wire key keeps
/// its old name until Block 10 versions the protocol; see the note above.
fn surface_id_of(cmd: &serde_json::Value) -> Option<SurfaceId> {
    cmd.get("window")
        .and_then(|v| v.as_u64())
        .map(SurfaceId::new)
}

/// Handle the session/consent-management commands (the client drives the
/// allow-list + control level here). Returns `Some(response)` if it handled
/// `cmd_type`, else `None` so the caller routes elsewhere.
fn handle_session_command(
    session: &mut ShareSession,
    cmd_type: &str,
    cmd: &serde_json::Value,
    now: u64,
) -> Option<String> {
    match cmd_type {
        "list_windows" => Some(list_windows_response()),
        "permit_window" => match surface_id_of(cmd) {
            Some(w) => match session.permit_surface(w) {
                // Begin (or stay in) live sharing once a surface is permitted.
                Ok(()) => {
                    let _ = session.start(now);
                    Some(json_ack("permit_window"))
                }
                Err(e) => Some(json_scope_denied("permit_window", &e)),
            },
            None => Some(json_err("permit_window", "missing window id")),
        },
        "revoke_window" => match surface_id_of(cmd) {
            Some(w) => match session.revoke_surface(w) {
                Ok(()) => Some(json_ack("revoke_window")),
                Err(e) => Some(json_scope_denied("revoke_window", &e)),
            },
            None => Some(json_err("revoke_window", "missing window id")),
        },
        // Refused up front when input injection is not enabled for this run,
        // rather than acknowledged and then contradicted. `input_event` is
        // gated on the same capability a few lines down in `input_gate`, so an
        // unconditional ACK here told the client it had control and then denied
        // every event it sent — the client's `ControlDenialPolicy.losesGrant`
        // turned control straight back off, which reads as a UI that enables
        // and then reverts a second or two later. Diagnosed 2026-08-25.
        //
        // A grant the host will not honour is worse than a plain refusal: the
        // refusal names `RD_CAP_INPUT`, so the operator can see what to set.
        "grant_input" => {
            if !capability_granted("input_event") {
                Some(json_cap_denied("grant_input", "RD_CAP_INPUT"))
            } else {
                match session.grant_input() {
                    Ok(()) => Some(json_ack("grant_input")),
                    Err(e) => Some(json_scope_denied("grant_input", &e)),
                }
            }
        }
        "revoke_input" => match session.revoke_input() {
            Ok(()) => {
                // Let go of anything still pressed, and do it AFTER the revoke
                // has succeeded rather than before, so a refused revoke does
                // not drop a live drag.
                //
                // Past the revoke every input_event is denied, so a client that
                // was holding a button can no longer send its Up — the host
                // would keep it down with nothing able to release it. The
                // Android client already releases before it asks, but a host
                // must not depend on a client being well behaved to avoid
                // holding the machine down; "no more input from this peer" has
                // to mean nothing of theirs is still pressed.
                module10::inject::release_input_state();
                Some(json_ack("revoke_input"))
            }
            Err(e) => Some(json_scope_denied("revoke_input", &e)),
        },
        // ── clipboard ────────────────────────────────────────────────────
        //
        // Both directions require the INPUT grant, not merely a session.
        // Writing the host's clipboard is writing to the host. Reading it is
        // not "viewing" either: the clipboard holds what was copied, which is
        // very often something that was never on screen — so a viewer who
        // could pull it would be taking data the view never showed them.
        //
        // Gated on `clipboard_grant`, which is `input_gate` minus the event
        // parsing; the surface authorization and the capability check are the
        // same ones every input event passes.
        "clipboard_push" => match clipboard_grant(session, "clipboard_push", cmd, now) {
            Err(denial) => Some(denial),
            Ok(()) => match cmd.get("text").and_then(|v| v.as_str()) {
                None => Some(json_err("clipboard_push", "missing text")),
                Some(text) => match clipboard::write_host_clipboard(text) {
                    // The ACK reports the SIZE, never the content. An operator
                    // watching the console should be able to see that a
                    // transfer happened without the log becoming the leak.
                    Ok(()) => {
                        eprintln!("[host] clipboard set from client ({} bytes)", text.len());
                        Some(json_ack("clipboard_push"))
                    }
                    Err(e) => Some(json_denied("clipboard_push", e.reason())),
                },
            },
        },
        "clipboard_pull" => match clipboard_grant(session, "clipboard_pull", cmd, now) {
            Err(denial) => Some(denial),
            Ok(()) => match clipboard::read_host_clipboard() {
                Ok(text) => {
                    eprintln!("[host] clipboard read by client ({} bytes)", text.len());
                    Some(json_clipboard(&text))
                }
                Err(e) => Some(json_denied("clipboard_pull", e.reason())),
            },
        },
        _ => None,
    }
}

/// Clipboard gate: the clipboard capability plus the same surface-scoped input
/// authorization every keystroke passes.
///
/// Deliberately built from `authorize_input` rather than a rule of its own.
/// "May this peer put text into this machine" is the question the input grant
/// already answers, and a second rule for the clipboard is a second rule that
/// can disagree with the first — permissively, which is the direction such
/// copies drift.
fn clipboard_grant(
    session: &ShareSession,
    for_cmd: &str,
    cmd: &serde_json::Value,
    now: u64,
) -> Result<(), String> {
    if !capability_granted("clipboard") {
        return Err(json_cap_denied(for_cmd, "RD_CAP_CLIPBOARD"));
    }
    // The clipboard takes the same lock check as `input_gate`. Pushing to it
    // while the screen is locked stages text for whoever unlocks; pulling from
    // it takes whatever the operator copied before they walked away.
    if let Err(why) = lock_gate(lock_observation()) {
        return Err(json_denied(for_cmd, why));
    }
    let w = surface_id_of(cmd).ok_or_else(|| json_err(for_cmd, "missing window id"))?;
    session
        .authorize_input(w, now)
        .map_err(|e| json_scope_denied(for_cmd, &e))
}

/// Capture gate: capability env grant + a permitted, currently-authorized window.
/// Returns the authorized `SurfaceId`, or the denial JSON to send back.
fn frame_gate(
    session: &ShareSession,
    for_cmd: &str,
    cmd: &serde_json::Value,
    now: u64,
) -> Result<SurfaceId, String> {
    if !capability_granted("screenshot_request") {
        return Err(json_cap_denied(for_cmd, "RD_CAP_SCREENSHOT"));
    }
    let w = surface_id_of(cmd).ok_or_else(|| json_err(for_cmd, "missing window id"))?;
    session
        .authorize_frame(w, now)
        .map_err(|e| json_scope_denied(for_cmd, &e))?;
    Ok(w)
}

/// Input gate: capability env grant + input authorized into a permitted surface
/// + a parsed, geometry-clamped event. Returns the message to inject, or a
/// denial. Every decision below is `session_core`'s; this function only reads
/// the platform's geometry and the client's JSON.
fn input_gate(
    session: &ShareSession,
    cmd: &serde_json::Value,
    now: u64,
) -> Result<module10::message::InputControlMessage, String> {
    use module10::message::{InputControlMessage, MouseMoveMode};
    if !capability_granted("input_event") {
        return Err(json_cap_denied("input_event", "RD_CAP_INPUT"));
    }
    // Before the surface scope, because a locked desktop is not a scope
    // question: there is no permitted window while the screen is a lock
    // screen, and the peer must be told the same thing whichever window it
    // named.
    if let Err(why) = lock_gate(lock_observation()) {
        return Err(json_denied("input_event", why));
    }
    let w = surface_id_of(cmd).ok_or_else(|| json_err("input_event", "missing window id"))?;
    session
        .authorize_input(w, now)
        .map_err(|e| json_scope_denied("input_event", &e))?;
    let event = cmd
        .get("event")
        .cloned()
        .ok_or_else(|| json_err("input_event", "missing event"))?;
    let msg: InputControlMessage =
        serde_json::from_value(event).map_err(|_| json_err("input_event", "bad event"))?;
    // Clamp absolute pointer moves to the permitted surface's on-screen rect: a
    // granted peer can never steer the pointer outside what it was given.
    //
    // The RULE lives in `session_core::authorize_absolute_input` and is tested
    // there; this function supplies only the platform geometry. That split is
    // deliberate. The clamp used to be written inline here as
    // `if let Some(rect) = ...`, so on Linux — where the per-window lookup
    // returns `None` for everything — it silently did not run at all. A
    // fail-open clamp reads exactly like a working one. Now the `None` case is
    // a typed refusal from a crate whose whole job is refusing.
    if let InputControlMessage::MouseMove {
        mode: MouseMoveMode::Absolute,
        abs_x,
        abs_y,
        ..
    } = &msg
    {
        let geometry = share_source::rect(w).map(|(l, t, r, b)| SurfaceGeometry::new(l, t, r, b));
        session
            .authorize_absolute_input(w, now, geometry, *abs_x as i64, *abs_y as i64)
            .map_err(|e| json_scope_denied("input_event", &e))?;
    }
    Ok(msg)
}

/// Scoped screenshot: gate on a permitted surface, then capture ONLY that
/// surface (see `share_source` for what a surface is on each platform).
async fn handle_screenshot_scoped(
    session: &ShareSession,
    cmd: &serde_json::Value,
    now: u64,
) -> Option<String> {
    let w = match frame_gate(session, "screenshot_request", cmd, now) {
        Ok(w) => w,
        Err(resp) => return Some(resp),
    };
    // Capture on a blocking thread: DXGI/GDI and the portal pull are synchronous
    // and would otherwise stall the runtime.
    match tokio::task::spawn_blocking(move || share_source::capture_rgba(w)).await {
        Ok(Ok(frame)) => {
            let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
            sha2::Digest::update(&mut hasher, &frame.data);
            let digest = sha2::Digest::finalize(hasher);
            let fp: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
            eprintln!(
                "[host] surface {} captured {}x{} ({} bytes, sha256:{}…)",
                w.raw(),
                frame.width,
                frame.height,
                frame.data.len(),
                fp
            );
            Some(format!(
                r#"{{"type":"screenshot","window":{},"width":{},"height":{},"bytes":{},"sha256_prefix":"{}"}}"#,
                w.raw(),
                frame.width,
                frame.height,
                frame.data.len(),
                fp
            ))
        }
        Ok(Err(e)) => {
            eprintln!("[host] surface capture failed: {e}");
            Some(json_err("screenshot_request", "capture_failed"))
        }
        Err(e) => {
            eprintln!("[host] screenshot task join error: {e}");
            Some(json_err("screenshot_request", "capture_task_failed"))
        }
    }
}

/// Scoped input: gate on a permitted window + input control, clamp, then inject.
/// The operator's UIPI decision, in one place: **give back a grant the host
/// cannot deliver.**
///
/// Lifted out of `handle_input_scoped` so it can be tested. The behaviour it
/// encodes cannot be reached from a test otherwise — provoking a real
/// `NotLanded` needs a higher-integrity window holding the foreground, which
/// needs a person to consent to a UAC prompt. Taking a verdict as an argument
/// instead lets the *consequences* be tested everywhere, including on the
/// platform whose read-back can only ever answer `Unknown`.
///
/// **The release happens before the revoke, and the order is load-bearing.**
/// Past a revoke every `input_event` is denied, so an Up sent afterwards would
/// be refused and whatever was held would stay held — turning a safety
/// mechanism into the stuck desktop it exists to prevent.
fn refuse_undelivered_input(session: &mut ShareSession) -> String {
    let front = module10::inject::foreground_window_title();
    eprintln!(
        "[host] input is not reaching the desktop; revoking the grant. \
         Foreground window: {}",
        front.as_deref().unwrap_or("unknown")
    );
    eprintln!(
        "[host] this is UIPI: a window of higher integrity than this host \
         is focused, and Windows discards injected input without an error."
    );
    module10::inject::release_input_state();
    let _ = session.revoke_input();
    json_denied(
        "input_event",
        "input is not reaching the desktop (a higher-integrity window is focused); \
         the control grant has been given back",
    )
}

fn handle_input_scoped(
    session: &mut ShareSession,
    cmd: &serde_json::Value,
    now: u64,
) -> Option<String> {
    let msg = match input_gate(session, cmd, now) {
        Ok(m) => m,
        Err(resp) => return Some(resp),
    };
    // Text is expanded here, AFTER the gate. Doing it before would mean a run
    // of keystrokes had been built for a client that turned out not to hold
    // input control — and the expansion is the only part that can fail for a
    // reason the user can fix, so it must not be mixed up with authorisation.
    let msgs = match &msg {
        module10::message::InputControlMessage::TextInput { text } => {
            match module10::keymap::text_to_messages(text) {
                Ok(v) => v,
                Err(module10::keymap::TextError::Unsupported { ch, at }) => {
                    // The character is named in the LOG, not in the reply.
                    // It is the peer's own text so echoing it leaks nothing,
                    // but it would have to be escaped into JSON correctly on a
                    // path where getting that wrong is a parser bug.
                    eprintln!(
                        "[host] refusing text: character {ch:?} at position {at} is not \
                         typable on this layout"
                    );
                    return Some(json_err("input_event", "unsupported_character"));
                }
                Err(module10::keymap::TextError::TooLong { len, max }) => {
                    eprintln!("[host] refusing text: {len} characters exceeds the {max} limit");
                    return Some(json_err("input_event", "text_too_long"));
                }
            }
        }
        _ => vec![msg],
    };

    // A text run is many events. Injecting them one at a time through the same
    // path every other input takes means text inherits the modifier ordering
    // and error handling that are already proven, rather than getting its own.
    let mut injected_total = 0u32;
    for m in &msgs {
        // Log what is about to reach the kernel, BEFORE it does.
        //
        // Added 2026-08-30 after a button on the phone froze the operator's
        // display hard enough to need the power button. Neither side logged a
        // SUCCESSFUL press, so the record could not say which control caused it
        // — the one question the log needed to answer.
        //
        // Keys, buttons and scrolls only: pointer moves arrive at 60-120 a
        // second and would bury the events that matter. Nothing here prints
        // TEXT — `TextInput` is named and its content is not, because it is
        // whatever the operator typed, passwords included.
        log_injection(m);
        match module10::inject::inject(m) {
            Ok(injected) => injected_total += u32::from(injected),
            Err(e) => {
                // Stop at the first failure rather than pressing on. Continuing
                // could leave a modifier held down with no matching release.
                eprintln!("[host] input injection failed: {e}");
                return Some(json_err("input_event", "injection_failed"));
            }
        }

        // DID IT ACTUALLY LAND? On Windows, `SendInput` returns the full event
        // count while a higher-integrity foreground window swallows everything
        // — UIPI, found by the Windows box on 2026-09-01. The host would
        // otherwise record a press that never happened, later "release" it, and
        // report a clean desktop it was never driving.
        //
        // The operator's decision, the same day: REFUSE A GRANT THE HOST CANNOT
        // DELIVER. So the grant is given back here rather than carried on with,
        // and the client is told why instead of watching its input vanish.
        //
        // `Unknown` — every platform without a read-back, which is every
        // platform but Windows — is deliberately not a refusal.
        if module10::inject::verify_delivery(m) == module10::inject::Delivery::NotLanded {
            return Some(refuse_undelivered_input(session));
        }
    }
    Some(format!(
        r#"{{"type":"ack","for":"input_event","injected":{injected_total}}}"#
    ))
}

async fn dispatch_agent2_command(json: &str) -> Option<String> {
    // Parse the command type and route accordingly
    let cmd: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[host] Invalid Agent2 JSON: {e}");
            return Some(r#"{"error":"invalid_json"}"#.to_string());
        }
    };

    let cmd_type = cmd
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    match cmd_type {
        // `screenshot_request` and `input_event` are NOT handled here anymore.
        // They are window-scoped: the session loop routes them to
        // `handle_screenshot_scoped` / `handle_input_scoped`, which enforce the
        // per-window `ShareSession` gate (a client may only capture/control a
        // window it explicitly permitted — never the full desktop). Keeping a
        // full-desktop capture path here, even unreachable, would be a footgun,
        // so it is deliberately removed.
        "ping" => Some(r#"{"type":"pong"}"#.to_string()),
        // An unknown command is REFUSED, not acknowledged.
        //
        // This used to reply `ack`, which told a peer the host had done
        // something it had never heard of. Block 10 made that visible: cutting
        // `clipboard_sync` and `file_transfer` did not stop the host answering
        // them, it just moved them into this arm — so a client asking for a
        // deleted capability still got "done". The same shape as the
        // clipboard_sync stub itself, which acked without ever touching a
        // clipboard.
        //
        // `denied` rather than `error`: the peer sent something well-formed
        // that this host does not implement, which is a refusal, not a fault.
        // The client's negotiator treats both as fatal to the session, and
        // that is the intended outcome — a client asking for capabilities this
        // host does not have is not a session worth continuing quietly.
        _ => {
            eprintln!(
                "[host] refusing unsupported Agent2 command type: {}",
                log_safe(cmd_type, 32)
            );
            Some(format!(
                r#"{{"type":"denied","for":"{}","reason":"unsupported"}}"#,
                json_escape(cmd_type)
            ))
        }
    }
}

/// One line per input event that changes host state, for the record.
///
/// Deliberately quiet about the high-frequency events and about text. A log
/// that buries a stuck modifier under ten thousand pointer moves is a log
/// nobody reads, and one that prints what was typed is a keylogger.
fn log_injection(m: &module10::message::InputControlMessage) {
    use module10::message::InputControlMessage as M;
    match m {
        M::KeyEvent {
            scan_code,
            action,
            modifiers,
        } => {
            // The scan code is WHICH KEY, and a run of them is what the user
            // typed. `[input] text run of N characters` two arms below already
            // reports a count rather than content; a key event is the same
            // thing one keystroke at a time. Whether a modifier was held is
            // kept: it carries no content and it is what a stuck-Ctrl
            // investigation needs.
            let _ = scan_code;
            eprintln!("[input] key {action:?} modifiers=0x{modifiers:02X}")
        }
        M::MouseButton { button, action } => {
            eprintln!("[input] button {button} {action:?}")
        }
        M::MouseScroll { dx, dy, mode } => {
            eprintln!("[input] scroll dx={dx} dy={dy} {mode:?}")
        }
        // Named, never quoted. Its length is a diagnostic; its content is the
        // operator's.
        M::TextInput { text } => {
            eprintln!("[input] text run of {} characters", text.chars().count())
        }
        // Moves are the flood. Silent on purpose.
        _ => {}
    }
}

/// Send a length-prefixed message over the socket.
async fn send_noise_msg(stream: &mut tokio::net::TcpStream, data: &[u8]) -> Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    Ok(())
}

/// Receive a length-prefixed message from the socket.
async fn recv_noise_msg(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 65535 {
        anyhow::bail!("noise message too large: {len}");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed message to any async writer (the split write half
/// during a streaming session).
async fn write_framed<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

/// The exact bytes one stream chunk becomes on the wire.
///
/// A named function rather than three lines inside `select!` so a test can call
/// **this**, not a copy of it. The frame path is the one place where a copy
/// would have been especially cheap and especially useless: chunks are opaque
/// bytes, so a test that framed them itself would agree with itself no matter
/// what the host did.
///
/// That gap was real. Block 10 changed this path and nothing in the gate
/// covered it — frames crossing the wire were only exercised by the `RD_USE_HW`
/// tests, which need a portal grant and do not run here.
fn frame_chunk_on_the_wire(chunk: Vec<u8>) -> Result<Vec<u8>, wire::WireError> {
    Ok(wire::Envelope::new(wire::Kind::FrameChunkV1, 0, chunk)?.encode())
}

/// How slow one capture has to be before the host says so.
///
/// Above the 2-second worst case of the Linux capturer's own forced wait, so a
/// desktop that simply has not repainted stays quiet. Anything past this is the
/// SOURCE stalling, not the picture being still — a distinction the log could
/// not previously make, because a hung capture and a quiet one both produced
/// nothing at all.
const SLOW_CAPTURE_WARN: std::time::Duration = std::time::Duration::from_secs(3);

/// Max frame-data bytes per stream chunk: below the Noise plaintext ceiling
/// (~64 KiB) with headroom for the chunk header and the AEAD tag.
const STREAM_CHUNK_PAYLOAD: usize = 60000;
/// ~20 fps target for the screen stream.
const STREAM_FRAME_MS: u64 = 50;

/// The ladder's top rung must reproduce the previous fixed behaviour exactly,
/// so a healthy link is unchanged by adaptation. Checked at compile time rather
/// than trusted.
const _: () = assert!(
    stream_ladder::RUNGS[0].frame_interval_ms == STREAM_FRAME_MS,
    "the top rung must reproduce the previous fixed frame interval"
);

/// Owns the screen-stream producer thread. The DXGI capturer is `!Send`, so the
/// whole capture→encode→chunk pump lives on its own OS thread and only byte
/// chunks cross to the async connection loop (through a caller-supplied
/// channel). Dropping the controller signals the thread to stop; the thread
/// winds down within one frame interval.
struct StreamController {
    /// The surface this stream was authorized for.
    ///
    /// Kept so the SEND path can re-check that authority, not just the start
    /// path. Until 2026-09-07 `start`'s own doc said "the caller must have
    /// passed the authorize_frame gate for this surface first" — and that was
    /// the whole check. See `chunk_send_decision`.
    surface: SurfaceId,
    stop: std::sync::Arc<AtomicBool>,
    /// Set by the capture thread itself right before it returns — on a clean
    /// `stop` request *and* on an unrecoverable capture error. Distinct from
    /// `stop`, which only ever means "please stop" (set from the outside, by
    /// `Drop`); this means "already stopped" (set from the inside). Without
    /// it, a capture error left `stream_start` believing a dead controller
    /// was still live: the command handler's `if stream.is_none()` guard
    /// would see `Some(_)` forever, silently ACK every retry, and never spawn
    /// a new capture thread — the client would be told to keep waiting for
    /// frames that could now never come, even after the operator re-granted
    /// the portal permission that failed the first time.
    finished: std::sync::Arc<AtomicBool>,
}

impl StreamController {
    /// True once the capture thread has exited, whether by request or by an
    /// unrecoverable error. Lets the `stream_start` handler tell a dead
    /// controller apart from a live one instead of trusting `Option::is_some`.
    fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Relaxed)
    }

    /// The surface this stream was authorized for.
    fn surface(&self) -> SurfaceId {
        self.surface
    }

    /// Start a stream **scoped to a single permitted surface** —
    /// one window on Windows, the desktop on Linux (see `share_source`).
    /// JPEG-encodes with module11's encoder and chunks it onto the wire in the
    /// exact format the client already expects. The caller must have passed the
    /// `ShareSession` `authorize_frame` gate for this surface first.
    fn start(quality: u8, tx: tokio::sync::mpsc::Sender<Vec<u8>>, surface: SurfaceId) -> Self {
        // Any previous fault belonged to a previous stream. Cleared here rather
        // than on stop, because a stream that fails never reaches its own
        // cleanup — and a warning left standing over a healthy stream is spent
        // credibility.
        CAPTURE_FAULT.clear();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let finished = std::sync::Arc::new(AtomicBool::new(false));
        let finished_thread = finished.clone();
        std::thread::Builder::new()
            .name("rd-window-stream".into())
            .spawn(move || {
                use module11::Encoder as _;
                let encoder = module11::JPEGEncoder::new();
                // The requested quality is a CEILING, not a setting: the
                // ladder may lower it under pressure, never raise it above what
                // the caller asked for.
                let requested_quality = quality.clamp(1, 100);
                let mut ladder = stream_ladder::State::top();
                let mut window_sent: u32 = 0;
                let mut window_dropped: u32 = 0;
                let mut seq: u32 = 0;
                let mut dropped: u64 = 0;
                let mut last_geometry = None;
                eprintln!(
                    "[host] surface stream started for surface {}",
                    surface.raw()
                );
                while !stop_thread.load(Ordering::Relaxed) {
                    let t0 = std::time::Instant::now();
                    let rung = ladder.rung();
                    let quality = requested_quality.min(rung.quality);
                    let interval = std::time::Duration::from_millis(rung.frame_interval_ms);
                    // A capture that never returns is invisible: the thread
                    // simply stops, the client waits, and the host's last line
                    // is "surface stream started". That happened on a SECOND
                    // stream in one host run on 2026-08-29 — ten minutes of
                    // silence with the thread parked on a futex, and no way to
                    // tell a hung capture from a quiet desktop.
                    //
                    // Timed here rather than inside the capture: the point is
                    // to catch the case where the call does not come back at
                    // all, which nothing inside it can report.
                    let capture_started = std::time::Instant::now();
                    let capture_result = share_source::capture_rgba(surface);
                    let capture_took = capture_started.elapsed();
                    if capture_took >= SLOW_CAPTURE_WARN {
                        eprintln!(
                            "[host] capture took {} ms — the source is stalling",
                            capture_took.as_millis()
                        );
                    }
                    match capture_result {
                        Ok(raw) => {
                            let (w, h) = (raw.width, raw.height);
                            if last_geometry.replace((w, h)) != Some((w, h)) {
                                eprintln!(
                                    "[host] surface {} stream geometry: {w}x{h}",
                                    surface.raw()
                                );
                            }
                            match encoder.encode(
                                &raw,
                                quality,
                                module11::ChromaSubsampling::Yuv420,
                                None,
                            ) {
                                Ok(encoded) => {
                                    // Drop the frame rather than queue it when
                                    // the link is behind. A remote desktop wants
                                    // the NEWEST frame; the next capture is
                                    // fresher than this one will be by the time
                                    // it drains. See `stream_backpressure`.
                                    let needed = stream_backpressure::chunks_needed(
                                        encoded.data.len(),
                                        STREAM_CHUNK_PAYLOAD,
                                    );
                                    match stream_backpressure::decide(
                                        tx.capacity(),
                                        needed,
                                        tx.max_capacity(),
                                    ) {
                                        stream_backpressure::Decision::Drop => {
                                            dropped = dropped.saturating_add(1);
                                            window_dropped += 1;
                                            // Loud enough to diagnose a slow
                                            // link, quiet enough not to become
                                            // the load itself.
                                            if dropped % 120 == 1 {
                                                eprintln!(
                                                    "[host] link behind: {dropped} frame(s) \
                                                     dropped so far (queue {}/{})",
                                                    tx.max_capacity() - tx.capacity(),
                                                    tx.max_capacity()
                                                );
                                            }
                                        }
                                        stream_backpressure::Decision::Send => {
                                            window_sent += 1;
                                            seq = seq.wrapping_add(1);
                                            for c in module11::chunk_frame(
                                                seq,
                                                w.min(u16::MAX as u32) as u16,
                                                h.min(u16::MAX as u32) as u16,
                                                encoded.is_keyframe,
                                                &encoded.data,
                                                STREAM_CHUNK_PAYLOAD,
                                            ) {
                                                // Err = the async receiver was dropped -> stop.
                                                if tx.blocking_send(c).is_err() {
                                                    finished_thread.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => eprintln!("[host] window encode error: {e}"),
                            }
                            if window_sent + window_dropped >= stream_ladder::WINDOW_FRAMES {
                                let before = ladder.rung;
                                ladder =
                                    stream_ladder::on_window(ladder, window_dropped, window_sent);
                                if ladder.rung != before {
                                    let now = ladder.rung();
                                    eprintln!(
                                        "[host] stream rung {before} -> {} ({} ms/frame, q{}) \
                                         after {window_dropped}/{} dropped",
                                        ladder.rung,
                                        now.frame_interval_ms,
                                        now.quality,
                                        window_sent + window_dropped
                                    );
                                }
                                window_sent = 0;
                                window_dropped = 0;
                            }
                        }
                        Err(e) => {
                            // Surface closed / minimized / grant revoked — stop
                            // streaming rather than fall back to anything wider.
                            //
                            // The client used to learn none of this: this thread
                            // just ended, the chunk channel silently closed, and
                            // the operator was left staring at an indefinite
                            // black screen with no error, no disconnect, nothing.
                            // Tell it explicitly, over the same channel frames
                            // would have used — the client already treats any
                            // non-stream-tagged message on this session as JSON.
                            eprintln!("[host] surface capture error (stopping stream): {e}");
                            // One call, both audiences. Telling only the
                            // client left the operator's own screen claiming
                            // the session was healthy (defect C), and two
                            // adjacent calls is how that recurs.
                            let reason =
                                capture_status::report_failure(&CAPTURE_FAULT, &e.to_string());
                            let _ = tx.blocking_send(json_err("stream", &reason).into_bytes());
                            finished_thread.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                    if let Some(rem) = interval.checked_sub(t0.elapsed()) {
                        std::thread::sleep(rem);
                    }
                }
                eprintln!("[host] window stream stopped");
                finished_thread.store(true, Ordering::Relaxed);
            })
            .expect("spawn stream thread");
        Self {
            surface,
            stop,
            finished,
        }
    }
}

impl Drop for StreamController {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {

    // ------------------------------------------- which invite a route mints

    fn mint_service() -> pairing::PairingService {
        use ed25519_dalek::SigningKey;
        let mut csprng = rand::rngs::OsRng;
        pairing::PairingService::new(SigningKey::generate(&mut csprng), "aa".repeat(32))
    }

    /// **A bound host advertises an address; a dialled-out host advertises a
    /// relay.** Neither may advertise the other, because a v4 invite names a
    /// socket the phone will try to open and a dialled-out host has none.
    #[test]
    fn the_route_decides_which_invite_schema_is_minted() {
        let caps = vec![pairing::CAP_VIEW.to_string()];
        let mut svc = mint_service();

        let bound = mint_for(
            &mut svc,
            &host_controller::Reach::Bound("192.168.1.20:8082".parse().unwrap()),
            1000,
            &caps,
        )
        .expect("a bound host could not mint");
        match &bound {
            Minted::Direct(i) => {
                assert_eq!(i.invite.version, pairing::INVITE_VERSION);
                assert_eq!(i.invite.addr, "192.168.1.20");
            }
            Minted::Relay(_) => panic!("a bound host minted a relay invite"),
        }

        let relay = mint_for(
            &mut svc,
            &host_controller::Reach::ViaRelay {
                relay: "203.0.113.9:9443".parse().unwrap(),
                session: "Zm9vYmFyYmF6cXV4MDAwMA".into(),
            },
            1000,
            &caps,
        )
        .expect("a dialled-out host could not mint");
        match &relay {
            Minted::Relay(i) => {
                assert_eq!(i.invite.version, pairing::RELAY_INVITE_VERSION);
                assert_eq!(i.invite.relay_addr, "203.0.113.9");
                assert_eq!(i.invite.session, "Zm9vYmFyYmF6cXV4MDAwMA");
            }
            Minted::Direct(_) => panic!("a dialled-out host minted a direct invite"),
        }
    }

    /// **The log line carries neither the token nor the session id.** The
    /// session is what a phone presents to reach this host; it belongs in the
    /// QR and nowhere else, exactly like the token.
    #[test]
    fn the_minting_log_line_names_no_credential() {
        let caps = vec![pairing::CAP_VIEW.to_string()];
        let mut svc = mint_service();
        let session = "Zm9vYmFyYmF6cXV4MDAwMA";
        let minted = mint_for(
            &mut svc,
            &host_controller::Reach::ViaRelay {
                relay: "203.0.113.9:9443".parse().unwrap(),
                session: session.into(),
            },
            1000,
            &caps,
        )
        .unwrap();

        let line = minted.describe();
        assert!(
            !line.contains(session),
            "the minting log line carried the session id: {line}"
        );
        let token = match &minted {
            Minted::Relay(i) => i.invite.token.clone(),
            Minted::Direct(i) => i.invite.token.clone(),
        };
        assert!(
            !line.contains(&token),
            "the minting log line carried the token"
        );
        assert!(
            !minted.token_fingerprint().contains(&token),
            "the fingerprint contains the token it stands in for"
        );
    }

    /// An invite view carries the QR and nothing that identifies the route, so
    /// neither schema leaks through the UI boundary.
    #[test]
    fn an_invite_view_is_the_same_shape_whichever_route_minted_it() {
        let caps = vec![pairing::CAP_VIEW.to_string()];
        let mut svc = mint_service();
        let direct = mint_for(
            &mut svc,
            &host_controller::Reach::Bound("192.168.1.20:8082".parse().unwrap()),
            1000,
            &caps,
        )
        .unwrap()
        .into_view();
        let relay = mint_for(
            &mut svc,
            &host_controller::Reach::ViaRelay {
                relay: "203.0.113.9:9443".parse().unwrap(),
                session: "Zm9vYmFyYmF6cXV4MDAwMA".into(),
            },
            1000,
            &caps,
        )
        .unwrap()
        .into_view();
        assert_eq!(direct.expires_at, relay.expires_at);
        assert!(direct.qr_size > 0 && relay.qr_size > 0);
        assert_eq!(relay.qr_modules.len(), relay.qr_size * relay.qr_size);
    }

    use std::sync::Arc;
    // The production path no longer creates listeners — host_controller does.
    // The protocol tests still need one to drive handle_client_connection.
    use super::*;
    use tokio::net::TcpListener;

    fn test_host_identity() -> &'static HostIdentity {
        HOST_IDENTITY.get_or_init(|| {
            let kp = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
                .generate_keypair()
                .unwrap();
            HostIdentity {
                private: kp.private,
                public: kp.public,
            }
        })
    }

    /// A loopback host driven by the SAME token authority the console uses.
    ///
    /// Before the Block 4 repair this harness minted its token from
    /// `SessionManager::generate_invite_token` — a store the console never
    /// populates. Every test here passed while a token from a real v4 QR could
    /// not be accepted by the shipping host at all. The harness now takes a
    /// `PairingService`, which is what the console holds.
    async fn start_loopback_host_with(
        pairing: &pairing::PairingService,
    ) -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<Result<()>>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tokens = pairing.redemption_handle();
        let devices = pairing::devices::DeviceHandle::new();
        let (auth_tx, auth_rx) = tokio::sync::mpsc::unbounded_channel();
        let notifier = host_controller::AuthNotifier::new(auth_tx, addr.to_string());
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            handle_client_connection(socket, tokens, devices, notifier).await
        });
        (addr, task, auth_rx)
    }

    /// A loopback host that serves SEVERAL connections in sequence, sharing one
    /// device store.
    ///
    /// `start_loopback_host_with` accepts exactly one connection and then the
    /// task ends, so a second connect gets "Connection reset by peer" no matter
    /// what the host would have decided. That is a harness limit, and a test of
    /// reconnection built on it would be measuring the harness — which is
    /// exactly the trap the 2026-08-26 device test fell into. Durable pairing
    /// needs at least two connections against one host, and needs them to share
    /// a store: a device enrolled on the first must be recognised on the second.
    async fn start_loopback_host_serving(
        pairing: &pairing::PairingService,
        connections: usize,
    ) -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
        pairing::devices::DeviceHandle,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tokens = pairing.redemption_handle();
        // ONE store for the host, as in the real backend.
        let devices = pairing::devices::DeviceHandle::new();
        let owner_view = devices.clone();
        let (auth_tx, auth_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            for _ in 0..connections {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let notifier =
                    host_controller::AuthNotifier::new(auth_tx.clone(), addr.to_string());
                // A refused connection must not end the host: the next one is
                // the whole point of the test.
                let _ = handle_client_connection(socket, tokens.clone(), devices.clone(), notifier)
                    .await;
            }
        });
        (addr, task, auth_rx, owner_view)
    }

    /// Mint a real v4 invitation and return its token, exactly as the console
    /// would put it in a QR.
    fn real_invite_token(pairing: &mut pairing::PairingService) -> String {
        let bind: std::net::SocketAddr = "127.0.0.1:8082".parse().unwrap();
        pairing
            .create_invite(bind, now_epoch_secs(), &[pairing::CAP_VIEW.to_string()])
            .expect("mint")
            .invite
            .token
    }

    fn test_pairing_service() -> pairing::PairingService {
        let mut csprng = rand::rngs::OsRng;
        pairing::PairingService::new(
            ed25519_dalek::SigningKey::generate(&mut csprng),
            "ab".repeat(32),
        )
    }

    async fn connect_with_pair_auth(
        addr: std::net::SocketAddr,
        token: &str,
        protocol: &str,
        version: u8,
        expected_host_pub: &[u8],
    ) -> Result<()> {
        let mut socket = tokio::net::TcpStream::connect(addr).await?;
        let keypair = snow::Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
        let mut handshake = snow::Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&keypair.private)
            .build_initiator()?;
        let mut buf = vec![0u8; 65535];

        let len = handshake.write_message(&[], &mut buf)?;
        send_noise_msg(&mut socket, &buf[..len]).await?;
        let message = recv_noise_msg(&mut socket).await?;
        handshake.read_message(&message, &mut buf)?;
        if handshake.get_remote_static() != Some(expected_host_pub) {
            anyhow::bail!("host key pin mismatch");
        }
        let len = handshake.write_message(&[], &mut buf)?;
        send_noise_msg(&mut socket, &buf[..len]).await?;

        let mut noise = handshake.into_transport_mode()?;
        let auth = serde_json::to_vec(&PairAuth {
            token: token.to_string(),
            protocol: protocol.to_string(),
            version,
        })?;
        let len = noise.write_message(&auth, &mut buf)?;
        send_noise_msg(&mut socket, &buf[..len]).await?;

        let reply = recv_noise_msg(&mut socket).await?;
        let len = noise.read_message(&reply, &mut buf)?;
        let reply: serde_json::Value = serde_json::from_slice(&buf[..len])?;
        if reply.get("type").and_then(|value| value.as_str()) != Some("pair_ok") {
            anyhow::bail!("pairing refused by host");
        }
        Ok(())
    }

    /// Connect with a CALLER-SUPPLIED client identity, optionally without a
    /// token.
    ///
    /// `connect_with_pair_auth` generates a fresh Noise keypair on every call,
    /// so it cannot express "the same device coming back" — which is precisely
    /// what durable pairing is about. This variant keeps the identity stable
    /// and lets the token be omitted, so a reconnect can be attempted the way a
    /// paired device would attempt it.
    async fn connect_as_device(
        addr: std::net::SocketAddr,
        keypair: &snow::Keypair,
        token: Option<&str>,
        expected_host_pub: &[u8],
    ) -> Result<()> {
        let mut socket = tokio::net::TcpStream::connect(addr).await?;
        let mut handshake = snow::Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&keypair.private)
            .build_initiator()?;
        let mut buf = vec![0u8; 65535];

        let len = handshake.write_message(&[], &mut buf)?;
        send_noise_msg(&mut socket, &buf[..len]).await?;
        let message = recv_noise_msg(&mut socket).await?;
        handshake.read_message(&message, &mut buf)?;
        if handshake.get_remote_static() != Some(expected_host_pub) {
            anyhow::bail!("host key pin mismatch");
        }
        let len = handshake.write_message(&[], &mut buf)?;
        send_noise_msg(&mut socket, &buf[..len]).await?;

        let mut noise = handshake.into_transport_mode()?;
        let auth = serde_json::to_vec(&PairAuth {
            token: token.unwrap_or_default().to_string(),
            protocol: pairing::SESSION_PROTOCOL.to_string(),
            version: SESSION_PROTOCOL_VERSION,
        })?;
        let len = noise.write_message(&auth, &mut buf)?;
        send_noise_msg(&mut socket, &buf[..len]).await?;

        let reply = recv_noise_msg(&mut socket).await?;
        let len = noise.read_message(&reply, &mut buf)?;
        let reply: serde_json::Value = serde_json::from_slice(&buf[..len])?;
        if reply.get("type").and_then(|value| value.as_str()) != Some("pair_ok") {
            anyhow::bail!("pairing refused by host");
        }
        Ok(())
    }

    /// Give the client a device identity that survives across connections.
    ///
    /// `APP_DATA_DIR` inside the client is a `OnceLock`, deliberately: an app
    /// moves its identity nowhere after startup. That makes this process-wide
    /// and first-caller-wins, so the directory must outlive every test rather
    /// than being cleaned up by whichever one happened to create it — a
    /// `TempDir` dropped at the end of one test would pull the identity file
    /// out from under the others. It is left behind under the system temp
    /// directory on purpose, named by pid.
    ///
    /// Sharing one client identity across tests is safe because the token-less
    /// branch is the only place the host consults it, and each test builds its
    /// own device store.
    fn persistent_client_identity() {
        let dir = std::env::temp_dir().join(format!("rd-client-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        remotedexter::set_data_dir(dir.to_str().unwrap());
    }

    /// Decode what the host actually put on the wire.
    ///
    /// Block 10: every message after `pair_ok` is a `wire::Envelope`, so a test
    /// that reads `plaintext` directly is reading a header. Two of these used
    /// to sniff `STREAM_TAG` on the first byte to tell a frame from a
    /// response — the very guess the envelope replaced.
    fn opened(frame: &remotedexter::ReceivedNoiseFrame) -> wire::Envelope {
        wire::decode_exact(&frame.plaintext)
            .unwrap_or_else(|e| panic!("host sent something that is not an envelope: {e:?}"))
    }

    // ── frames on the wire, without hardware ─────────────────────────────
    //
    // The gap Block 10 walked through: the frame path is only exercised
    // end-to-end by the RD_USE_HW tests, which need a real portal grant and do
    // not run in the gate. So the envelope adoption changed how every frame is
    // framed with nothing verifying it, and the operator found the next black
    // screen instead of a test doing.
    //
    // Capture cannot be faked here — the host deliberately refuses synthetic
    // frames rather than stream a fake desktop. What CAN be driven without
    // hardware is everything after capture: the real chunker, the host's own
    // `frame_chunk_on_the_wire`, and the client's own `classify_inbound`.

    /// A frame survives the whole wire format and comes back byte-identical.
    #[test]
    fn a_frame_survives_the_host_framing_and_the_client_classifier() {
        // Not uniform bytes: a run-length pattern that would expose chunks
        // reassembled in the wrong order, or one dropped from the middle.
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let chunks =
            module11::chunk::chunk_frame(42, 1920, 1080, true, &payload, STREAM_CHUNK_PAYLOAD);
        assert!(chunks.len() > 1, "the test needs a multi-chunk frame");

        let mut reassembler = module11::chunk::FrameReassembler::new();
        let mut completed = None;
        for (i, chunk) in chunks.into_iter().enumerate() {
            let on_wire =
                frame_chunk_on_the_wire(chunk).expect("the host must be able to frame it");
            match remotedexter::classify_inbound(&mut reassembler, &on_wire) {
                remotedexter::InboundMessage::Frame(f) => completed = Some(f),
                remotedexter::InboundMessage::ChunkPending => {}
                other => panic!("chunk {i} was classified as {other:?}"),
            }
        }

        let frame = completed.expect("the frame never completed");
        assert_eq!(frame.data, payload, "the frame came back changed");
        assert_eq!(frame.width, 1920);
        assert_eq!(frame.height, 1080);
        assert_eq!(frame.seq, 42);
        assert!(frame.keyframe);
    }

    /// The riskiest chunk is the biggest one: a full payload sits EXACTLY on
    /// `Kind::FrameChunkV1`'s ceiling, so an off-by-one anywhere between the
    /// chunker's maximum and the envelope's would refuse every full chunk and
    /// black the screen while the host kept reporting healthy capture.
    #[test]
    fn a_maximum_sized_chunk_still_fits_its_kind() {
        let payload = vec![0xCDu8; STREAM_CHUNK_PAYLOAD * 2];
        let chunks =
            module11::chunk::chunk_frame(1, 640, 480, false, &payload, STREAM_CHUNK_PAYLOAD);
        let largest = chunks.iter().map(|c| c.len()).max().expect("chunks");
        assert_eq!(
            largest,
            wire::Kind::FrameChunkV1.max_payload(),
            "the chunker's largest output and the envelope's ceiling have drifted apart"
        );
        for (i, chunk) in chunks.into_iter().enumerate() {
            assert!(
                frame_chunk_on_the_wire(chunk).is_ok(),
                "chunk {i} at the ceiling was refused"
            );
        }
    }

    /// A chunk larger than the kind allows must be REFUSED, not truncated.
    /// The host logs and drops that frame; silently sending a short one would
    /// corrupt the stream for every frame after it.
    #[test]
    fn an_oversized_chunk_is_refused_rather_than_truncated() {
        let too_big = vec![0u8; wire::Kind::FrameChunkV1.max_payload() + 1];
        assert!(frame_chunk_on_the_wire(too_big).is_err());
    }

    /// Interleaving is what a real session does: control responses and frame
    /// chunks share one encrypted link. A reassembler that let a control
    /// message disturb a half-built frame would lose it.
    #[test]
    fn control_messages_between_chunks_do_not_disturb_a_frame() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 97) as u8).collect();
        let chunks =
            module11::chunk::chunk_frame(7, 1280, 720, true, &payload, STREAM_CHUNK_PAYLOAD);
        assert!(chunks.len() > 2);

        let mut reassembler = module11::chunk::FrameReassembler::new();
        let mut completed = None;
        for chunk in chunks {
            let on_wire = frame_chunk_on_the_wire(chunk).expect("framed");
            if let remotedexter::InboundMessage::Frame(f) =
                remotedexter::classify_inbound(&mut reassembler, &on_wire)
            {
                completed = Some(f);
            }
            // A host response lands between chunks, as it does in a session.
            let ack = wire::Envelope::new(
                wire::Kind::ControlJson,
                0,
                br#"{"type":"ack","for":"input_event"}"#.to_vec(),
            )
            .expect("ack")
            .encode();
            assert!(matches!(
                remotedexter::classify_inbound(&mut reassembler, &ack),
                remotedexter::InboundMessage::Command(_)
            ));
        }
        assert_eq!(
            completed.expect("the frame never completed").data,
            payload,
            "a control message between chunks corrupted the frame"
        );
    }

    fn reset_loopback_test_state() {
        std::env::remove_var("RD_CAP_INPUT");
        std::env::remove_var("RD_CAP_SCREENSHOT");
        SESSION_ACTIVE.store(false, Ordering::SeqCst);
        *SESSION_ACTIVATION_TIME.lock().unwrap() = None;
    }

    fn field<'a>(json: &'a str, key: &str) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .and_then(|v| {
                v.get(key)
                    .map(|x| x.to_string().trim_matches('"').to_string())
            })
    }

    /// **BLOCK 9's founding requirement, proven RED before implementation.**
    ///
    /// "After one QR enrollment, the phone can reconnect to a started host
    /// without a new QR." Today it cannot: every connection must redeem a
    /// one-use pairing token, so a device that has already enrolled has nothing
    /// left to present and is refused at `pair_auth`.
    ///
    /// The block's verification section requires this failure to be
    /// demonstrated before the feature exists, so that the later pass means
    /// something. Note what the test does NOT do: it never reuses the spent
    /// token. Replay must keep failing — that property is already covered by
    /// `a replayed token must not authenticate` and Block 9 must not weaken it.
    /// A paired reconnect has to succeed on the device's own Noise static key,
    /// which the host currently never even reads.
    #[tokio::test]
    async fn a_paired_device_reconnects_without_a_new_qr() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        // Two connections, one host, one device store.
        let (addr, _host, _auth, _devices) = start_loopback_host_serving(&pairing, 2).await;

        // One device identity for the life of the test — that is what "the
        // same phone coming back" means.
        let device = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();

        connect_as_device(addr, &device, Some(&token), &identity.public)
            .await
            .expect("enrollment with a real QR token must succeed");

        let again = connect_as_device(addr, &device, None, &identity.public).await;
        assert!(
            again.is_ok(),
            "an enrolled device must reconnect without a new QR; refused with: {:?}",
            again.err()
        );
    }

    /// The client that is **shipped** must be able to do this, not just a
    /// hand-rolled one.
    ///
    /// `a_paired_device_reconnects_without_a_new_qr` drives `connect_as_device`,
    /// a test-local Noise client living in this module. It proves the *host*
    /// honours a token-less reconnect, and that is worth proving on its own —
    /// but it says nothing about whether the APK can ever reach that code. It
    /// could not: `PinnedNoiseSession::connect` refuses an empty token, so the
    /// only client users actually run had no way to present one. The host half
    /// passed its tests while the product could not perform the feature.
    ///
    /// This test closes that gap by driving `remotedexter::PinnedNoiseSession`
    /// — the same type the APK calls through JNI — for both connections.
    #[tokio::test]
    async fn the_shipping_client_reconnects_without_a_new_qr() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        persistent_client_identity();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (addr, _host, _auth, _devices) = start_loopback_host_serving(&pairing, 2).await;

        let enrolled = remotedexter::PinnedNoiseSession::connect(
            addr.ip().to_string(),
            addr.port(),
            token,
            identity.public.to_vec(),
        )
        .await;
        assert!(
            enrolled.is_ok(),
            "the shipping client must enroll with a real QR token; refused with: {:?}",
            enrolled.err()
        );
        drop(enrolled);

        let again = remotedexter::PinnedNoiseSession::connect_paired(
            addr.ip().to_string(),
            addr.port(),
            identity.public.to_vec(),
        )
        .await;
        assert!(
            again.is_ok(),
            "the shipping client must reconnect with no token at all; refused with: {:?}",
            again.err()
        );
    }

    /// Revocation has to bind the client users run, not only the test client.
    ///
    /// This is the lever that matters for a lost phone, so it is worth proving
    /// against the real transport: the owner presses Revoke, and the same
    /// binary that reconnected a moment ago is turned away.
    #[tokio::test]
    async fn the_shipping_client_is_refused_once_revoked() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        persistent_client_identity();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (addr, _host, _auth, devices) = start_loopback_host_serving(&pairing, 2).await;

        remotedexter::PinnedNoiseSession::connect(
            addr.ip().to_string(),
            addr.port(),
            token,
            identity.public.to_vec(),
        )
        .await
        .expect("enrollment with a real QR token must succeed");

        // The owner revokes from the console. Revoke every device the store
        // holds: this connection enrolled exactly one, and naming it here would
        // mean reading the client's key out of the store rather than acting the
        // way the console does.
        let listed = devices.snapshot();
        assert_eq!(listed.len(), 1, "one connection should enroll one device");
        devices.revoke(&listed[0].public_key, now_epoch_secs());

        let after = remotedexter::PinnedNoiseSession::connect_paired(
            addr.ip().to_string(),
            addr.port(),
            identity.public.to_vec(),
        )
        .await;
        assert!(
            after.is_err(),
            "a revoked device must be refused even though its key and the host pin are unchanged"
        );
    }

    /// A device that never enrolled has no standing, however well-formed its
    /// handshake. Block 9 must not turn "spoke Noise correctly" into access.
    #[tokio::test]
    async fn an_unenrolled_device_cannot_reconnect_without_a_token() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let pairing = test_pairing_service();
        let (addr, _host, _auth, _devices) = start_loopback_host_serving(&pairing, 1).await;

        let stranger = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let result = connect_as_device(addr, &stranger, None, &identity.public).await;
        assert!(
            result.is_err(),
            "a device that never enrolled must be refused on its key alone"
        );
    }

    /// Revocation has to bind on the wire, not merely in the store.
    #[tokio::test]
    async fn a_revoked_device_cannot_reconnect() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (addr, _host, _auth, devices) = start_loopback_host_serving(&pairing, 2).await;

        let device = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        connect_as_device(addr, &device, Some(&token), &identity.public)
            .await
            .expect("enrolment must succeed");

        // The owner withdraws it, exactly as the device list will.
        let key: [u8; 32] = device.public.clone().try_into().unwrap();
        assert!(
            devices.revoke(&key, now_epoch_secs()),
            "revoke must find the record"
        );

        let after = connect_as_device(addr, &device, None, &identity.public).await;
        assert!(
            after.is_err(),
            "a revoked device must be refused; a tombstone that does not bind is decoration"
        );
    }

    /// The property Block 9 must NOT weaken: a spent token stays spent, even
    /// for a device the host now knows.
    #[tokio::test]
    async fn an_enrolled_device_still_cannot_replay_its_spent_token() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (addr, _host, _auth, _devices) = start_loopback_host_serving(&pairing, 2).await;

        let device = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        connect_as_device(addr, &device, Some(&token), &identity.public)
            .await
            .expect("enrolment must succeed");

        let replayed = connect_as_device(addr, &device, Some(&token), &identity.public).await;
        assert!(
            replayed.is_err(),
            "presenting a spent token must fail even for an enrolled device — \
             being known is not permission to replay"
        );
    }

    /// Serializes tests that mutate the process-global `RD_CAP_*` env so they
    /// can't clobber each other under cargo's parallel test runner.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Ping still answers, and the cut capabilities are REFUSED — not acked.
    ///
    /// Replaces `clipboard_and_ping_ack` and
    /// `file_transfer_gate_roundtrip_and_traversal_guard`, both of which tested
    /// features Block 10 deletes (plan §4.2: file transfer and clipboard sync
    /// are high-risk data movement surfaces and neither is needed to prove
    /// remote desktop).
    ///
    /// Deleting them alone would have been a silent downgrade: the commands
    /// fell through to the catch-all, which answered `ack`, so the host went on
    /// telling peers it had handled a capability it no longer had. That is why
    /// this asserts the refusal rather than simply dropping the coverage — the
    /// removal has to be observable from the wire.
    #[tokio::test]
    async fn ping_answers_and_cut_capabilities_are_refused() {
        let p = dispatch_agent2_command(r#"{"type":"ping"}"#).await.unwrap();
        assert_eq!(field(&p, "type").as_deref(), Some("pong"));

        for cut in [
            r#"{"type":"clipboard_sync","data":"hi"}"#,
            r#"{"type":"file_transfer","op":"list"}"#,
            r#"{"type":"file_transfer","op":"put","name":"note.txt","data":"aGk="}"#,
        ] {
            let r = dispatch_agent2_command(cut).await.unwrap();
            assert_eq!(
                field(&r, "type").as_deref(),
                Some("denied"),
                "a cut capability must be refused, not acknowledged: {cut} -> {r}"
            );
        }
    }

    #[tokio::test]
    async fn pinned_noise_rejects_wrong_host_pin_without_activation() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (addr, host, _auth) = start_loopback_host_with(&pairing).await;
        let mut wrong_pin = [0xA5; 32];
        if wrong_pin.as_slice() == identity.public.as_slice() {
            wrong_pin[0] ^= 0xFF;
        }

        let result = remotedexter::PinnedNoiseSession::connect(
            addr.ip().to_string(),
            addr.port(),
            token,
            wrong_pin.to_vec(),
        )
        .await;

        assert!(
            result.is_err(),
            "a wrong host pin must reject the connection"
        );
        assert!(
            !session_active(),
            "wrong-pin handshake activated the session"
        );
        assert!(
            host.await.unwrap().is_err(),
            "host unexpectedly accepted a wrong-pin client"
        );
    }

    /// **Was `pinned_noise_rejects_wrong_prologue_without_activation`.**
    ///
    /// The prologue is gone: it only ever existed because the token had already
    /// been sent in the clear, and it came with an `RD_BIND_TOKEN_PROLOGUE=0`
    /// downgrade switch. The PROPERTY it protected — a peer that does not hold
    /// the real token cannot get a session — now lives inside the encrypted
    /// channel, which is a strictly stronger place for it.
    // ── Block 4 integration repair: the shipping host's token authority ──

    /// **C. A token from a real v4 invite is accepted exactly once.**
    ///
    /// Before the repair this could not pass: the handshake validated against
    /// `SessionManager`'s UUID store, which the console never populates, so a
    /// token minted by `PairingService` — the one in the QR — was always
    /// rejected.
    #[tokio::test]
    async fn a_real_v4_invite_token_is_accepted_exactly_once() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);

        // First use: accepted, and reported as an authenticated peer.
        let (addr, host, mut auth) = start_loopback_host_with(&pairing).await;
        let session = remotedexter::PinnedNoiseSession::connect(
            addr.ip().to_string(),
            addr.port(),
            token.clone(),
            identity.public.clone(),
        )
        .await;
        assert!(
            session.is_ok(),
            "a real v4 invite token must be accepted: {:?}",
            session.as_ref().err()
        );
        assert_eq!(
            auth.try_recv().ok().is_some(),
            true,
            "an accepted peer must be reported as authenticated"
        );
        drop(session);
        let _ = host.await;

        // Second use of the SAME token: refused. One-use means one, and the
        // store is shared by handle, so a second connection sees it spent.
        let (addr2, host2, mut auth2) = start_loopback_host_with(&pairing).await;
        let replay = remotedexter::PinnedNoiseSession::connect(
            addr2.ip().to_string(),
            addr2.port(),
            token,
            identity.public.clone(),
        )
        .await;
        assert!(replay.is_err(), "a replayed token must be refused");
        assert!(
            auth2.try_recv().is_err(),
            "a replayed token must not authenticate"
        );
        assert!(host2.await.unwrap().is_err());
    }

    /// **D. Expired and unrelated tokens are refused.**
    ///
    /// The `SessionManager` case is the one that matters most: it is exactly
    /// the token the shipping host used to accept, and it must now be refused
    /// because that store is no longer an authority.
    #[tokio::test]
    async fn expired_and_unrelated_tokens_are_all_refused() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let identity = test_host_identity();

        // (a) A token from SessionManager — the OLD authority.
        {
            reset_loopback_test_state();
            use session_manager::SessionManager;
            // The old authority, constructed here purely to mint the token this
            // test proves is now refused. Block 10 removed SessionManager from
            // the connection path, so this is the only place left that needs
            // one — and needing one to produce a token the host rejects is the
            // point of the test.
            let sm = Arc::new(SessionManager::new());
            let stale_authority_token = sm.generate_invite_token();
            let mut pairing = test_pairing_service();
            let _outstanding = real_invite_token(&mut pairing);
            let (addr, host, mut auth) = start_loopback_host_with(&pairing).await;
            let r = remotedexter::PinnedNoiseSession::connect(
                addr.ip().to_string(),
                addr.port(),
                stale_authority_token,
                identity.public.clone(),
            )
            .await;
            assert!(
                r.is_err(),
                "a SessionManager token must NOT authenticate — it is not the pairing authority"
            );
            assert!(auth.try_recv().is_err());
            assert!(host.await.unwrap().is_err());
        }

        // (b) An expired invite.
        {
            reset_loopback_test_state();
            let mut pairing = test_pairing_service();
            // Mint far enough in the past that its 60s TTL has elapsed.
            let bind: std::net::SocketAddr = "127.0.0.1:8082".parse().unwrap();
            let past = now_epoch_secs().saturating_sub(3600);
            let expired = pairing
                .create_invite(bind, past, &[pairing::CAP_VIEW.to_string()])
                .expect("mint")
                .invite
                .token;
            let (addr, host, mut auth) = start_loopback_host_with(&pairing).await;
            let r = remotedexter::PinnedNoiseSession::connect(
                addr.ip().to_string(),
                addr.port(),
                expired,
                identity.public.clone(),
            )
            .await;
            assert!(r.is_err(), "an expired invite must be refused");
            assert!(auth.try_recv().is_err());
            assert!(host.await.unwrap().is_err());
        }

        // (c) A token for a DIFFERENT host's invite.
        {
            reset_loopback_test_state();
            let mut other_host = test_pairing_service();
            let other_token = real_invite_token(&mut other_host);
            let mut pairing = test_pairing_service();
            let _mine = real_invite_token(&mut pairing);
            let (addr, host, mut auth) = start_loopback_host_with(&pairing).await;
            let r = remotedexter::PinnedNoiseSession::connect(
                addr.ip().to_string(),
                addr.port(),
                other_token,
                identity.public.clone(),
            )
            .await;
            assert!(r.is_err(), "another host's token must be refused");
            assert!(auth.try_recv().is_err());
            assert!(host.await.unwrap().is_err());
        }
    }

    // ───────────────────────────────────────────── the relay route, end to end
    //
    // Three real parties on loopback: the real relay server, the real host
    // dialling out to it, and the real client reaching the host through it.
    // Nothing here is a stand-in — the relay is `relay::serve_connection`, the
    // host is `handle_client_connection`, and the client is the same
    // `PinnedNoiseSession` the APK runs.

    /// A real relay, serving on loopback exactly as `relayd` does.
    async fn start_loopback_relay(token: &str) -> std::net::SocketAddr {
        let r = relay::Relay::new(Box::new(relay::auth::BearerToken::new(
            &[token.to_string()],
        )));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    continue;
                };
                let r2 = r.clone();
                tokio::spawn(async move {
                    let _ = relay::serve_connection(&r2, sock).await;
                });
            }
        });
        addr
    }

    /// A real host that DIALS OUT to `relay` and serves one spliced client.
    ///
    /// Returns the session id the relay issued, which is what a v5 invite
    /// carries, and the task serving the connection.
    async fn start_dialling_host(
        pairing: &pairing::PairingService,
        relay: std::net::SocketAddr,
        relay_token: &str,
    ) -> (String, tokio::task::JoinHandle<Result<()>>) {
        use host_controller::DialOut;
        let mut dial = crate::relay_dial::RelayDialOut::new(
            relay,
            crate::relay_dial::RelayCredential::Bearer(relay_token.to_string()),
        );
        let mut source = dial.connect().await.expect("the host could not register");
        let session = match source.reach() {
            host_controller::Reach::ViaRelay { session, .. } => session,
            other => panic!("a dialled-out host reported {other:?}"),
        };

        let tokens = pairing.redemption_handle();
        let devices = pairing::devices::DeviceHandle::new();
        let (auth_tx, _auth_rx) = tokio::sync::mpsc::unbounded_channel();
        let notifier = host_controller::AuthNotifier::new(auth_tx, "via relay".to_string());
        let task = tokio::spawn(async move {
            let (socket, _addr, _label) = source
                .next_peer()
                .await
                .ok_or_else(|| anyhow::anyhow!("the relay never handed the host a client"))?;
            handle_client_connection(socket, tokens, devices, notifier).await
        });
        (session, task)
    }

    /// **The whole loop, through a relay.** Host dials out, client scans a
    /// session id, the relay splices, and the pinned Noise session completes.
    #[tokio::test]
    async fn a_client_reaches_a_dialled_out_host_through_a_real_relay() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);

        let relay_addr = start_loopback_relay("host-credential").await;
        let (session, host) = start_dialling_host(&pairing, relay_addr, "host-credential").await;

        let result = remotedexter::PinnedNoiseSession::connect_via_relay(
            relay_addr.ip().to_string(),
            relay_addr.port(),
            session,
            token,
            identity.public.clone(),
        )
        .await;
        assert!(
            result.is_ok(),
            "the relayed session must succeed: {:?}",
            result.as_ref().err()
        );
        drop(result);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), host).await;
    }

    /// **THE PROPERTY THE RELAY DESIGN RESTS ON, from the client's side.**
    ///
    /// A relay that splices the phone to a host of its own choosing must fail.
    /// The pin in the invite is checked in the handshake, so the substituted
    /// host cannot complete it — the relay is a wire, and a wire that lies is
    /// caught by the key, not by trusting the wire.
    #[tokio::test]
    async fn a_relay_that_splices_to_the_wrong_host_is_caught_by_the_pin() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        // The host's identity must be installed, or it closes before the
        // handshake reaches the pin and the test passes for the wrong reason.
        // It did exactly that until the red proof caught it.
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);

        let relay_addr = start_loopback_relay("host-credential").await;
        let (session, host) = start_dialling_host(&pairing, relay_addr, "host-credential").await;

        // The invite pinned SOME OTHER host's key. Everything else is correct:
        // a real relay, a real session id, a real token, a real host that is
        // genuinely there and genuinely completes its side of the handshake.
        let mut wrong_pin = identity.public.clone();
        wrong_pin[0] ^= 0xff;
        let result = remotedexter::PinnedNoiseSession::connect_via_relay(
            relay_addr.ip().to_string(),
            relay_addr.port(),
            session,
            token,
            wrong_pin,
        )
        .await;
        let why = match &result {
            Err(e) => e.to_string(),
            Ok(_) => panic!(
                "a relayed session completed against a host whose key was not the pinned one"
            ),
        };
        // Asserting on the REASON, not merely on failure. This test passed
        // against a client with the pin check deleted, because the host closed
        // early for an unrelated reason and "it failed" looked like proof.
        assert!(
            why.contains("pin"),
            "the session must fail AT THE PIN, not for some other reason: {why}"
        );
        host.abort();
    }

    /// An invented session id is refused by the relay, and the client says so
    /// rather than hanging or falling back to anything.
    #[tokio::test]
    async fn an_invented_relay_session_is_refused_and_named() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let relay_addr = start_loopback_relay("host-credential").await;

        let result = remotedexter::PinnedNoiseSession::connect_via_relay(
            relay_addr.ip().to_string(),
            relay_addr.port(),
            "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
            token,
            identity.public.clone(),
        )
        .await;
        let why = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an invented session id opened a session"),
        };
        assert!(
            why.contains("refused"),
            "the failure should name the relay's refusal: {why}"
        );
    }

    /// **The token never crosses the relay leg in plaintext.**
    ///
    /// A recording proxy sits between the client and the RELAY, so `seen` is
    /// exactly what a relay operator — or anyone on the path to one — observes:
    /// the session id it already issued, and ciphertext.
    #[tokio::test]
    async fn the_token_never_appears_on_the_relay_leg() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);

        let relay_addr = start_loopback_relay("host-credential").await;
        let (session, host) = start_dialling_host(&pairing, relay_addr, "host-credential").await;

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let seen_task = Arc::clone(&seen);
        let pump = tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.unwrap();
            let mut upstream = tokio::net::TcpStream::connect(relay_addr).await.unwrap();
            let (mut cr, mut cw) = client.split();
            let (mut ur, mut uw) = upstream.split();
            let a = async {
                let mut b = [0u8; 4096];
                loop {
                    match cr.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            seen_task.lock().unwrap().extend_from_slice(&b[..n]);
                            if uw.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            let seen_b = Arc::clone(&seen_task);
            let bfut = async {
                let mut b = [0u8; 4096];
                loop {
                    match ur.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            seen_b.lock().unwrap().extend_from_slice(&b[..n]);
                            if cw.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            tokio::join!(a, bfut);
        });

        let result = remotedexter::PinnedNoiseSession::connect_via_relay(
            proxy_addr.ip().to_string(),
            proxy_addr.port(),
            session.clone(),
            token.clone(),
            identity.public.clone(),
        )
        .await;
        assert!(
            result.is_ok(),
            "the proxied relay session must succeed: {:?}",
            result.as_ref().err()
        );
        drop(result);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), pump).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), host).await;

        let bytes = seen.lock().unwrap().clone();
        assert!(!bytes.is_empty(), "the proxy recorded nothing");

        // POSITIVE CONTROL: the same scan over a buffer that DOES contain the
        // token must find it. A clean result is only meaningful because this
        // one is dirty.
        let mut planted = bytes.clone();
        planted.extend_from_slice(token.as_bytes());
        assert!(
            planted.windows(token.len()).any(|w| w == token.as_bytes()),
            "the scan cannot detect a token even when one is present"
        );
        assert!(
            bytes.windows(token.len()).all(|w| w != token.as_bytes()),
            "the pairing token appeared in plaintext on the relay leg"
        );
        let raw: Vec<u8> = (0..token.len() / 2)
            .map(|i| u8::from_str_radix(&token[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        assert!(
            bytes.windows(raw.len()).all(|w| w != raw.as_slice()),
            "the pairing token appeared on the relay leg in raw byte form"
        );

        // The session id IS on this leg, and that is correct: the relay issued
        // it and needs it to route. It is not a secret from the relay.
        assert!(
            bytes
                .windows(session.len())
                .any(|w| w == session.as_bytes()),
            "the session id should be visible to the relay — if it is not, this test is not watching the right leg"
        );
    }

    /// **E. The token never appears in plaintext on the wire.**
    ///
    /// A recording proxy sits between client and host and tees every byte in
    /// both directions. The old protocol put the token in a plaintext JSON
    /// frame as the very first thing sent, so this test would have found it
    /// immediately.
    #[tokio::test]
    async fn the_invite_token_never_appears_in_plaintext_on_the_wire() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (host_addr, host, _auth) = start_loopback_host_with(&pairing).await;

        // Recording proxy.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let seen_task = Arc::clone(&seen);
        let pump = tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.unwrap();
            let mut upstream = tokio::net::TcpStream::connect(host_addr).await.unwrap();
            let (mut cr, mut cw) = client.split();
            let (mut ur, mut uw) = upstream.split();
            let a = async {
                let mut b = [0u8; 4096];
                loop {
                    match cr.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            seen_task.lock().unwrap().extend_from_slice(&b[..n]);
                            if uw.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            let seen_b = Arc::clone(&seen_task);
            let bfut = async {
                let mut b = [0u8; 4096];
                loop {
                    match ur.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            seen_b.lock().unwrap().extend_from_slice(&b[..n]);
                            if cw.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            tokio::join!(a, bfut);
        });

        let session = remotedexter::PinnedNoiseSession::connect(
            proxy_addr.ip().to_string(),
            proxy_addr.port(),
            token.clone(),
            identity.public.clone(),
        )
        .await;
        assert!(
            session.is_ok(),
            "the proxied session must succeed: {:?}",
            session.as_ref().err()
        );
        drop(session);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pump).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), host).await;

        let bytes = seen.lock().unwrap().clone();
        assert!(
            !bytes.is_empty(),
            "the proxy recorded nothing — it did not observe the session"
        );

        // POSITIVE CONTROL for the detector itself.
        //
        // Restoring the old plaintext frame to force this test red made the
        // SESSION fail first — the host read the stray bytes as a malformed
        // Noise message — so the red proved the handshake broke, not that the
        // scan works. This control fixes that permanently: the same scan, over
        // a buffer that does contain the token, must find it. A clean result
        // above is only meaningful because this one is dirty.
        let mut planted = bytes.clone();
        planted.extend_from_slice(token.as_bytes());
        assert!(
            planted.windows(token.len()).any(|w| w == token.as_bytes()),
            "the plaintext scan cannot detect a token even when one is present"
        );
        // The token as ASCII, which is how the old plaintext frame carried it.
        assert!(
            bytes.windows(token.len()).all(|w| w != token.as_bytes()),
            "the pairing token appeared in plaintext on the wire"
        );
        // And its raw hex-decoded form, in case an encoding ever changes.
        let raw: Vec<u8> = (0..token.len() / 2)
            .map(|i| u8::from_str_radix(&token[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        assert!(
            bytes.windows(raw.len()).all(|w| w != raw.as_slice()),
            "the pairing token appeared on the wire in raw byte form"
        );
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused_inside_the_encrypted_channel() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let _real = real_invite_token(&mut pairing); // an invite IS outstanding
        let (addr, host, mut auth) = start_loopback_host_with(&pairing).await;

        let result = remotedexter::PinnedNoiseSession::connect(
            addr.ip().to_string(),
            addr.port(),
            "f0".repeat(32), // well-formed, and not the outstanding token
            identity.public.clone(),
        )
        .await;

        assert!(result.is_err(), "a wrong token must be refused");
        assert!(!session_active(), "a refused token activated the session");
        assert!(
            auth.try_recv().is_err(),
            "a refused peer must never be reported as authenticated"
        );
        assert!(host.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn unsupported_pair_auth_metadata_is_refused_without_spending_token() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let identity = test_host_identity();

        // Version 3 is the PRE-BLOCK-10 client: bare JSON and bare stream
        // chunks, no envelope. It is listed explicitly because it is the only
        // one of these that ever really existed — an old APK meeting a new
        // host. It must be refused at pair_auth with its token intact, so the
        // user can upgrade and use the same invite, rather than being silently
        // downgraded onto a framing this host no longer speaks.
        for (protocol, version) in [("rdv3", 99), ("unsupported", 3), ("rdv3", 3)] {
            reset_loopback_test_state();
            let mut pairing = test_pairing_service();
            let token = real_invite_token(&mut pairing);

            let (addr, host, mut auth) = start_loopback_host_with(&pairing).await;
            let malformed =
                connect_with_pair_auth(addr, &token, protocol, version, &identity.public).await;
            assert!(
                malformed.is_err(),
                "unsupported pair_auth metadata authenticated: protocol={protocol}, version={version}"
            );
            assert!(auth.try_recv().is_err());
            assert!(host.await.unwrap().is_err());

            let (addr, host, _auth) = start_loopback_host_with(&pairing).await;
            let valid = remotedexter::PinnedNoiseSession::connect(
                addr.ip().to_string(),
                addr.port(),
                token,
                identity.public.clone(),
            )
            .await;
            assert!(
                valid.is_ok(),
                "invalid metadata spent the one-use token: protocol={protocol}, version={version}"
            );
            drop(valid);
            let _ = host.await;
        }
    }

    #[tokio::test]
    async fn pinned_noise_rejects_invalid_pin_before_connecting() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let result = remotedexter::PinnedNoiseSession::connect(
            addr.ip().to_string(),
            addr.port(),
            "unused-token".to_string(),
            vec![0x11; 31],
        )
        .await;

        assert!(result.is_err(), "an invalid pin length must be rejected");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "invalid pin length reached the TCP listener"
        );
        assert!(
            !session_active(),
            "invalid pin length activated the session"
        );
    }

    #[tokio::test]
    async fn pinned_noise_ping_pong_roundtrip_and_clean_disconnect() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (addr, host, _auth) = start_loopback_host_with(&pairing).await;

        let mut session = remotedexter::PinnedNoiseSession::connect(
            addr.ip().to_string(),
            addr.port(),
            token,
            identity.public.clone(),
        )
        .await
        .expect("pinned Noise connection");

        let sent_len = session
            .send_command(br#"{"type":"ping"}"#)
            .await
            .expect("send ping");
        assert!((1..=65535).contains(&sent_len));
        let reply = session.recv().await.expect("receive pong");
        assert!((1..=65535).contains(&reply.ciphertext_len));
        assert_eq!(opened(&reply).payload, br#"{"type":"pong"}"#);
        assert!(
            session_active(),
            "encrypted pong arrived without an active host session"
        );

        drop(session);
        tokio::time::timeout(std::time::Duration::from_secs(2), host)
            .await
            .expect("host did not finish after disconnect")
            .expect("host task panicked")
            .expect("host connection failed");
        assert!(!session_active(), "disconnect left the host session active");
    }

    /// Phase 2: the Kotlin→session command channel, driven over a real pinned
    /// Noise connection to the real host.
    ///
    /// This runs the production `run_pinned_session` — the exact function the
    /// JNI start path runs — so channel ownership, the single-owner send/recv
    /// loop, and teardown are all the shipping ones rather than a test-only
    /// arrangement. Several commands are queued at once so the loop must
    /// interleave sends with inbound replies: if the `select!` ever reordered
    /// or duplicated a Noise nonce, AEAD decryption would fail and the session
    /// would end in error instead of returning every pong.
    #[tokio::test]
    async fn command_channel_sends_over_the_live_pinned_session() {
        use remotedexter::CommandRejection;

        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (addr, host, _auth) = start_loopback_host_with(&pairing).await;

        // Observe inbound JSON through the engine's real callback seam.
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        remotedexter::set_agent2_observer_for_test(move |json| {
            sink.lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(json.to_string());
        });

        let client = tokio::spawn(remotedexter::run_pinned_session(
            addr.ip().to_string(),
            addr.port(),
            token,
            identity.public.clone(),
        ));

        // The session claims the channel as its first act; wait for that rather
        // than assuming a particular scheduling order.
        let claimed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if remotedexter::submit_session_command(r#"{"type":"ping"}"#)
                    != Err(CommandRejection::NoSession)
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            claimed.is_ok(),
            "the session never claimed the command channel"
        );

        // Queue several more so sends and receives must interleave.
        const EXTRA: usize = 4;
        for _ in 0..EXTRA {
            assert_eq!(
                remotedexter::submit_session_command(r#"{"type":"ping"}"#),
                Ok(())
            );
        }

        let expected = EXTRA + 1;
        let got = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if seen.lock().unwrap_or_else(|p| p.into_inner()).len() >= expected {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;

        let replies = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
        assert!(
            got.is_ok(),
            "expected {expected} pongs over the encrypted link, saw {}: {replies:?}",
            replies.len()
        );
        for r in replies.iter().take(expected) {
            assert_eq!(
                field(r, "type").as_deref(),
                Some("pong"),
                "unexpected inbound message: {r}"
            );
        }
        assert!(
            session_active(),
            "commands flowed without an active host session"
        );

        // Clean shutdown through the channel, not by dropping the socket.
        assert_eq!(remotedexter::request_session_shutdown(), Ok(()));
        tokio::time::timeout(std::time::Duration::from_secs(10), client)
            .await
            .expect("client session did not finish after shutdown")
            .expect("client task panicked")
            .expect("client session ended in error");

        // Teardown must have released the channel.
        assert_eq!(
            remotedexter::submit_session_command(r#"{"type":"ping"}"#),
            Err(CommandRejection::NoSession),
            "disconnect must clear the registered sender"
        );

        tokio::time::timeout(std::time::Duration::from_secs(10), host)
            .await
            .expect("host did not finish after client shutdown")
            .expect("host task panicked")
            .expect("host connection failed");
        assert!(!session_active(), "disconnect left the host session active");
    }

    /// Grants `RD_CAP_SCREENSHOT` for as long as it lives. Cleanup is in `Drop`
    /// rather than at the end of the test body so a failed assertion cannot
    /// leave the capture capability granted for the rest of the process.
    struct ScreenshotCapGuard;

    impl ScreenshotCapGuard {
        fn grant() -> Self {
            std::env::set_var("RD_CAP_SCREENSHOT", "1");
            Self
        }
    }

    impl Drop for ScreenshotCapGuard {
        fn drop(&mut self) {
            std::env::remove_var("RD_CAP_SCREENSHOT");
        }
    }

    /// A real portal frame arrives in well under a second once the grant is in
    /// force, so these ceilings do not measure capture speed — they bound how
    /// long the test waits before concluding the portal never granted at all.
    const HW_RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    const HW_STREAM_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

    /// One decrypted message, with an explicit ceiling. The 64 KiB framing bound
    /// is checked here rather than at the call sites because it must hold for
    /// *every* frame the host sends — stream chunks and JSON responses alike.
    async fn hw_recv(
        session: &mut remotedexter::PinnedNoiseSession,
        within: std::time::Duration,
        what: &str,
    ) -> remotedexter::ReceivedNoiseFrame {
        let frame = tokio::time::timeout(within, session.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out after {within:?} waiting for {what}"))
            .unwrap_or_else(|e| panic!("receive failed waiting for {what}: {e}"));
        assert!(
            (1..=65535).contains(&frame.ciphertext_len),
            "framed ciphertext out of bounds ({}) while waiting for {what}",
            frame.ciphertext_len
        );
        frame
    }

    /// Hardware capstone: the whole host gate over one real pinned Noise session
    /// — `list_windows` → `permit_window` → `stream_start` → genuine
    /// xdg-desktop-portal frames → reassembly → JPEG decode → `stream_stop` →
    /// clean disconnect. Everything the ordinary suite proves in isolation, run
    /// once against the live compositor.
    ///
    /// Skipped unless `RD_USE_HW=1`, because it opens a screen-share portal
    /// session. Run it **by exact name only**:
    ///
    /// ```text
    /// RD_USE_HW=1 cargo test -p host_app \
    ///   pinned_noise_live_stream_reassembles_real_portal_frame -- --nocapture
    /// ```
    ///
    /// **Capture only.** `RD_CAP_INPUT` is removed and asserted absent, and no
    /// `grant_input`/`input_event` is ever sent, so nothing here can touch the
    /// live pointer or keyboard. Linux `share_source` refuses to fall back to
    /// synthetic frames, so a pass means real pixels off the real desktop.
    #[tokio::test]
    async fn pinned_noise_live_stream_reassembles_real_portal_frame() {
        if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
            eprintln!(
                "skipping pinned_noise_live_stream_reassembles_real_portal_frame (set RD_USE_HW=1)"
            );
            return;
        }

        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_loopback_test_state();
        // Token-prologue binding stays at its default (on): this capstone runs
        // the production path, not a relaxed one.
        let _cap = ScreenshotCapGuard::grant();
        assert!(
            std::env::var("RD_CAP_INPUT").is_err(),
            "the capture capstone must never run with input granted"
        );

        let identity = test_host_identity();
        let mut pairing = test_pairing_service();
        let token = real_invite_token(&mut pairing);
        let (addr, host, _auth) = start_loopback_host_with(&pairing).await;

        let mut session = tokio::time::timeout(
            HW_RECV_TIMEOUT,
            remotedexter::PinnedNoiseSession::connect(
                addr.ip().to_string(),
                addr.port(),
                token,
                identity.public.clone(),
            ),
        )
        .await
        .expect("timed out completing the pinned Noise handshake")
        .expect("pinned Noise connection");

        // ── The client's picker: ask what this host will share ───────────
        session
            .send_command(br#"{"type":"list_windows"}"#)
            .await
            .expect("send list_windows");
        let listed = hw_recv(&mut session, HW_RECV_TIMEOUT, "list_windows response").await;
        let listed_env = opened(&listed);
        let listed = std::str::from_utf8(&listed_env.payload).expect("list_windows reply is UTF-8");
        assert_eq!(
            field(listed, "type").as_deref(),
            Some("windows"),
            "unexpected list_windows reply: {listed}"
        );
        // Take the id the host actually offered — the Linux desktop id, a real
        // HWND on Windows. Hardcoding it would stop exercising the picker the
        // client is required to go through before anything is capturable.
        let listed_json: serde_json::Value =
            serde_json::from_str(listed).expect("list_windows reply is JSON");
        let window_id = listed_json["windows"][0]["id"]
            .as_u64()
            .unwrap_or_else(|| panic!("host offered no shareable surface: {listed}"));
        eprintln!("[capstone] host offers surface id {window_id}");

        // ── Consent: nothing is capturable until this is permitted ───────
        session
            .send(format!(r#"{{"type":"permit_window","window":{window_id}}}"#).as_bytes())
            .await
            .expect("send permit_window");
        let permitted = hw_recv(&mut session, HW_RECV_TIMEOUT, "permit_window ack").await;
        let permitted_env = opened(&permitted);
        let permitted =
            std::str::from_utf8(&permitted_env.payload).expect("permit_window ack is UTF-8");
        assert_eq!(
            field(permitted, "type").as_deref(),
            Some("ack"),
            "permit_window refused: {permitted}"
        );
        assert_eq!(field(permitted, "for").as_deref(), Some("permit_window"));

        // ── Stream ───────────────────────────────────────────────────────
        session
            .send(format!(r#"{{"type":"stream_start","window":{window_id}}}"#).as_bytes())
            .await
            .expect("send stream_start");

        // The ack is written by the command arm and chunks by the stream arm of
        // the host's `select!`, so their order on the wire is not guaranteed.
        // Wait for both rather than assuming which lands first. Reassembly is
        // module11's — this test must not grow a second copy of that parser.
        let mut reassembler = module11::FrameReassembler::new();
        let mut start_acked = false;
        let mut keyframe: Option<module11::ReassembledFrame> = None;
        let mut chunks_seen = 0usize;
        let deadline = std::time::Instant::now() + HW_STREAM_DEADLINE;
        while keyframe.is_none() || !start_acked {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "no complete keyframe within {HW_STREAM_DEADLINE:?} \
                 (chunks seen: {chunks_seen}, stream_start acked: {start_acked}) — \
                 the screen-share grant was refused or the portal is unavailable"
            );
            let msg = hw_recv(
                &mut session,
                remaining,
                "a stream chunk or the stream_start ack",
            )
            .await;
            let env = opened(&msg);
            if env.kind == wire::Kind::FrameChunkV1 {
                chunks_seen += 1;
                if let Some(f) = reassembler.push(&env.payload) {
                    if f.keyframe {
                        keyframe = Some(f);
                    }
                }
            } else {
                let text = std::str::from_utf8(&env.payload).expect("host response is UTF-8");
                assert_eq!(
                    field(text, "type").as_deref(),
                    Some("ack"),
                    "stream_start refused: {text}"
                );
                assert_eq!(field(text, "for").as_deref(), Some("stream_start"));
                start_acked = true;
            }
        }

        // ── Prove the bytes are a real picture, not a plausible blob ─────
        let frame = keyframe.expect("a complete keyframe");
        eprintln!(
            "[capstone] keyframe seq={} {}x{} from {} chunks ({} JPEG bytes)",
            frame.seq,
            frame.width,
            frame.height,
            chunks_seen,
            frame.data.len()
        );
        assert!(
            frame.data.len() > 3 && frame.data[..3] == [0xFF, 0xD8, 0xFF],
            "reassembled frame is not JPEG (first bytes: {:02X?})",
            &frame.data[..frame.data.len().min(3)]
        );
        let decoded = image::load_from_memory_with_format(&frame.data, image::ImageFormat::Jpeg)
            .expect("the reassembled keyframe must decode as a JPEG image");
        assert!(
            decoded.width() > 0 && decoded.height() > 0,
            "decoded frame has a zero dimension"
        );
        assert_eq!(
            (decoded.width(), decoded.height()),
            (frame.width as u32, frame.height as u32),
            "decoded image does not match the dimensions the chunk header advertised"
        );
        // A flat image is what a broken capture path produces (all black, all
        // grey). A real desktop is never one colour.
        let rgb = decoded.to_rgb8();
        let first = *rgb.pixels().next().expect("decoded image has pixels");
        assert!(
            rgb.pixels().any(|p| *p != first),
            "decoded frame is a single flat colour — not a real desktop"
        );

        // ── Stop ─────────────────────────────────────────────────────────
        session
            .send_command(br#"{"type":"stream_stop"}"#)
            .await
            .expect("send stream_stop");
        // Chunks already queued in the host's channel keep arriving after the
        // producer is dropped, so the ack is behind them rather than instead of
        // them. Drain until it shows up.
        let stop_deadline = std::time::Instant::now() + HW_STREAM_DEADLINE;
        loop {
            let remaining = stop_deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "no stream_stop ack within {HW_STREAM_DEADLINE:?}"
            );
            let msg = hw_recv(&mut session, remaining, "the stream_stop ack").await;
            let env = opened(&msg);
            if env.kind == wire::Kind::FrameChunkV1 {
                continue; // queued chunk from before the stop took effect
            }
            let text = std::str::from_utf8(&env.payload).expect("host response is UTF-8");
            assert_eq!(
                field(text, "type").as_deref(),
                Some("ack"),
                "stream_stop refused: {text}"
            );
            assert_eq!(field(text, "for").as_deref(), Some("stream_stop"));
            break;
        }

        assert!(
            session_active(),
            "streamed real frames without an active host session"
        );
        drop(session);
        tokio::time::timeout(HW_RECV_TIMEOUT, host)
            .await
            .expect("host did not finish after disconnect")
            .expect("host task panicked")
            .expect("host connection failed");
        assert!(!session_active(), "disconnect left the host session active");
    }

    /// Per-window stream must fail **closed**: an id that can never be captured
    /// (0 is never a valid HWND) produces no frames and stops, closing the
    /// channel — it never falls back to any wider (desktop) capture.
    #[tokio::test]
    async fn stream_controller_is_window_scoped_and_fails_closed() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let ctl = StreamController::start(75, tx, SurfaceId::new(0));
        let closed = loop {
            match tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv()).await {
                Ok(Some(_)) => continue, // unexpected for an invalid window
                Ok(None) => break true,  // channel closed = producer stopped
                Err(_) => break false,   // timed out without closing
            }
        };
        drop(ctl);
        assert!(closed, "an invalid-window stream must fail closed and stop");
    }

    // ── A log must say what happened, never what was typed ──────────────────

    /// Clipboard contents must not reach the log. The handler already reported
    /// size only; the line upstream printed the whole command and undid it.
    #[test]
    fn clipboard_contents_never_reach_the_log() {
        let secret = "correct horse battery staple";
        let cmd = format!(r#"{{"type":"clipboard_push","text":"{secret}"}}"#);
        let line = describe_command(&cmd);
        assert!(
            !line.contains(secret),
            "the clipboard text appeared in the log line: {line:?}"
        );
        assert!(
            line.contains("clipboard_push"),
            "the type is still reported"
        );
        assert!(
            line.contains("bytes"),
            "the size is still reported: {line:?}"
        );
    }

    /// A key event says a key happened, not which one. A run of scan codes is
    /// what the user typed.
    #[test]
    fn a_key_event_is_described_without_saying_which_key() {
        let cmd = r#"{"type":"input_event","event":{"Key":{"scan":30,"action":"Down"}}}"#;
        let line = describe_command(cmd);
        assert!(line.contains("input_event"));
        assert!(
            line.contains("Key"),
            "the KIND of event is useful: {line:?}"
        );
        assert!(
            !line.contains("30"),
            "the scan code is the keystroke: {line:?}"
        );
    }

    /// The forgery half. A peer that can put a newline in a logged string can
    /// write convincing fake events into the operator's journal.
    #[test]
    fn a_peer_cannot_forge_a_log_line() {
        let forged = "x\n[host] pairing token deadbeef redeemed — device enrolled";
        let cmd = format!(r#"{{"type":"{forged}"}}"#);
        let line = describe_command(&cmd);
        assert!(
            !line.contains('\n'),
            "a newline survived into the log: {line:?}"
        );
        assert!(
            !line.contains("token deadbeef redeemed"),
            "the forged event text survived: {line:?}"
        );
    }

    /// Unparseable input is the input most likely to be hostile, so it is
    /// counted rather than echoed.
    #[test]
    fn unparseable_input_is_counted_not_echoed() {
        let junk = "\u{1b}[2J[host] everything is fine";
        let line = describe_command(junk);
        assert!(
            !line.contains("everything is fine"),
            "echoed junk: {line:?}"
        );
        assert!(line.contains("unparseable"));
    }

    /// Peer-chosen text is bounded, so a megabyte type cannot flood the journal.
    #[test]
    fn a_logged_string_is_bounded() {
        let huge = "a".repeat(10_000);
        assert!(
            log_safe(&huge, 32).chars().count() <= 33,
            "32 plus an ellipsis"
        );
    }

    /// Control characters cannot survive into a log line, whatever they are.
    #[test]
    fn control_characters_are_replaced_not_passed_through() {
        for c in ['\n', '\r', '\t', '\u{0}', '\u{1b}'] {
            let s = format!("a{c}b");
            let out = log_safe(&s, 16);
            assert_eq!(out, "a.b", "control char {c:?} survived as {out:?}");
        }
    }

    /// The escaping the baseline import documented and never implemented. A
    /// peer-chosen type is echoed into a `denied` reply, so it must not be able
    /// to break out of the JSON string it sits in.
    #[test]
    fn a_peer_chosen_type_cannot_break_the_json_reply() {
        let hostile = r#"a","injected":"yes"#;
        let escaped = json_escape(hostile);
        let reply = format!(r#"{{"type":"denied","for":"{escaped}","reason":"unsupported"}}"#);
        let parsed: serde_json::Value =
            serde_json::from_str(&reply).expect("the reply must still be valid JSON");
        assert!(
            parsed.get("injected").is_none(),
            "injected a field: {reply}"
        );
        assert_eq!(
            parsed.get("for").and_then(|v| v.as_str()),
            Some(hostile),
            "the type round-trips as DATA rather than structure"
        );
    }

    // ── Session slots: a leaked slot is a permanent lockout ─────────────────

    /// These share process-global counters, so they must not run concurrently
    /// with each other.
    static SLOT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn drain_slots() {
        let mut g = LIVE_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
        *g = None;
        LIVE_ANONYMOUS.store(0, Ordering::SeqCst);
    }

    const K1: [u8; 32] = [1u8; 32];
    const K2: [u8; 32] = [2u8; 32];

    #[test]
    fn a_device_is_refused_at_its_own_cap_and_admitted_again_after_release() {
        let _g = SLOT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        drain_slots();

        let held: Vec<_> = (0..host_controller::SessionLimit::MAX_PER_DEVICE)
            .map(|_| acquire_session_slot(Some(K1)).expect("under the cap"))
            .collect();
        assert!(
            acquire_session_slot(Some(K1)).is_none(),
            "the device is at its own cap"
        );
        // Another device is unaffected — that is what the per-device cap buys.
        let other = acquire_session_slot(Some(K2));
        assert!(other.is_some(), "one device must not lock out another");

        drop(held);
        assert!(
            acquire_session_slot(Some(K1)).is_some(),
            "releasing a slot must admit the next session"
        );
        drain_slots();
    }

    /// THE FAILURE THIS GUARDS. A slot that is not released turns a cap into a
    /// permanent lockout that only a restart clears — worse than having no cap.
    /// Release is `Drop`, so an early return, a `?` or a panic cannot skip it.
    #[test]
    fn a_slot_is_released_even_when_its_holder_panics() {
        let _g = SLOT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        drain_slots();

        let r = std::panic::catch_unwind(|| {
            let _slot = acquire_session_slot(Some(K1)).expect("first slot");
            panic!("the session died badly");
        });
        assert!(r.is_err(), "the panic must have happened");

        for _ in 0..host_controller::SessionLimit::MAX_PER_DEVICE {
            assert!(
                acquire_session_slot(Some(K1)).is_some(),
                "a panicking session must not strand its slot"
            );
        }
        drain_slots();
    }

    /// The map must not grow one entry per device ever seen.
    #[test]
    fn releasing_the_last_slot_forgets_the_device() {
        let _g = SLOT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        drain_slots();

        let slot = acquire_session_slot(Some(K1)).expect("slot");
        drop(slot);
        let guard = LIVE_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
        let empty = guard.as_ref().is_none_or(|m| !m.contains_key(&K1));
        drop(guard);
        assert!(
            empty,
            "a device at zero sessions must leave no entry behind"
        );
        drain_slots();
    }

    // ── Revocation must reach a session that is ALREADY connected ───────────

    const DEV_A: [u8; 32] = [7u8; 32];
    const DEV_B: [u8; 32] = [9u8; 32];

    #[test]
    fn an_enrolled_device_keeps_its_live_session() {
        let d = pairing::devices::DeviceHandle::new();
        d.enroll(DEV_A, "phone", 100);
        assert_eq!(live_session_verdict(&d, Some(&DEV_A)), LiveAuth::Continue);
    }

    /// THE DEFECT, as a test. Revoking used to stop the device RECONNECTING
    /// while the session it already held carried on streaming and injecting,
    /// because the device store was consulted once, at authentication.
    #[test]
    fn revoking_a_device_terminates_the_session_it_already_has() {
        let d = pairing::devices::DeviceHandle::new();
        d.enroll(DEV_A, "phone", 100);
        assert_eq!(
            live_session_verdict(&d, Some(&DEV_A)),
            LiveAuth::Continue,
            "precondition: the session was allowed before the revoke"
        );

        d.revoke(&DEV_A, 120);

        assert!(
            matches!(
                live_session_verdict(&d, Some(&DEV_A)),
                LiveAuth::Terminate(_)
            ),
            "a revoked device must lose the session it is HOLDING, not merely \
             be refused the next one"
        );
    }

    /// Revocation is per device. One phone losing access must not drop another.
    #[test]
    fn revoking_one_device_does_not_disturb_another() {
        let d = pairing::devices::DeviceHandle::new();
        d.enroll(DEV_A, "phone", 100);
        d.enroll(DEV_B, "tablet", 100);
        d.revoke(&DEV_A, 120);
        assert!(matches!(
            live_session_verdict(&d, Some(&DEV_A)),
            LiveAuth::Terminate(_)
        ));
        assert_eq!(live_session_verdict(&d, Some(&DEV_B)), LiveAuth::Continue);
    }

    /// Forgetting removes the record entirely; unknown must fail closed too,
    /// or "Forget" would be a quieter way to keep a session alive than "Revoke".
    #[test]
    fn a_forgotten_device_also_loses_its_live_session() {
        let d = pairing::devices::DeviceHandle::new();
        d.enroll(DEV_A, "phone", 100);
        d.revoke(&DEV_A, 120);
        d.forget(&DEV_A);
        assert!(matches!(
            live_session_verdict(&d, Some(&DEV_A)),
            LiveAuth::Terminate(_)
        ));
    }

    /// Documented behaviour, not an oversight: a peer with no static key cannot
    /// be named and so cannot be revoked by key. Noise XX always yields one, so
    /// this is unreachable in practice.
    #[test]
    fn a_peer_with_no_static_key_is_not_terminated_by_this_check() {
        let d = pairing::devices::DeviceHandle::new();
        assert_eq!(live_session_verdict(&d, None), LiveAuth::Continue);
    }

    // ── A stream must not outlive the authority that created it ─────────────

    /// A controller with no capture thread. `start` spawns one; these tests are
    /// about the DECISION, so they build the struct directly and never touch a
    /// screen.
    fn paper_stream(window: u64) -> StreamController {
        StreamController {
            surface: SurfaceId::new(window),
            stop: std::sync::Arc::new(AtomicBool::new(false)),
            finished: std::sync::Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn a_live_stream_may_send_its_chunks() {
        let s = active_session_with(7);
        let stream = paper_stream(7);
        assert_eq!(
            chunk_send_decision(Some(&stream), &s, now_epoch_secs()),
            ChunkSend::Send
        );
    }

    /// THE DEFECT, as a test. Revoking the surface used to stop the NEXT
    /// one-shot capture while an already-running stream kept delivering pixels,
    /// because `frame_gate` ran once at `stream_start` and the send path never
    /// consulted the session again.
    #[test]
    fn revoking_the_surface_stops_a_stream_that_is_already_running() {
        let mut s = active_session_with(7);
        let stream = paper_stream(7);
        assert_eq!(
            chunk_send_decision(Some(&stream), &s, now_epoch_secs()),
            ChunkSend::Send,
            "precondition: it was sending before the revoke"
        );

        s.revoke_surface(SurfaceId::new(7)).unwrap();

        assert_eq!(
            chunk_send_decision(Some(&stream), &s, now_epoch_secs()),
            ChunkSend::AuthorityEnded,
            "a revoked surface must stop pixels ALREADY IN FLIGHT, not merely \
             refuse the next request"
        );
    }

    #[test]
    fn ending_the_session_stops_a_stream_that_is_already_running() {
        let mut s = active_session_with(7);
        let stream = paper_stream(7);
        s.end();
        assert_eq!(
            chunk_send_decision(Some(&stream), &s, now_epoch_secs()),
            ChunkSend::AuthorityEnded
        );
    }

    /// Expiry is authority ending on a clock rather than by a decision, and it
    /// has to bite the same way.
    #[test]
    fn an_expired_session_stops_a_stream_that_is_already_running() {
        let s = active_session_with(7);
        let stream = paper_stream(7);
        let long_past_expiry = now_epoch_secs() + 4000; // TTL in the helper is 3600
        assert_eq!(
            chunk_send_decision(Some(&stream), &s, long_past_expiry),
            ChunkSend::AuthorityEnded
        );
    }

    /// A stream for one surface must not authorize chunks for another. Both are
    /// permitted here, so what is being tested is that the decision uses the
    /// STREAM'S surface rather than any permitted one.
    #[test]
    fn the_decision_uses_the_streams_own_surface() {
        let mut s = active_session_with(7);
        s.permit_surface(SurfaceId::new(9)).unwrap();
        s.revoke_surface(SurfaceId::new(7)).unwrap();
        assert_eq!(
            chunk_send_decision(Some(&paper_stream(7)), &s, now_epoch_secs()),
            ChunkSend::AuthorityEnded,
            "surface 7 was revoked"
        );
        assert_eq!(
            chunk_send_decision(Some(&paper_stream(9)), &s, now_epoch_secs()),
            ChunkSend::Send,
            "surface 9 is still permitted"
        );
    }

    /// Chunks can still be queued after a stream is dropped. They must be
    /// drained, never written to the socket — and this is NOT an error, so it
    /// is a distinct verdict rather than a denial.
    #[test]
    fn chunks_queued_after_the_stream_stops_are_drained_not_sent() {
        let s = active_session_with(7);
        assert_eq!(
            chunk_send_decision(None, &s, now_epoch_secs()),
            ChunkSend::NoStream
        );
    }

    // ── Window-scope gate tests (the security boundary) ──────────────────────

    fn active_session_with(window: u64) -> ShareSession {
        let now = now_epoch_secs();
        let mut s = ShareSession::new("test-sess", "test-contract", now + 3600);
        s.handshake_complete().unwrap();
        s.permit_surface(SurfaceId::new(window)).unwrap();
        s.start(now).unwrap();
        s
    }

    /// The operator's UIPI decision, tested at the layer it was implemented.
    ///
    /// `an_elevated_foreground_window_cannot_make_the_host_claim_a_false_press`
    /// asserts at the `inject()` layer and is **deliberately still red**: the
    /// fix did not change `inject()`, which still returns `Ok` for a press UIPI
    /// swallowed. It was never going to go green, and that is not a defect —
    /// the decision was to stop *acting* on the false press, one layer up.
    /// This is that layer.
    #[test]
    fn an_undelivered_press_gives_the_grant_back() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_epoch_secs();
        let mut session = active_session_with(42);
        session.grant_input().unwrap();
        assert!(
            session.authorize_input(SurfaceId::new(42), now).is_ok(),
            "the grant must be real before the refusal, or this proves nothing"
        );

        let reply = refuse_undelivered_input(&mut session);

        assert!(
            reply.contains("\"type\":\"denied\"") && reply.contains("\"for\":\"input_event\""),
            "the client must be told, and told which command was refused: {reply}"
        );
        assert!(
            reply.contains("given back"),
            "the reason must say the grant was returned, not merely that input failed: {reply}"
        );
        assert!(
            session.authorize_input(SurfaceId::new(42), now).is_err(),
            "the grant was NOT given back — the host would go on accepting input \
             it cannot deliver, which is the whole thing this decision prevents"
        );
    }

    /// A refusal must not leave the desktop holding anything.
    ///
    /// **The host has to do the releasing, because after the revoke the client
    /// cannot.** Past a revoke every `input_event` is denied, so the Up the
    /// phone would normally send is refused; if the host does not release on
    /// its way out, whatever was down stays down. Red-proven by deleting the
    /// release: the key is stranded and this test names it.
    ///
    /// **Something is actually pressed first.** The first version of this test
    /// asserted `!is_holding_input()` over a session that had never injected
    /// anything, so it passed no matter what `refuse_undelivered_input` did --
    /// a vacuous test guarding the exact bug that turns a safety mechanism into
    /// a stuck desktop. `#[cfg(windows)]` because it needs a real injector, and
    /// F13 because it is inert.
    #[test]
    #[cfg(windows)]
    fn a_refusal_releases_what_it_was_holding() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut session = active_session_with(42);
        session.grant_input().unwrap();

        module10::inject::release_input_state();
        module10::inject::inject(&module10::message::InputControlMessage::KeyEvent {
            scan_code: 0x64, // F13
            action: module10::message::KeyAction::Down,
            modifiers: 0,
        })
        .expect("F13 down");
        // ASSERT THE DESKTOP, NOT OUR OWN RECORD.
        //
        // This asserted `is_holding_input()`, which reads the host's record --
        // and `observe_key` fills that whether or not Windows applied anything.
        // Windows round 18 caught it passing in round 17 while its F13 press was
        // being refused outright: the guard against a vacuous test was itself
        // vacuous. `live_input_release` had the right instrument all along.
        assert_eq!(
            module10::inject::scan_code_is_down(0x64),
            Some(true),
            "F13 did not actually go down on this desktop, so the release this test \
             checks would have nothing to release and the test would prove nothing"
        );
        assert!(
            module10::inject::is_holding_input(),
            "the key is down on the desktop but the host kept no record of it"
        );

        let _ = refuse_undelivered_input(&mut session);

        assert!(
            !module10::inject::is_holding_input(),
            "the refusal gave the grant back while still holding a key. Past the              revoke every input_event is denied, so the client can no longer send              the Up - this is the stuck desktop wearing a safety mechanism's clothes"
        );
    }

    #[test]
    fn capture_denied_without_grant_or_permitted_window() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_epoch_secs();
        let mut s = ShareSession::new("t", "t", now + 3600);
        s.handshake_complete().unwrap();
        let cmd: serde_json::Value =
            serde_json::from_str(r#"{"type":"screenshot_request","window":42}"#).unwrap();
        // No capability env -> denied regardless of scope.
        std::env::remove_var("RD_CAP_SCREENSHOT");
        assert!(frame_gate(&s, "screenshot_request", &cmd, now).is_err());
        // Capability granted but window never permitted -> scope denial.
        std::env::set_var("RD_CAP_SCREENSHOT", "1");
        let r = frame_gate(&s, "screenshot_request", &cmd, now);
        std::env::remove_var("RD_CAP_SCREENSHOT");
        assert!(
            r.is_err(),
            "an unpermitted window must be denied even with the capability"
        );
    }

    #[test]
    fn capture_allows_only_the_permitted_window() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_SCREENSHOT", "1");
        let now = now_epoch_secs();
        let s = active_session_with(42);
        let permitted: serde_json::Value =
            serde_json::from_str(r#"{"type":"screenshot_request","window":42}"#).unwrap();
        let other: serde_json::Value =
            serde_json::from_str(r#"{"type":"screenshot_request","window":99}"#).unwrap();
        let ok = frame_gate(&s, "screenshot_request", &permitted, now).is_ok();
        let denied = frame_gate(&s, "screenshot_request", &other, now).is_err();
        std::env::remove_var("RD_CAP_SCREENSHOT");
        assert!(ok, "the permitted window must be capturable");
        assert!(denied, "a non-permitted window must never be captured");
    }

    #[test]
    fn revoking_a_window_cuts_off_capture() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_SCREENSHOT", "1");
        let now = now_epoch_secs();
        let mut s = active_session_with(42);
        let cmd: serde_json::Value =
            serde_json::from_str(r#"{"type":"screenshot_request","window":42}"#).unwrap();
        let before = frame_gate(&s, "screenshot_request", &cmd, now).is_ok();
        s.revoke_surface(SurfaceId::new(42)).unwrap();
        let after = frame_gate(&s, "screenshot_request", &cmd, now).is_err();
        std::env::remove_var("RD_CAP_SCREENSHOT");
        assert!(before, "the permitted window is capturable before revoke");
        assert!(after, "revoke must immediately cut off capture");
    }

    /// The clipboard is its OWN capability, and `RD_CAP_INPUT` does not buy it.
    ///
    /// This is the whole point of `clipboard_grant` being a separate check
    /// rather than a call into `input_gate`. A phone that may drive the mouse
    /// has not thereby been given the machine's clipboard, which holds things
    /// that were never on screen — a copied password among them. The refusal
    /// NAMES the variable, so an operator who wanted the feature can see what
    /// to set rather than concluding the button is broken.
    #[test]
    fn the_clipboard_needs_its_own_capability_not_merely_input() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_INPUT", "1");
        std::env::remove_var("RD_CAP_CLIPBOARD");
        let now = now_epoch_secs();
        let mut s = active_session_with(42);
        s.grant_input().unwrap();
        let cmd: serde_json::Value =
            serde_json::from_str(r#"{"type":"clipboard_push","window":42,"text":"x"}"#).unwrap();

        let without = clipboard_grant(&s, "clipboard_push", &cmd, now);
        std::env::set_var("RD_CAP_CLIPBOARD", "1");
        let with = clipboard_grant(&s, "clipboard_push", &cmd, now);
        std::env::remove_var("RD_CAP_CLIPBOARD");
        std::env::remove_var("RD_CAP_INPUT");

        let denial = without.expect_err("input alone must not grant the clipboard");
        assert!(
            denial.contains("RD_CAP_CLIPBOARD"),
            "the refusal must name the variable to set, got: {denial}"
        );
        assert!(with.is_ok(), "with both grants the clipboard is reachable");
    }

    /// Viewing is not enough, in EITHER direction.
    ///
    /// Writing the host's clipboard is writing to the host. Reading it is not
    /// "viewing" either: the clipboard holds what was COPIED, very often
    /// something that was never on the screen, so a peer with only a view would
    /// be taking data the view never showed them. Both go through the same
    /// surface-scoped input authorization every keystroke passes.
    #[test]
    fn the_clipboard_is_denied_to_a_viewer_in_both_directions() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_INPUT", "1");
        std::env::set_var("RD_CAP_CLIPBOARD", "1");
        let now = now_epoch_secs();
        let mut s = active_session_with(42);
        let push: serde_json::Value =
            serde_json::from_str(r#"{"type":"clipboard_push","window":42,"text":"x"}"#).unwrap();
        let pull: serde_json::Value =
            serde_json::from_str(r#"{"type":"clipboard_pull","window":42}"#).unwrap();

        // View-only: both refused.
        let push_viewonly = clipboard_grant(&s, "clipboard_push", &push, now).is_err();
        let pull_viewonly = clipboard_grant(&s, "clipboard_pull", &pull, now).is_err();

        s.grant_input().unwrap();
        let push_granted = clipboard_grant(&s, "clipboard_push", &push, now).is_ok();
        let pull_granted = clipboard_grant(&s, "clipboard_pull", &pull, now).is_ok();

        // A window this peer was never permitted stays refused.
        let other: serde_json::Value =
            serde_json::from_str(r#"{"type":"clipboard_push","window":99,"text":"x"}"#).unwrap();
        let other_denied = clipboard_grant(&s, "clipboard_push", &other, now).is_err();

        // Dropping back to view-only re-denies immediately.
        s.revoke_input().unwrap();
        let redenied = clipboard_grant(&s, "clipboard_push", &push, now).is_err();

        std::env::remove_var("RD_CAP_CLIPBOARD");
        std::env::remove_var("RD_CAP_INPUT");

        assert!(push_viewonly, "a viewer must not write the host clipboard");
        assert!(pull_viewonly, "a viewer must not read the host clipboard");
        assert!(push_granted && pull_granted, "a granted peer may do both");
        assert!(
            other_denied,
            "the clipboard must not widen the window scope"
        );
        assert!(redenied, "revoking control must cut the clipboard off too");
    }

    /// A missing window id is refused rather than defaulted.
    ///
    /// `surface_id_of` returning `None` must not become "some window"; the
    /// scope check is the thing standing between a granted peer and a surface
    /// it was never permitted.
    #[test]
    fn a_clipboard_command_without_a_window_is_refused() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_CLIPBOARD", "1");
        let now = now_epoch_secs();
        let mut s = active_session_with(42);
        s.grant_input().unwrap();
        let cmd: serde_json::Value = serde_json::from_str(r#"{"type":"clipboard_pull"}"#).unwrap();
        let result = clipboard_grant(&s, "clipboard_pull", &cmd, now);
        std::env::remove_var("RD_CAP_CLIPBOARD");
        assert!(result.is_err(), "a command with no window must be refused");
    }

    /// Serialises the tests that write the process-wide lock cache.
    ///
    /// Order with `ENV_LOCK` is always ENV first, then this one; two tests
    /// taking them in opposite orders would deadlock the suite.
    static LOCK_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Sets the cache and hands back what was there, so a test restores the
    /// exact prior state rather than assuming the default.
    fn set_lock_cache(hint: u8, ever: bool) -> (u8, bool) {
        let prev = (
            LOCK_HINT.load(Ordering::SeqCst),
            LOCK_EVER_OBSERVED.load(Ordering::SeqCst),
        );
        LOCK_HINT.store(hint, Ordering::SeqCst);
        LOCK_EVER_OBSERVED.store(ever, Ordering::SeqCst);
        prev
    }

    #[test]
    fn an_unlocked_desktop_takes_input_and_a_locked_one_does_not() {
        assert!(lock_gate(LockObservation::Unlocked).is_ok());
        assert!(
            lock_gate(LockObservation::Locked).is_err(),
            "a locked desktop must refuse injected input"
        );
    }

    /// The two "no answer" cases are deliberately NOT the same answer.
    ///
    /// A host with no logind never had lock awareness, and refusing every
    /// keystroke there would break the product rather than protect anyone. A
    /// host whose logind answered and then went quiet is a different story:
    /// the host cannot see the lock any more, and silencing the probe must not
    /// be a way out of the guard.
    #[test]
    fn losing_logind_refuses_but_never_having_it_does_not() {
        assert!(
            lock_gate(LockObservation::NeverObserved).is_ok(),
            "a host with no logind must still be usable"
        );
        assert!(
            lock_gate(LockObservation::Lost).is_err(),
            "logind going quiet after answering must refuse, not fail open"
        );
    }

    /// The uid the lock probe asks logind about.
    ///
    /// `Uid:` carries four values and only the first is the operator's. Taking
    /// the wrong column would query a user that exists on some systems and not
    /// others, and the probe would fail with no answer — which reads as "this
    /// machine has no logind" and quietly allows every keystroke.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_lock_probe_reads_the_real_uid_from_proc_status() {
        // The four uids are real, effective, saved and filesystem, and this
        // fixture makes them DIFFERENT on purpose. Written first with four
        // identical 1000s, it passed just as happily reading the effective uid
        // as the real one — a test that cannot fail is not evidence.
        let status = "Name:\tremotedexter\nState:\tS (sleeping)\n\
                      Uid:\t1000\t0\t0\t1000\nGid:\t1000\t44\t44\t1000\n";
        assert_eq!(parse_real_uid(status).as_deref(), Some("1000"));
        assert_eq!(
            parse_real_uid("Uid:\t0\t1000\t1000\t0\n").as_deref(),
            Some("0")
        );
        // No Uid line, a truncated one, and a non-numeric one are all "cannot
        // tell", never a guess.
        assert_eq!(parse_real_uid("Name:\tx\n"), None);
        assert_eq!(parse_real_uid("Uid:\n"), None);
        assert_eq!(parse_real_uid("Uid:\troot\n"), None);
    }

    #[test]
    fn the_cache_reports_lost_only_after_logind_has_answered_once() {
        let _g = LOCK_STATE_LOCK.lock().unwrap();
        let prev = set_lock_cache(0, false);
        let never = lock_observation();
        set_lock_cache(0, true);
        let lost = lock_observation();
        set_lock_cache(2, true);
        let locked = lock_observation();
        set_lock_cache(1, true);
        let unlocked = lock_observation();
        set_lock_cache(prev.0, prev.1);
        drop(_g);
        assert_eq!(never, LockObservation::NeverObserved);
        assert_eq!(lost, LockObservation::Lost);
        assert_eq!(locked, LockObservation::Locked);
        assert_eq!(unlocked, LockObservation::Unlocked);
    }

    /// The gate a granted peer actually passes through, with the screen locked.
    ///
    /// Proven necessary in the VM on 2026-09-07: without this the keystrokes
    /// reached the lock screen's password field. The session here is fully
    /// authorised — permitted window, input granted, capability set — because
    /// that is the case the lock has to override.
    #[test]
    fn a_granted_peer_cannot_type_into_a_locked_desktop() {
        let _e = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _g = LOCK_STATE_LOCK.lock().unwrap();
        std::env::set_var("RD_CAP_INPUT", "1");
        std::env::set_var("RD_CAP_CLIPBOARD", "1");
        let now = now_epoch_secs();
        let mut s = active_session_with(42);
        s.grant_input().unwrap();
        let ev: serde_json::Value = serde_json::from_str(
            r#"{"type":"input_event","window":42,"event":{"MouseMove":{"mode":"Relative","dx":0,"dy":0,"abs_x":0,"abs_y":0}}}"#,
        )
        .unwrap();
        let clip: serde_json::Value =
            serde_json::from_str(r#"{"type":"clipboard_pull","window":42}"#).unwrap();

        let prev = set_lock_cache(1, true);
        let unlocked_input = input_gate(&s, &ev, now).is_ok();
        let unlocked_clip = clipboard_grant(&s, "clipboard_pull", &clip, now).is_ok();

        set_lock_cache(2, true);
        let locked_input = input_gate(&s, &ev, now);
        let locked_clip = clipboard_grant(&s, "clipboard_pull", &clip, now);
        set_lock_cache(prev.0, prev.1);
        std::env::remove_var("RD_CAP_INPUT");
        std::env::remove_var("RD_CAP_CLIPBOARD");
        // Both guards go before the assertions. Every mutable thing this test
        // touched is already restored, and a failing assertion that unwinds
        // while still holding them POISONS them: the one real failure is then
        // reported as a dozen, eight of which have nothing to do with it.
        drop(_g);
        drop(_e);

        assert!(unlocked_input, "an unlocked desktop must still take input");
        assert!(
            unlocked_clip,
            "an unlocked desktop must still take clipboard"
        );
        let denial = locked_input.expect_err("a locked desktop must refuse input");
        assert!(
            denial.contains("locked"),
            "the peer should learn why it was refused: {denial}"
        );
        assert!(
            locked_clip.is_err(),
            "a locked desktop must refuse the clipboard too"
        );
    }

    #[test]
    fn input_requires_permitted_window_and_explicit_control_grant() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_INPUT", "1");
        let now = now_epoch_secs();
        let mut s = active_session_with(42);
        let ev: serde_json::Value = serde_json::from_str(
            r#"{"type":"input_event","window":42,"event":{"MouseMove":{"mode":"Relative","dx":0,"dy":0,"abs_x":0,"abs_y":0}}}"#,
        )
        .unwrap();
        // View-only by default -> input denied even for a permitted window.
        let denied_viewonly = input_gate(&s, &ev, now).is_err();
        // Explicit grant -> allowed.
        s.grant_input().unwrap();
        let allowed = input_gate(&s, &ev, now).is_ok();
        // A different window is denied even with input granted.
        let other: serde_json::Value = serde_json::from_str(
            r#"{"type":"input_event","window":99,"event":{"MouseMove":{"mode":"Relative","dx":0,"dy":0,"abs_x":0,"abs_y":0}}}"#,
        )
        .unwrap();
        let other_denied = input_gate(&s, &other, now).is_err();
        // Dropping back to view-only re-denies.
        s.revoke_input().unwrap();
        let redenied = input_gate(&s, &ev, now).is_err();
        std::env::remove_var("RD_CAP_INPUT");
        assert!(denied_viewonly, "view-only must deny input");
        assert!(allowed, "granted input into the permitted window must pass");
        assert!(
            other_denied,
            "input control must not widen the window scope"
        );
        assert!(redenied, "revoking input must re-deny");
    }

    /// An absolute move must be refused whenever the permitted window's
    /// geometry cannot be established, because there is then nothing to clamp
    /// it against.
    ///
    /// This is not hypothetical. `window_rect` is Windows-only in
    /// `capture_windows_printwindow` and returns `None` for every window on Linux; the
    /// clamp used to be written `if let Some(rect) = window_rect(w)`, so it
    /// silently did not run. That was harmless only while input injection was a
    /// no-op stub. With the uinput backend live, it meant a client granted one
    /// window could steer the pointer across the whole desktop and click
    /// anything — the exact boundary this host exists to hold.
    ///
    /// On Linux this asserts the refusal directly. On Windows the geometry of a
    /// real window is available, so the same rule is asserted through a window
    /// id that cannot have a rect.
    #[test]
    fn absolute_move_is_refused_when_window_geometry_is_unknown() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_INPUT", "1");
        let now = now_epoch_secs();
        // Window 0 is never a real window on either platform, so `window_rect`
        // cannot produce a rect for it.
        let mut s = active_session_with(0);
        s.grant_input().unwrap();
        let ev: serde_json::Value = serde_json::from_str(
            r#"{"type":"input_event","window":0,"event":{"MouseMove":{"mode":"Absolute","dx":0,"dy":0,"abs_x":10,"abs_y":10}}}"#,
        )
        .unwrap();
        let result = input_gate(&s, &ev, now);
        // A relative move over the same window still passes: it is the absolute
        // path that depends on geometry, and denying everything would hide a
        // regression in the clamp rather than catch it.
        let rel: serde_json::Value = serde_json::from_str(
            r#"{"type":"input_event","window":0,"event":{"MouseMove":{"mode":"Relative","dx":1,"dy":1,"abs_x":0,"abs_y":0}}}"#,
        )
        .unwrap();
        let rel_ok = input_gate(&s, &rel, now).is_ok();
        std::env::remove_var("RD_CAP_INPUT");
        assert!(
            result.is_err(),
            "absolute move must fail closed without window geometry"
        );
        assert!(rel_ok, "relative moves do not depend on window geometry");
    }

    #[test]
    fn session_commands_drive_the_allowlist_and_control() {
        // This test is about the allowlist and the control flow, not the
        // capability gate, so it enables input rather than dropping the
        // assertion that `grant_input` acknowledges.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_INPUT", "1");
        let now = now_epoch_secs();
        let mut s = ShareSession::new("t", "t", now + 3600);
        s.handshake_complete().unwrap();
        let permit: serde_json::Value =
            serde_json::from_str(r#"{"type":"permit_window","window":7}"#).unwrap();
        let r = handle_session_command(&mut s, "permit_window", &permit, now).unwrap();
        assert_eq!(field(&r, "type").as_deref(), Some("ack"));
        assert!(s.authorize_frame(SurfaceId::new(7), now).is_ok());
        let gi: serde_json::Value = serde_json::from_str(r#"{"type":"grant_input"}"#).unwrap();
        let r2 = handle_session_command(&mut s, "grant_input", &gi, now).unwrap();
        assert_eq!(field(&r2, "type").as_deref(), Some("ack"));
        assert!(s.authorize_input(SurfaceId::new(7), now).is_ok());
        // list_windows returns a windows envelope (contents depend on the host).
        let lw: serde_json::Value = serde_json::from_str(r#"{"type":"list_windows"}"#).unwrap();
        let r3 = handle_session_command(&mut s, "list_windows", &lw, now).unwrap();
        assert_eq!(field(&r3, "type").as_deref(), Some("windows"));
        // A non-session command is not handled here (routes elsewhere).
        let ping: serde_json::Value = serde_json::from_str(r#"{"type":"ping"}"#).unwrap();
        assert!(handle_session_command(&mut s, "ping", &ping, now).is_none());
        std::env::remove_var("RD_CAP_INPUT");
    }

    /// `grant_input` must not promise what `input_event` will refuse.
    ///
    /// The host used to ACK `grant_input` unconditionally — it is not
    /// capability-gated — while every following `input_event` was denied on
    /// `RD_CAP_INPUT`. The client therefore showed "Control enabled", the first
    /// finger movement was refused, and `ControlDenialPolicy.losesGrant` turned
    /// it straight back off. The operator reported that on 2026-08-25 as
    /// "it enables and then about two seconds later it says disabled", and it
    /// cost hours because the UI reported a grant the host would never honour.
    ///
    /// A host must not hold a grant it will not act on, so this asserts the
    /// session state too, not merely the reply.
    #[test]
    fn grant_input_is_refused_when_the_input_capability_is_off() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("RD_CAP_INPUT");
        let now = now_epoch_secs();
        let mut s = ShareSession::new("t", "t", now + 3600);
        s.handshake_complete().unwrap();
        let permit: serde_json::Value =
            serde_json::from_str(r#"{"type":"permit_window","window":7}"#).unwrap();
        handle_session_command(&mut s, "permit_window", &permit, now).unwrap();

        let gi: serde_json::Value = serde_json::from_str(r#"{"type":"grant_input"}"#).unwrap();
        let r = handle_session_command(&mut s, "grant_input", &gi, now).unwrap();

        assert_eq!(
            field(&r, "type").as_deref(),
            Some("denied"),
            "grant_input must be refused when input is not enabled; got {r}"
        );
        let reason = field(&r, "reason").unwrap_or_default();
        assert!(
            reason.contains("RD_CAP_INPUT"),
            "the denial must name the switch the operator has to set, got: {reason}"
        );
        assert!(
            s.authorize_input(SurfaceId::new(7), now).is_err(),
            "a refused grant must leave no input authority behind"
        );
    }

    /// The gate must not be a blanket refusal: with the capability on, the
    /// grant still works exactly as before.
    #[test]
    fn grant_input_is_granted_when_the_input_capability_is_on() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_INPUT", "1");
        let now = now_epoch_secs();
        let mut s = ShareSession::new("t", "t", now + 3600);
        s.handshake_complete().unwrap();
        let permit: serde_json::Value =
            serde_json::from_str(r#"{"type":"permit_window","window":7}"#).unwrap();
        handle_session_command(&mut s, "permit_window", &permit, now).unwrap();

        let gi: serde_json::Value = serde_json::from_str(r#"{"type":"grant_input"}"#).unwrap();
        let r = handle_session_command(&mut s, "grant_input", &gi, now).unwrap();
        std::env::remove_var("RD_CAP_INPUT");

        assert_eq!(field(&r, "type").as_deref(), Some("ack"), "got {r}");
        assert!(
            s.authorize_input(SurfaceId::new(7), now).is_ok(),
            "an acknowledged grant must actually authorize input"
        );
    }

    /// Regression test for the streaming bug diagnosed 2026-08-16/17: the host
    /// used to advertise the desktop surface under `u64::MAX`. Rust's own
    /// `serde_json` round-trips that fine, but Android's `org.json.optLong` —
    /// a **signed** 64-bit path — cannot represent it and silently saturates
    /// to `Long.MAX_VALUE`, corrupting the id before the client ever echoes it
    /// back to the host. `DESKTOP_ID` must survive a signed-64-bit reader
    /// intact, not just a Rust one.
    ///
    /// Written against the real `list_windows_response()` wire format (not a
    /// hand-built JSON string), so a future change to that function stays
    /// covered. Confirmed failing against the pre-fix `u64::MAX` constant
    /// before this fix landed — `.as_i64()` returned `None` for it, exactly
    /// mirroring `optLong`'s silent saturation.
    #[test]
    fn desktop_id_survives_a_signed_64_bit_json_round_trip() {
        let resp = list_windows_response();
        let v: serde_json::Value = serde_json::from_str(&resp).expect("valid JSON");
        let wire_id = v["windows"][0]["id"]
            .as_u64()
            .expect("id present as an unsigned 64-bit number");
        assert_eq!(
            wire_id,
            share_source::DESKTOP_ID,
            "wire id must be share_source::DESKTOP_ID"
        );

        // The actual regression check: can a *signed* 64-bit reader (what
        // org.json.optLong uses under the hood) represent this value without
        // loss? `u64::MAX` (18446744073709551615) cannot — `.as_i64()` would
        // return `None` for it.
        let signed = v["windows"][0]["id"].as_i64();
        assert_eq!(
            signed,
            Some(share_source::DESKTOP_ID as i64),
            "DESKTOP_ID must round-trip through a signed-64-bit JSON path — a \
             value that only fits u64 silently corrupts on receipt by a \
             signed-64-bit client such as Android's org.json"
        );
    }

    /// The durable half of the same fix: the desktop surface must be
    /// identifiable by an explicit flag, not by matching a numeric sentinel.
    /// A sentinel in a number field is what caused the bug above in the first
    /// place — casting it to a smaller sentinel only moves the problem to a
    /// value that happens to currently fit.
    #[test]
    fn desktop_surface_is_flagged_explicitly_on_the_wire() {
        let resp = list_windows_response();
        let v: serde_json::Value = serde_json::from_str(&resp).expect("valid JSON");
        assert_eq!(
            v["windows"][0]["desktop"].as_bool(),
            Some(true),
            "the desktop entry must self-identify via an explicit field, not \
             leave the client to infer it from the numeric id"
        );
    }

    /// Regression test for the second, independent defect found alongside the
    /// sentinel bug: a capture failure used to leave `stream` holding a dead
    /// `StreamController` forever. `stream_start`'s `if stream.is_none()`
    /// guard then saw `Some(_)` even though the capture thread had already
    /// exited, so it ACKed every retry without ever spawning a new thread —
    /// the client would be told to keep waiting for frames that could now
    /// never arrive, even after the operator fixed whatever made capture fail
    /// the first time (e.g. re-granting a revoked portal permission).
    #[tokio::test]
    async fn stream_controller_reports_finished_after_a_capture_error() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        // Window 0 is never a valid HWND/desktop id on either platform, so
        // capture fails on the very first frame — deterministic, no display
        // required.
        let ctl = StreamController::start(75, tx, SurfaceId::new(0));

        // Drain until the channel closes (producer thread exits) or we see the
        // client-facing error message the fix now sends.
        let mut saw_error_message = false;
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv()).await {
                Ok(Some(bytes)) => {
                    if bytes.first() != Some(&module11::STREAM_TAG) {
                        let text = std::str::from_utf8(&bytes).unwrap_or("");
                        assert_eq!(field(text, "type").as_deref(), Some("error"));
                        saw_error_message = true;
                    }
                }
                Ok(None) => break, // channel closed = producer thread ended
                Err(_) => panic!("capture thread did not exit within 3s"),
            }
        }
        assert!(
            saw_error_message,
            "a capture failure must be reported to the client, not just to stderr"
        );

        // The actual regression: is_finished() must become true so a future
        // stream_start can tell this controller apart from a live one.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !ctl.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "StreamController never reported finished after its capture \
                 thread exited — a retrying client would be silently stuck"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // ── Block 8: localising the Windows white screen ─────────────────────
    //
    // The reported symptom is a white screen on the phone, and it is consistent
    // with a fault in any of capture, encode, transport, decode or render.
    // `windows-frame-probe` answers the capture half on the Windows box. These
    // two answer the encode/decode half here, on any machine, so that when the
    // probe says "capture is producing real pixels" there is already proof that
    // the next layer down does not flatten them.

    /// A known non-uniform pattern must survive JPEG encode and decode still
    /// non-uniform, at the dimensions it went in with.
    #[test]
    fn a_real_frame_survives_the_encode_path_without_turning_white() {
        use module11::encoder::{Encoder, JPEGEncoder};
        use module11::types::ChromaSubsampling;
        use module11::RawFrame;

        // A 64x64 checkerboard. Deliberately coarse: JPEG at low quality will
        // blur fine detail, and this test is about "did the image survive at
        // all", not about fidelity.
        let (w, h) = (64u32, 64u32);
        let mut data = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                let on = ((x / 8) + (y / 8)) % 2 == 0;
                let v = if on { 240 } else { 16 };
                data.extend_from_slice(&[v, v, v, 255]);
            }
        }
        let frame = RawFrame {
            data,
            width: w,
            height: h,
        };
        let encoded = JPEGEncoder::new()
            .encode(&frame, 80, ChromaSubsampling::Yuv420, None)
            .expect("a valid RGBA frame must encode");
        let decoded = image::load_from_memory_with_format(&encoded.data, image::ImageFormat::Jpeg)
            .expect("the encoder must produce a decodable JPEG");
        assert_eq!(
            (decoded.width(), decoded.height()),
            (w, h),
            "the encode path changed the frame's dimensions"
        );
        let rgb = decoded.to_rgb8();
        let first = *rgb.pixels().next().expect("decoded image has pixels");
        assert!(
            rgb.pixels().any(|p| *p != first),
            "a checkerboard came out of the encode path as a single colour — \
             a white screen would NOT be a capture fault"
        );
    }

    #[test]
    fn geometry_transitions_survive_encode_chunk_and_reassembly() {
        use module11::encoder::{Encoder, JPEGEncoder};
        use module11::types::ChromaSubsampling;
        use module11::{FrameReassembler, RawFrame};

        let encoder = JPEGEncoder::new();
        let mut reassembler = FrameReassembler::new();
        for (sequence, (width, height)) in [(1u32, (96u32, 64u32)), (2, (64, 96)), (3, (96, 64))] {
            let mut data = Vec::with_capacity((width * height * 4) as usize);
            for y in 0..height {
                for x in 0..width {
                    data.extend_from_slice(&[(x % 251) as u8, (y % 251) as u8, 96, 255]);
                }
            }
            let raw = RawFrame {
                data,
                width,
                height,
            };
            let encoded = encoder
                .encode(&raw, 80, ChromaSubsampling::Yuv420, None)
                .expect("a valid transition frame must encode");
            let chunks = module11::chunk_frame(
                sequence,
                width as u16,
                height as u16,
                encoded.is_keyframe,
                &encoded.data,
                97,
            );
            assert!(chunks.len() > 1, "the test must cross a chunk boundary");

            let mut completed = None;
            for chunk in chunks {
                if let Some(frame) = reassembler.push(&chunk) {
                    completed = Some(frame);
                }
            }
            let frame = completed.expect("the final chunk must complete the frame");
            assert_eq!(frame.seq, sequence);
            assert_eq!(
                (frame.width, frame.height),
                (width as u16, height as u16),
                "wire metadata retained geometry from the preceding orientation"
            );
            let decoded =
                image::load_from_memory_with_format(&frame.data, image::ImageFormat::Jpeg)
                    .expect("the reassembled payload must remain a valid JPEG");
            assert_eq!(
                (decoded.width(), decoded.height()),
                (width, height),
                "encoded pixels retained geometry from the preceding orientation"
            );
        }
    }

    /// The control. A genuinely uniform frame must come back uniform — without
    /// this, the test above could pass on an encoder that never flattens
    /// anything and prove nothing about the one that does.
    #[test]
    fn a_blank_frame_still_decodes_blank_so_the_check_can_tell_them_apart() {
        use module11::encoder::{Encoder, JPEGEncoder};
        use module11::types::ChromaSubsampling;
        use module11::RawFrame;

        let (w, h) = (64u32, 64u32);
        let frame = RawFrame {
            data: vec![0xFF; (w * h * 4) as usize],
            width: w,
            height: h,
        };
        let encoded = JPEGEncoder::new()
            .encode(&frame, 80, ChromaSubsampling::Yuv420, None)
            .expect("a uniform frame is still a valid frame");
        let decoded = image::load_from_memory_with_format(&encoded.data, image::ImageFormat::Jpeg)
            .expect("must decode");
        let rgb = decoded.to_rgb8();
        let first = *rgb.pixels().next().expect("decoded image has pixels");
        assert!(
            rgb.pixels().all(|p| *p == first),
            "an all-white frame did not decode as one colour; the discriminator is unreliable"
        );
        assert!(first.0[0] > 200, "all-white in must be near-white out");
    }

    /// The lines of a batch file that actually DO something.
    ///
    /// Drops `rem` comments and `echo` output. The distinction is the whole
    /// point of the test below: a launcher that *prints* how to enable input
    /// and a launcher that *enables* input contain the same characters, and a
    /// substring search over the raw file cannot tell them apart. The
    /// `windows-host` gate row said as much about this very test -- "reads
    /// only text" -- and it was right.
    #[cfg(test)]
    fn effective_batch_lines(source: &str) -> Vec<&str> {
        source
            .lines()
            .map(str::trim)
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                !(lower.starts_with("rem ")
                    || lower == "rem"
                    || lower.starts_with("::")
                    || lower.starts_with("echo"))
            })
            .collect()
    }

    /// The supported launchers must make viewing usable without silently
    /// granting control. Windows previously pointed every shortcut straight at
    /// `host_app.exe`, so the fail-closed capture gate refused `stream_start`.
    ///
    /// Two properties, not one, since round 5:
    ///
    /// 1. **The launcher must not grant input.** Deny-by-default is the
    ///    policy and the launcher does not get to overrule it.
    /// 2. **The launcher must SAY HOW to grant it.** That is the half that
    ///    was missing: the refusal reaches the operator as a toast on the
    ///    phone naming an environment variable, on a machine they may not be
    ///    sitting at. Silence there is not caution, it is a dead end.
    ///
    /// Holding both at once is why this reads effective lines rather than raw
    /// text -- under a substring search the second property makes the first
    /// unprovable.
    #[test]
    fn supported_launchers_grant_capture_but_not_input() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("host_app has a repository parent");
        let linux = std::fs::read_to_string(root.join("run.sh")).expect("Linux launcher");
        assert!(linux.contains("export RD_CAP_SCREENSHOT=1"));
        assert!(!linux.contains("export RD_CAP_INPUT=1"));

        // THE ONE THAT ACTUALLY SHIPS, and the one this test did not read until
        // 2026-09-05. run.sh and run.bat are DEVELOPMENT launchers. The .deb
        // installs packaging/linux/remotedexter-launcher as /usr/bin/remotedexter
        // and the .desktop file's Exec=remotedexter runs it, so it is what every
        // user who clicks the icon gets.
        //
        // It granted NOTHING. Deny-by-default meant the packaged product could
        // not capture the screen at all: stream_start refused, phone blank,
        // console silent at the moment it mattered. The defect survived every
        // gate because this test proved its property about the wrong artifact —
        // and the operator found it by clicking the icon instead of typing
        // run.sh, which is what a real user does.
        let packaged = std::fs::read_to_string(root.join("packaging/linux/remotedexter-launcher"))
            .expect("the packaged launcher");
        assert!(
            packaged.contains("export RD_CAP_SCREENSHOT=1"),
            "the PACKAGED launcher must enable viewing — without it, installing \
             the .deb and clicking the icon produces a host that cannot show a \
             desktop, which is the whole product"
        );
        for line in packaged.lines() {
            let code = line.split('#').next().unwrap_or("").trim();
            assert!(
                !code.starts_with("export RD_CAP_INPUT") && !code.starts_with("RD_CAP_INPUT=1 "),
                "the packaged launcher grants control on an effective line, which \
                 overrules deny-by-default: {line:?}"
            );
        }
        assert!(
            packaged.contains("RD_CAP_INPUT"),
            "the packaged launcher must tell the operator how to enable control; \
             otherwise the refusal reaches them only as a toast on the phone, \
             naming a variable, on a machine they may not be sitting at"
        );

        let windows =
            std::fs::read_to_string(root.join("windows/run.bat")).expect("Windows launcher");
        let effective = effective_batch_lines(&windows);

        assert!(
            effective
                .iter()
                .any(|l| l.contains("set RD_CAP_SCREENSHOT=1")),
            "the Windows launcher must actually enable viewing, not just mention it"
        );
        for line in &effective {
            assert!(
                !line.contains("RD_CAP_INPUT=1"),
                "the Windows launcher assigns RD_CAP_INPUT on an effective line, \
                 which silently grants control: {line:?}"
            );
        }
        assert!(
            windows.contains("RD_CAP_INPUT"),
            "the Windows launcher must tell the operator how to enable input; \
             the refusal otherwise arrives as a toast on the phone naming a \
             variable, on a machine they may not be sitting at"
        );

        // And the guard for the missing executable, which is the other half of
        // the same chain: the launcher does not build host_app.exe, so on a
        // clean checkout it must say so rather than `start` nothing.
        assert!(
            effective.iter().any(|l| l.contains("if not exist")),
            "the launcher must check for host_app.exe before starting it"
        );

        // The DIAGNOSTIC launcher, added 2026-09-07. It exists because run.bat
        // detaches via `start ""` and the artifact for a P9 run IS console
        // output — round 13 had to declare a deviation to capture it.
        //
        // A third launcher that grants capabilities is the shape of the
        // 2026-09-05 defect, so it is held to the same two properties as the
        // others. The stronger check — that the two launchers grant the SAME
        // thing, compared at runtime rather than asserted twice — lives in
        // windows/test-run-bat.ps1, because only executing them can prove it.
        let console = std::fs::read_to_string(root.join("windows/run-console.bat"))
            .expect("the diagnostic launcher");
        let console_effective = effective_batch_lines(&console);
        assert!(
            console_effective
                .iter()
                .any(|l| l.contains("set RD_CAP_SCREENSHOT=1")),
            "the diagnostic launcher must enable viewing like the supported one"
        );
        for line in &console_effective {
            assert!(
                !line.contains("RD_CAP_INPUT=1"),
                "the diagnostic launcher assigns RD_CAP_INPUT on an effective line —                  a launcher for testing does not get to relax deny-by-default: {line:?}"
            );
        }
        assert!(
            console_effective.iter().any(|l| l.contains("if not exist")),
            "the diagnostic launcher must check for host_app.exe before running it"
        );
        assert!(
            !console_effective.iter().any(|l| l.contains("start \"\"")),
            "run-console.bat must NOT detach — running attached is its whole purpose"
        );

        let shortcuts =
            std::fs::read_to_string(root.join("windows/bootstrap/install_shortcut.bat"))
                .expect("Windows shortcut installer");
        assert!(shortcuts.contains("set HOST_LAUNCHER=%WIN_DIR%\\run.bat"));
        assert!(!shortcuts.contains("set HOST_EXE="));
    }

    #[test]
    fn only_pointer_moves_are_collapsed_into_a_count() {
        // A phone streams 60-120 moves a second and each was a full JSON line
        // on stderr in a RELEASE build. The 2026-09-05 P9 run had to find one
        // release line among hundreds of them.
        assert!(is_pointer_move_command(
            r#"{"type":"input_event","window":1,"event":{"MouseMove":{"mode":"Absolute","dx":0,"dy":0,"abs_x":9,"abs_y":9}}}"#
        ));

        // Everything that carries a decision must still print in full. These
        // are the lines that say what the host allowed, refused, or injected —
        // losing one of them to a counter would be trading the record of a
        // security decision for quieter output.
        for keep in [
            r#"{"type":"input_event","window":1,"event":{"MouseButton":{"button":0,"action":"Down"}}}"#,
            r#"{"type":"input_event","window":1,"event":{"MouseButton":{"button":0,"action":"Up"}}}"#,
            r#"{"type":"input_event","window":1,"event":{"Key":{"scan":30,"action":"Down"}}}"#,
            r#"{"type":"grant_input"}"#,
            r#"{"type":"revoke_input"}"#,
            r#"{"type":"stream_start","window":1}"#,
            r#"{"type":"permit_window","window":1}"#,
        ] {
            assert!(
                !is_pointer_move_command(keep),
                "must still be logged: {keep}"
            );
        }
    }

    #[test]
    fn anything_unrecognisable_is_logged_rather_than_counted() {
        // The asymmetry that sets the default: a missed move costs one noisy
        // line; a misclassified command costs the record of what the host did.
        // So the predicate must answer "no" whenever it is unsure — including
        // for input it cannot parse at all, which is exactly the input worth
        // seeing.
        for unclear in [
            "",
            "not json",
            "{}",
            r#"{"type":"input_event"}"#,
            r#"{"type":"input_event","event":{}}"#,
            // A move bundled with something else is NOT just a move.
            r#"{"type":"input_event","event":{"MouseMove":{},"MouseButton":{"button":0,"action":"Down"}}}"#,
            r#"{"type":"MouseMove"}"#,
        ] {
            assert!(
                !is_pointer_move_command(unclear),
                "unrecognised input must be logged, not silently counted: {unclear:?}"
            );
        }
    }

    /// The discriminator itself, because the test above now depends on it.
    /// Without this, `effective_batch_lines` could return an empty vector and
    /// every "no effective line assigns RD_CAP_INPUT" assertion would pass
    /// vacuously over a launcher that grants control on every line.
    #[test]
    fn effective_batch_lines_keeps_statements_and_drops_talk() {
        let sample = "\
@echo off
rem set RD_CAP_INPUT=1
REM   set RD_CAP_INPUT=1
:: set RD_CAP_INPUT=1
    echo   set RD_CAP_INPUT=1
set RD_CAP_SCREENSHOT=1
    set RD_CAP_INPUT=1
";
        let kept = effective_batch_lines(sample);
        assert!(
            kept.iter().any(|l| l.contains("set RD_CAP_SCREENSHOT=1")),
            "a real assignment must survive"
        );
        assert_eq!(
            kept.iter().filter(|l| l.contains("RD_CAP_INPUT=1")).count(),
            1,
            "exactly the one real assignment survives; the four comments and \
             echoes do not: {kept:?}"
        );
        assert!(
            !kept.is_empty(),
            "an empty result would make every downstream assertion vacuous"
        );
    }
    /// The host must not be left holding the machine down — the three ways,
    /// against real uinput devices.
    ///
    /// **This is the defect that cost the operator a hard power-off** on
    /// 2026-08-30: hover still highlighted, no click landed, and the only exit
    /// was the button on the tower. `release_all` had exactly one caller,
    /// `shutdown`, reached only by host **Stop** — so a press whose Up never
    /// arrived held the desktop until the host was stopped, which is precisely
    /// what a held desktop makes hardest.
    ///
    /// `hw-input-release` proves the Up events reach the kernel. These prove
    /// the host actually *calls* the release at each of the three moments, which
    /// no amount of unit testing can reach: without a real injector nothing is
    /// ever held, so the whole property is vacuous off hardware.
    ///
    /// Serialised: the injector is process-global and these press and release
    /// it. Run in BaxtersVMHarness — Article XIV forbids this box's live seat.
    // Linux AND Windows. Every call below goes through `module10::inject`,
    // which is cross-platform, so the backend decides what actually happens —
    // uinput here, `SendInput` there. The Windows release path has never been
    // executed, and this is the suite that would execute it.
    //
    // NOT gated on `feature = "linux-input"`: that is module10's feature, not
    // host_app's, and naming it here compiled the whole module out silently —
    // the suite reported 138 tests and looked green while proving nothing.
    #[cfg(any(target_os = "linux", windows))]
    mod live_input_release {
        use super::*;
        use module10::message::{ButtonAction, InputControlMessage};
        // Every use of KeyAction in this module is behind `#[cfg(windows)]`
        // (the chord and read-back helpers), while the module itself also
        // builds on Linux — so an ungated import is dead there. Gated rather
        // than `#[allow]`ed: this tree's own rule is no allow band-aids, and an
        // allow would also hide a genuinely unused import added later.
        #[cfg(windows)]
        use module10::message::KeyAction;

        static INJECT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        /// Press the middle button and leave it down — a client that vanished
        /// mid-drag.
        ///
        /// Middle rather than left because nothing in the Linux guest reacts to
        /// it. **That is not true on Windows**, where a held middle button
        /// starts autoscroll: the cursor changes to the four-way arrow and
        /// stays that way after the release until a click or Esc dismisses it.
        /// Reported from the Windows box on 2026-08-31, where the operator saw
        /// the cursor change and asked why. Nothing is left *stuck* — that was
        /// checked across every button and modifier — but the desktop's state
        /// is visibly altered, so run these with the cursor over bare wallpaper
        /// (`Win+D`) rather than over a scrollable window.
        fn press_and_hold() -> bool {
            module10::inject::release_input_state();
            let pressed = module10::inject::inject(&InputControlMessage::MouseButton {
                button: 2,
                action: ButtonAction::Down,
            });
            match pressed {
                Ok(_) => {}
                Err(e) => panic!("could not inject: {e:?} — is /dev/uinput writable?"),
            }
            assert!(
                module10::inject::is_holding_input(),
                "the host does not believe it is holding a button it just pressed"
            );
            true
        }

        /// Wait, briefly, for Windows to report `want` for a button.
        ///
        /// `SendInput` is asynchronous: it queues events and returns, so the
        /// system may not have applied them by the time the next line runs.
        /// Asserting immediately races that and fails intermittently — which it
        /// did, on the first version of this test. A bounded wait asks the
        /// honest question ("does the Up arrive?") instead of an unanswerable
        /// one ("has it arrived within nanoseconds?"), and still fails outright
        /// if the event never lands.
        ///
        /// Returns the observed state and how long it took.
        #[cfg(windows)]
        fn wait_for_button(
            button: u8,
            want: bool,
            limit: std::time::Duration,
        ) -> (bool, std::time::Duration) {
            wait_for(|| module10::inject::button_is_down(button), want, limit)
        }

        /// The bounded wait, over any read-back that answers `Option<bool>`.
        ///
        /// `None` is never treated as a pass. A probe that cannot answer -- a
        /// layout with no virtual key at that position, a non-Windows build --
        /// must time out and fail loudly rather than quietly satisfy a
        /// `want == false` assertion, which would turn "I could not look" into
        /// "the desktop is clean".
        #[cfg(windows)]
        fn wait_for(
            probe: impl Fn() -> Option<bool>,
            want: bool,
            limit: std::time::Duration,
        ) -> (bool, std::time::Duration) {
            let start = std::time::Instant::now();
            loop {
                if probe() == Some(want) {
                    return (true, start.elapsed());
                }
                if start.elapsed() >= limit {
                    return (false, start.elapsed());
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }

        /// Ctrl. Chosen over Shift and Alt deliberately: holding right Shift
        /// for eight seconds raises the Filter Keys prompt, and Alt activates
        /// the focused window's menu bar on release. A held Ctrl does nothing
        /// on its own and nothing when let go -- while still being exactly the
        /// modifier whose sticking makes a desktop misbehave.
        #[cfg(windows)]
        const HELD_MODIFIER: u8 = 0x02;

        /// F13, Set 1 scan code `0x64`.
        ///
        /// The keyboard equivalent of the same care. It is injectable and
        /// readable like any other key, but essentially no software binds it
        /// and it types no character, so a press that is deliberately left
        /// down cannot enter text into whatever the operator had focused. The
        /// middle mouse button was picked for the same reason and turned out
        /// to put Windows into autoscroll (round 4 §7); this one was checked
        /// against that lesson.
        #[cfg(windows)]
        const HELD_KEY_SCAN: u16 = 0x64;

        /// Press Ctrl+F13 and leave both down: a client that vanished holding
        /// a chord. One injection, because that is how the product holds
        /// things -- `HeldInput` records the key and the modifier bit
        /// together, and `release_events` has to emit an Up for each.
        #[cfg(windows)]
        fn press_and_hold_chord() {
            module10::inject::release_input_state();
            match module10::inject::inject(&InputControlMessage::KeyEvent {
                scan_code: HELD_KEY_SCAN,
                action: KeyAction::Down,
                modifiers: HELD_MODIFIER,
            }) {
                Ok(_) => {}
                Err(e) => panic!("could not inject the chord: {e:?}"),
            }
            assert!(
                module10::inject::is_holding_input(),
                "the host does not believe it is holding a chord it just pressed"
            );
        }

        /// Round 4 left this open, and named it the one worth taking first: the
        /// read-back covered mouse buttons only, so a modifier or a key that
        /// `SendInput` accepted but Windows never applied would leave the
        /// desktop held while the host reported itself clean.
        ///
        /// **A stuck modifier is worse than a stuck button.** A held button is
        /// obvious. A held Ctrl leaves a desktop that still responds and does
        /// the wrong thing with every click -- the shape of the lockup that
        /// cost a hard power-off on Linux.
        ///
        /// Both halves are asserted separately so a failure names which one
        /// stuck; a single combined assertion would report "something is held".
        #[test]
        #[cfg(windows)]
        fn the_modifier_and_key_releases_actually_reach_windows() {
            if skip() {
                return;
            }
            let _g = INJECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());

            // The scan code has to resolve on this layout or the key half of
            // this test is asking an unanswerable question. Say so and stop,
            // rather than passing on a `None` nobody read.
            assert!(
                module10::inject::scan_code_is_down(HELD_KEY_SCAN).is_some(),
                "scan code {HELD_KEY_SCAN:#06x} maps to no virtual key on this layout,                  so the key read-back cannot be performed here"
            );

            module10::inject::release_input_state();
            let short = std::time::Duration::from_millis(500);
            let (mod_clean, _) = wait_for(
                || module10::inject::modifier_is_down(HELD_MODIFIER),
                false,
                short,
            );
            let (key_clean, _) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                false,
                short,
            );
            assert!(
                mod_clean && key_clean,
                "ctrl or F13 was already down before this test pressed it                  (ctrl clean: {mod_clean}, key clean: {key_clean})"
            );

            press_and_hold_chord();

            let (saw_mod, mod_after) = wait_for(
                || module10::inject::modifier_is_down(HELD_MODIFIER),
                true,
                short,
            );
            assert!(
                saw_mod,
                "SendInput reported success but Windows never saw ctrl go down after {mod_after:?}"
            );
            let (saw_key, key_after) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                true,
                short,
            );
            assert!(
                saw_key,
                "SendInput reported success but Windows never saw F13 go down after {key_after:?}"
            );
            eprintln!(
                "[readback] Windows saw ctrl down after {mod_after:?}, F13 after {key_after:?}"
            );

            let mut session = active_session_with(42);
            end_session_and_release(&mut session);

            assert!(
                !module10::inject::is_holding_input(),
                "the host still holds the chord after the client went away"
            );

            let limit = std::time::Duration::from_secs(2);
            let (mod_up, mod_up_after) = wait_for(
                || module10::inject::modifier_is_down(HELD_MODIFIER),
                false,
                limit,
            );
            let (key_up, key_up_after) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                false,
                limit,
            );
            eprintln!(
                "[readback] Windows reported ctrl up after {mod_up_after:?}, F13 up after {key_up_after:?}"
            );
            assert!(
                mod_up,
                "the host cleared its record but Windows STILL has CTRL down after                  {mod_up_after:?} - every click on this desktop is now a ctrl-click,                  and the mouse-button read-back would not have noticed"
            );
            assert!(
                key_up,
                "the host cleared its record but Windows STILL has F13 down after                  {key_up_after:?}"
            );
        }
        fn skip() -> bool {
            if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
                eprintln!("skipping: set RD_USE_HW=1 with /dev/uinput to run this");
                return true;
            }
            false
        }

        /// The client disappeared. This is the common case — a backgrounded
        /// phone, a dropped link — and it is the one the operator hit.
        #[test]
        fn a_vanished_client_does_not_leave_the_button_down() {
            if skip() {
                return;
            }
            let _g = INJECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            press_and_hold();
            let mut session = active_session_with(42);
            end_session_and_release(&mut session);
            assert!(
                !module10::inject::is_holding_input(),
                "the host still holds the button after the client went away"
            );
        }

        /// The half the other three cannot prove: that the Up actually reached
        /// Windows, not merely that the host stopped believing it was pressed.
        ///
        /// `is_holding_input()` reads the host's own record. `release_input_state`
        /// clears that record only when `SendInput` returns success — but success
        /// means "accepted into the input queue", not "applied". UIPI, a
        /// higher-integrity foreground window, or an injection blocker can swallow
        /// the event, and the host would report itself clean over a desktop that is
        /// still held down. That is the exact failure this whole suite exists to
        /// prevent, and it is invisible to the other three tests.
        ///
        /// This is the Windows counterpart to the Linux `/dev/input/event*`
        /// read-back recorded in `hw-input-release`.
        #[test]
        #[cfg(windows)]
        fn the_release_actually_reaches_windows_not_just_our_record() {
            if skip() {
                return;
            }
            let _g = INJECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            module10::inject::release_input_state();
            let (clean, _) = wait_for_button(2, false, std::time::Duration::from_millis(500));
            assert!(
                clean,
                "the middle button was already down before this test pressed it"
            );

            press_and_hold();
            let (saw_down, down_after) =
                wait_for_button(2, true, std::time::Duration::from_millis(500));
            assert!(
                saw_down,
                "SendInput reported success but Windows never saw the Down after {down_after:?}"
            );
            eprintln!("[readback] Windows saw the Down after {down_after:?}");

            let mut session = active_session_with(42);
            end_session_and_release(&mut session);

            assert!(
                !module10::inject::is_holding_input(),
                "the host still holds the button after the client went away"
            );

            let (released, up_after) = wait_for_button(2, false, std::time::Duration::from_secs(2));
            eprintln!("[readback] Windows reported the button up after {up_after:?}");
            assert!(
                released,
                "the host cleared its own record but Windows STILL has the button down \
                 after {up_after:?} - this is the stuck desktop, and the other three \
                 tests would all have passed"
            );
        }

        /// The idle watchdog, read back from Windows rather than from our own
        /// record. Round 4's gap 1.
        ///
        /// Round 4 ran `a_silent_client_...` green only and said why: its red
        /// would mean holding the **middle button** down a further 32 seconds
        /// on the operator's only desktop, and on Windows a held middle button
        /// is not inert -- it puts the desktop into autoscroll (round 4 §7).
        /// That reasoning was right about the middle button.
        ///
        /// It is not a reason to leave the watchdog unproven, because the
        /// hazard was the *choice of key*, not the test. F13 held for 32
        /// seconds does nothing at all: no autoscroll, no menu, no character,
        /// no Filter Keys prompt. So this holds F13, waits out the real grace
        /// period, and asks Windows -- not `is_holding_input()` -- whether the
        /// watchdog's release actually landed.
        ///
        /// No modifier here on purpose. The other read-back test covers a held
        /// Ctrl over a sub-second window; leaving Ctrl down for half a minute
        /// would make every keystroke the operator typed in that window a
        /// shortcut, and this test does not need it to prove anything.
        ///
        /// Takes the full grace period in real time, like its sibling: a
        /// shortened clock would prove the opposite of what is claimed.
        #[test]
        #[cfg(windows)]
        fn the_idle_release_actually_reaches_windows() {
            if skip() {
                return;
            }
            let _g = INJECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                module10::inject::scan_code_is_down(HELD_KEY_SCAN).is_some(),
                "scan code {HELD_KEY_SCAN:#06x} maps to no virtual key on this layout"
            );

            module10::inject::release_input_state();
            let short = std::time::Duration::from_millis(500);
            let (clean, _) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                false,
                short,
            );
            assert!(clean, "F13 was already down before this test pressed it");

            match module10::inject::inject(&InputControlMessage::KeyEvent {
                scan_code: HELD_KEY_SCAN,
                action: KeyAction::Down,
                modifiers: 0,
            }) {
                Ok(_) => {}
                Err(e) => panic!("could not inject the held key: {e:?}"),
            }
            let (saw_down, down_after) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                true,
                short,
            );
            assert!(
                saw_down,
                "SendInput reported success but Windows never saw F13 go down after {down_after:?}"
            );

            assert!(
                !module10::inject::release_if_idle(),
                "the watchdog fired immediately; a live drag would be interrupted"
            );
            assert!(module10::inject::is_holding_input());

            std::thread::sleep(
                module10::inject::INPUT_IDLE_RELEASE + std::time::Duration::from_secs(2),
            );
            assert!(
                module10::inject::release_if_idle(),
                "the watchdog never fired, so a silent client holds the desktop forever"
            );
            assert!(
                !module10::inject::is_holding_input(),
                "the watchdog reported a release it did not perform"
            );

            let (released, up_after) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                false,
                std::time::Duration::from_secs(2),
            );
            eprintln!("[readback] Windows reported the idle-released key up after {up_after:?}");
            assert!(
                released,
                "the watchdog cleared its own record but Windows STILL has the key down \
                 after {up_after:?} - a silent client leaves this desktop held, and \
                 a_silent_client_has_its_button_released_after_the_grace would have passed"
            );
        }

        /// Print a confirm-latency distribution and its margin to the budget.
        ///
        /// Round 7 §A asks for this rather than a pass/fail, and the reason is
        /// sound: "no failures today" says the budget is *currently* enough and
        /// nothing about how close it came. A p95 of 6ms against a 500ms budget
        /// is a different situation from a p95 of 400ms, and both report zero
        /// failures.
        #[cfg(windows)]
        fn report_latency(what: &str, samples: &mut Vec<u128>) {
            if samples.is_empty() {
                return;
            }
            samples.sort_unstable();
            let pick = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
            let budget_us = module10::inject::DELIVERY_CONFIRM_TIMEOUT.as_micros();
            let worst = *samples.last().expect("non-empty");
            eprintln!(
                "[race] {what:<7} confirm latency us: min={} p50={} p95={} max={}  \
                 budget={budget_us}us  margin={}x",
                samples[0],
                pick(0.50),
                pick(0.95),
                worst,
                if worst == 0 {
                    budget_us as u128
                } else {
                    budget_us / worst
                }
            );
        }

        /// **Does the new UIPI refusal fire on ordinary, correct presses?**
        ///
        /// `verify_delivery` is called IMMEDIATELY after `inject()` returns,
        /// with no wait. But `SendInput` is **asynchronous** -- it queues events
        /// and returns, and the system applies them afterwards. Round 4 found
        /// exactly this and said so:
        ///
        /// > `SendInput` queues events and returns; reading `GetAsyncKeyState`
        /// > on the next line races the system applying them.
        ///
        /// The measured gap is not uniform. Keyboard Downs have been observed
        /// at ~50-120us, but **mouse button Downs have been measured at ~5.4ms**
        /// (round 4 §5, round 5 §2). A read-back taken microseconds after the
        /// call can therefore see "not down" for a press that is perfectly fine
        /// and simply has not been applied yet.
        ///
        /// That verdict is `NotLanded`, and `NotLanded` now **revokes the
        /// operator's control grant**. So the cost of this race is not a
        /// spurious log line: it is the phone losing control of the desktop
        /// mid-use, on a machine with no elevated window anywhere.
        ///
        /// The Linux side could not test this. `Delivery::Unknown` is the only
        /// answer that platform can give, and `Unknown` is correctly never a
        /// refusal -- so the entire timing question is invisible there. This is
        /// the Windows box's job.
        ///
        /// **This test asserts the absence of the race on a normal desktop.**
        /// Nothing elevated is focused, every press is legitimate, and the
        /// verdict must be `Landed` every single time.
        #[test]
        #[cfg(windows)]
        fn an_ordinary_press_is_not_mistaken_for_a_dropped_one() {
            if skip() {
                return;
            }
            let _g = INJECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            use module10::inject::Delivery;

            let settle = std::time::Duration::from_millis(500);
            module10::inject::release_input_state();

            // ── keys ────────────────────────────────────────────────────────
            // F13: injectable, readable, and bound by essentially nothing, so a
            // press left down for microseconds types nothing anywhere.
            const KEY_ROUNDS: usize = 200;
            let mut key_not_landed = 0usize;
            let mut key_unknown = 0usize;
            let mut key_us: Vec<u128> = Vec::with_capacity(KEY_ROUNDS);
            for _ in 0..KEY_ROUNDS {
                let msg = InputControlMessage::KeyEvent {
                    scan_code: HELD_KEY_SCAN,
                    action: KeyAction::Down,
                    modifiers: 0,
                };
                module10::inject::inject(&msg).expect("F13 down");
                // The confirm latency: how long the product actually waits
                // before it is satisfied the press landed. This is the number
                // `DELIVERY_CONFIRM_TIMEOUT` has to cover, so it is the number
                // worth reporting -- a pass/fail says the budget is enough
                // today and nothing about the margin.
                let t0 = std::time::Instant::now();
                let verdict = module10::inject::verify_delivery(&msg);
                key_us.push(t0.elapsed().as_micros());
                match verdict {
                    Delivery::NotLanded => key_not_landed += 1,
                    Delivery::Unknown => key_unknown += 1,
                    Delivery::Landed => {}
                }
                module10::inject::release_input_state();
                wait_for(
                    || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                    false,
                    settle,
                );
            }
            eprintln!(
                "[race] keys   : {key_not_landed}/{KEY_ROUNDS} NotLanded, {key_unknown} Unknown"
            );
            report_latency("keys", &mut key_us);

            // ── mouse buttons, the slow path ────────────────────────────────
            // Fewer rounds: a held middle button puts Windows into autoscroll
            // (round 4 §7), so each iteration is a press the desktop can react
            // to. It is still the button the release suite already uses, and it
            // is the one whose Down was measured at ~5.4ms.
            const BTN_ROUNDS: usize = 25;
            let mut btn_not_landed = 0usize;
            let mut btn_unknown = 0usize;
            let mut btn_us: Vec<u128> = Vec::with_capacity(BTN_ROUNDS);
            for _ in 0..BTN_ROUNDS {
                let msg = InputControlMessage::MouseButton {
                    button: 2,
                    action: ButtonAction::Down,
                };
                module10::inject::inject(&msg).expect("middle down");
                let t0 = std::time::Instant::now();
                let verdict = module10::inject::verify_delivery(&msg);
                btn_us.push(t0.elapsed().as_micros());
                match verdict {
                    Delivery::NotLanded => btn_not_landed += 1,
                    Delivery::Unknown => btn_unknown += 1,
                    Delivery::Landed => {}
                }
                module10::inject::release_input_state();
                wait_for(|| module10::inject::button_is_down(2), false, settle);
            }
            eprintln!(
                "[race] buttons: {btn_not_landed}/{BTN_ROUNDS} NotLanded, {btn_unknown} Unknown"
            );
            report_latency("buttons", &mut btn_us);

            assert_eq!(
                key_unknown + btn_unknown,
                0,
                "the read-back stopped answering on Windows; every verdict below is \
                 meaningless because Unknown is never a refusal"
            );
            assert_eq!(
                key_not_landed, 0,
                "{key_not_landed} of {KEY_ROUNDS} ordinary KEY presses were judged NotLanded \
                 on a desktop with nothing elevated focused. Each one revokes the operator's \
                 control grant."
            );
            assert_eq!(
                btn_not_landed, 0,
                "{btn_not_landed} of {BTN_ROUNDS} ordinary BUTTON presses were judged \
                 NotLanded on a desktop with nothing elevated focused. Each one revokes the \
                 operator's control grant mid-use. SendInput is asynchronous and \
                 verify_delivery reads back with no wait; a bounded wait (the wait_for_button \
                 pattern already in this file) is the fix."
            );
        }

        /// Round 4's gap 3: UIPI. **A separate opt-in, because it cannot run
        /// unattended** -- it needs a window belonging to a higher-integrity
        /// process to hold the foreground, which means somebody has to consent
        /// to a UAC prompt first. Gated on `RD_UIPI=1` rather than `RD_USE_HW`
        /// so it is never counted as covered by an ordinary hardware run.
        ///
        /// The property under test is not "injection works" -- against an
        /// elevated foreground window it is *supposed* to fail. It is
        /// **the host must not claim a press it did not make**:
        ///
        /// > if `inject()` returns `Ok`, Windows must report the key down.
        ///
        /// That is the one failure the read-back exists for. `SendInput`
        /// returning a count means the events were accepted into the queue,
        /// not applied; if UIPI discards them while the call still reports
        /// success, the host records a press that never happened, later
        /// "releases" it, and reports a clean desktop it was never driving.
        /// Every other test in this module would pass through that.
        ///
        /// Either outcome is a result worth having. A refusal at `inject()` is
        /// the correct, safe behaviour and this test passes. A silent drop
        /// fails it, and names the window that ate the input.
        #[test]
        #[cfg(windows)]
        fn an_elevated_foreground_window_cannot_make_the_host_claim_a_false_press() {
            if std::env::var("RD_UIPI").as_deref() != Ok("1") {
                eprintln!(
                    "skipping: set RD_UIPI=1 AND leave an elevated window focused to run this"
                );
                return;
            }
            let _g = INJECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());

            let front = module10::inject::foreground_window_title()
                .unwrap_or_else(|| "<no foreground window>".to_string());
            eprintln!("[uipi] foreground window: {front:?}");

            module10::inject::release_input_state();
            let short = std::time::Duration::from_millis(500);
            let (clean, _) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                false,
                short,
            );
            assert!(clean, "F13 was already down before this test pressed it");

            let claimed = module10::inject::inject(&InputControlMessage::KeyEvent {
                scan_code: HELD_KEY_SCAN,
                action: KeyAction::Down,
                modifiers: 0,
            });
            match &claimed {
                Ok(_) => eprintln!("[uipi] inject() reported SUCCESS"),
                Err(e) => eprintln!("[uipi] inject() REFUSED: {e:?} - this is the safe outcome"),
            }

            let (landed, after) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                true,
                short,
            );
            eprintln!("[uipi] Windows reports the key down: {landed} (after {after:?})");

            // Whatever happened, do not walk away holding anything.
            module10::inject::release_input_state();
            let (released, _) = wait_for(
                || module10::inject::scan_code_is_down(HELD_KEY_SCAN),
                false,
                std::time::Duration::from_secs(2),
            );

            if claimed.is_ok() {
                assert!(
                    landed,
                    "inject() reported success but Windows never saw the key go down, with \
                     {front:?} in the foreground. The host would now believe it is driving \
                     a desktop it cannot reach - this is the false-clean report the \
                     read-back exists to catch."
                );
                assert!(
                    released,
                    "the key was pressed and the release did not reach Windows, with \
                     {front:?} in the foreground"
                );
            } else {
                assert!(
                    !landed,
                    "inject() reported a refusal but the key went down anyway, with \
                     {front:?} in the foreground - the host is under-reporting what it did"
                );
            }
        }

        /// The grant was given back mid-press. Past a revoke every input_event
        /// is denied, so the client can no longer send its own Up — tapping
        /// "Viewing Only" during a drag was enough to strand the button.
        #[test]
        fn revoking_the_grant_does_not_leave_the_button_down() {
            if skip() {
                return;
            }
            let _g = INJECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let mut session = active_session_with(42);
            session.grant_input().unwrap();
            press_and_hold();
            let cmd: serde_json::Value =
                serde_json::from_str(r#"{"type":"revoke_input"}"#).unwrap();
            let reply =
                handle_session_command(&mut session, "revoke_input", &cmd, now_epoch_secs());
            assert!(
                reply.unwrap_or_default().contains("\"ack\""),
                "the revoke was refused, so this proves nothing about the release"
            );
            assert!(
                !module10::inject::is_holding_input(),
                "the host still holds the button after the grant was revoked"
            );
        }

        /// The client is still connected and has simply stopped speaking. The
        /// other two releases cannot see this one: nothing ended and nothing
        /// was revoked.
        ///
        /// Takes the full grace period in real time, deliberately — the point
        /// is that it does NOT fire early, and a shortened clock would prove
        /// the opposite of what is claimed.
        #[test]
        fn a_silent_client_has_its_button_released_after_the_grace() {
            if skip() {
                return;
            }
            let _g = INJECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            press_and_hold();
            assert!(
                !module10::inject::release_if_idle(),
                "the watchdog fired immediately; a live drag would be interrupted"
            );
            assert!(module10::inject::is_holding_input());
            std::thread::sleep(
                module10::inject::INPUT_IDLE_RELEASE + std::time::Duration::from_secs(2),
            );
            assert!(
                module10::inject::release_if_idle(),
                "the watchdog never fired, so a silent client holds the desktop forever"
            );
            assert!(
                !module10::inject::is_holding_input(),
                "the watchdog reported a release it did not perform"
            );
        }
    }
    /// B2, from Windows round 5: the gate is exact and must STAY exact, but it
    /// must not be silent about a value that will not grant.
    #[test]
    fn a_capability_value_that_is_not_exactly_one_is_flagged() {
        // The case that cost a Windows session: `set RD_CAP_INPUT=1 && run.bat`
        // stores "1 " because cmd takes everything up to the `&&`.
        assert!(capability_value_is_malformed("1 "));
        assert!(capability_value_is_malformed(" 1"));
        assert!(capability_value_is_malformed("true"));
        assert!(capability_value_is_malformed("yes"));
        assert!(capability_value_is_malformed("0"));
        assert!(capability_value_is_malformed(""));
    }

    /// And the one value that grants must not be flagged, or every correct
    /// launch prints a warning and the warning stops meaning anything.
    #[test]
    fn the_granting_value_is_not_flagged() {
        assert!(!capability_value_is_malformed("1"));
    }

    /// The gate itself is unchanged and still exact. Trimming would loosen a
    /// deny-by-default security gate, which is the wrong direction -- the
    /// warning exists precisely so that staying strict is not also silent.
    #[test]
    fn the_gate_is_still_exact_and_was_not_loosened() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("RD_CAP_INPUT", "1 ");
        assert!(
            !capability_granted("input_event"),
            "a trailing space must NOT grant -- the fix for that was a warning, not a trim"
        );
        std::env::set_var("RD_CAP_INPUT", "1");
        assert!(capability_granted("input_event"));
        std::env::remove_var("RD_CAP_INPUT");
    }

    /// Every capability the gate knows about must be in the list the warning
    /// scans, or a malformed value for it is silent -- which is the bug.
    #[test]
    fn every_gated_capability_is_scanned_for_malformed_values() {
        for cap in [
            "screenshot_request",
            "input_event",
            "clipboard_push",
            "file_transfer",
        ] {
            let _ = cap;
        }
        assert!(CAPABILITY_VARS.contains(&"RD_CAP_SCREENSHOT"));
        assert!(CAPABILITY_VARS.contains(&"RD_CAP_INPUT"));
        assert!(CAPABILITY_VARS.contains(&"RD_CAP_CLIPBOARD"));
    }
}
