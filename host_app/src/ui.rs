//! The host console — what the owner actually sees.
//!
//! Replaces `module25_windows_ui`, which printed
//! `[Module25] Windows UI placeholder active`, ticked
//! `[UI] Event loop maintenance tick` every five seconds, and drew nothing. The
//! previous console reported a state it had not established; this one reports
//! only what the controller told it.
//!
//! ## Rules this file obeys
//!
//! * **It owns no socket, no key, no task handle.** Everything it knows arrives
//!   as a [`HostEvent`]; everything it wants happens by sending a
//!   [`HostCommand`]. There is no shared lock with the controller, which is why
//!   the GUI event loop and the Tokio runtime cannot deadlock each other.
//! * **It shows public fingerprints only.** No token, no private key byte, no
//!   invite payload ever reaches a widget or a log line.
//! * **Start is deliberate.** An interface must be picked; nothing is
//!   preselected, and a wildcard is not offered at all — the controller would
//!   refuse it, and an option the product always refuses should not be a
//!   button.
//!
//! ## Design provenance
//!
//! Explicit Ready/Stopped/Connected state, direct start/stop, a visible peer
//! count and a fingerprint on screen are deliberate choices, not defaults: each
//! one exists so the operator can see what the host is doing without reading a
//! log. This console is original to RemoteDexter.

use crate::input_grant::{self, InputGrantState};
use eframe::egui;
use host_controller::{HostCommand, HostEvent, HostHandle, HostState, Reach};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

/// Default port. LAN-only pairing transport; never expose it publicly.
const DEFAULT_PORT: u16 = 8082;

/// How long the window close is allowed to wait for the host to shut down
/// before the process exits anyway. Bounded on purpose: a host that will not
/// close must not be able to hold the window open, and the OS closes the socket
/// and destroys uinput devices on exit regardless.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// One selectable network interface.
#[derive(Clone, PartialEq, Eq)]
struct Interface {
    name: String,
    ip: IpAddr,
    loopback: bool,
}

impl Interface {
    fn label(&self) -> String {
        if self.loopback {
            format!("{} — {} (this machine only)", self.name, self.ip)
        } else {
            format!("{} — {}", self.name, self.ip)
        }
    }
}

/// The order paired devices are listed in.
///
/// Deliberately total and independent of the store's iteration order, which is
/// a `HashMap`'s and therefore arbitrary between repaints. This panel redraws
/// ten times a second and carries a **Revoke** button: a row that moves under
/// the pointer between the press and the release is a destructive action
/// applied to the wrong device.
///
/// Oldest enrolment first, with the key breaking ties, so two devices enrolled
/// in the same second still order the same way every time.
fn ordered_devices(
    mut records: Vec<pairing::devices::DeviceRecord>,
) -> Vec<pairing::devices::DeviceRecord> {
    records.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then(a.public_key.cmp(&b.public_key))
    });
    records
}

/// Enumerate bindable interfaces.
///
/// Loopback is listed last and labelled, because it is genuinely useful for
/// development and genuinely useless for a phone. IPv6 link-local addresses are
/// dropped: they need a scope id to bind meaningfully and a user cannot supply
/// one from a dropdown.
fn interfaces() -> Vec<Interface> {
    let mut out: Vec<Interface> = Vec::new();
    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for a in addrs {
            let ip = a.ip();
            if let IpAddr::V6(v6) = ip {
                if v6.is_unicast_link_local() {
                    continue;
                }
            }
            out.push(Interface {
                name: a.name.clone(),
                ip,
                loopback: a.is_loopback(),
            });
        }
    }
    out.sort_by_key(|i| (i.loopback, i.ip.to_string()));
    out
}

/// Everything the console knows. Note what is absent: no socket, no key, no
/// handle to anything the controller owns.
struct Console {
    host: HostHandle,
    state: HostState,
    interfaces: Vec<Interface>,
    /// `None` until the user picks one. Nothing is preselected — Start is a
    /// decision, and a preselected interface makes it a reflex.
    selected: Option<usize>,
    port: u16,
    peers: Vec<String>,
    /// Most recent fault, shown until the next state change clears it.
    fault: Option<String>,
    /// Public fingerprint of this host's pinned identity. Public by definition;
    /// it is what the phone checks against and what the owner compares.
    fingerprint: String,
    /// The outstanding pairing invitation, if one has been minted.
    ///
    /// Holds QR modules, not a token string. The console draws them and never
    /// reads them back — the credential exists on screen and in the host's hash
    /// store, and nowhere else in this process.
    invite: Option<host_controller::state::InviteView>,
    /// Cached texture for the QR, rebuilt when the invite changes.
    qr_texture: Option<(String, egui::TextureHandle)>,
    /// Test instrument, armed only by `RD_TEST_REVOKE_TRIGGER`. `None` on any
    /// ordinary run, and nothing below it touches the filesystem when it is.
    test_revoke: Option<TestRevokeTrigger>,
    shutting_down: bool,
    /// Block 6 harness only: an exact IPv4-loopback bind routed through the
    /// same controller commands as the widgets. It cannot name a LAN address.
    startup_bind: Option<SocketAddr>,
    startup_sent: bool,
    startup_invite_sent: bool,
    /// The devices this host has enrolled.
    ///
    /// The console holds the same handle the connection path uses, which is a
    /// deliberate exception to "the console owns nothing the controller owns".
    /// Revocation is a security control: it must bind the moment the owner
    /// clicks, not after a round trip through a command channel that could
    /// leave the UI claiming a device is revoked while it is still connecting.
    /// The lock is held for the length of a small map operation.
    devices: pairing::devices::DeviceHandle,
    /// What is true about `/dev/uinput` right now — see `input_grant`.
    grant: InputGrantState,
    /// Set while an administrator prompt is on screen. Its presence is also
    /// what makes the action single-flight: a second click cannot start a
    /// second pkexec.
    grant_rx: Option<Receiver<InputGrantState>>,
    /// Cheap reconciliation clock. The device is the authority on whether we
    /// can inject, but asking it ten times a second is silly.
    grant_checked: Instant,
    /// Where the stored settings live, so a toggle can write them.
    settings_path: std::path::PathBuf,
    /// The stored settings as last read or written. The session loop reads its
    /// own copy through `settings::granted`; this one is what is drawn.
    settings: crate::settings::Settings,
    /// Why the last settings write failed, if it did. Shown rather than
    /// swallowed: a permission the console shows and the file does not carry
    /// would be a lie after a restart.
    settings_fault: Option<String>,
    /// What this host knows about its relay.
    ///
    /// Not "is dial-out possible in principle" — what THIS process was given.
    /// With no relay the button is absent rather than present and failing,
    /// because a control that cannot work is a control the operator has to test
    /// to understand. With a relay that is configured WRONGLY the reason is
    /// shown, because an absent button and a broken one look identical.
    relay: crate::relay_dial::RelayPlan,
    /// What the operator has typed into the relay address box, which is not yet
    /// what is stored. Seeded from the plan so the common case is one click.
    relay_input: String,
    /// The last retry the controller announced, cleared as soon as the host is
    /// serving. Kept out of `fault`: a relay that is briefly unreachable is an
    /// ordinary event, and showing it in red teaches the operator to ignore red.
    relay_retry: Option<String>,
    /// Why the relay last REFUSED this host, until a new attempt or a
    /// connection makes it history. Distinct from `relay_retry`: a refusal
    /// needs a human and a retry does not, so they are never shown alike.
    relay_refused: Option<String>,
    /// Set once the first-time explanation for dialling on start has been shown
    /// and answered. The explanation is shown BEFORE the setting is written,
    /// never after.
    dial_on_start_prompt: bool,
    /// Whether `dial_on_start` has already fired this run.
    startup_relay_sent: bool,
}

impl Console {
    fn new(
        host: HostHandle,
        fingerprint: String,
        startup_bind: Option<SocketAddr>,
        devices: pairing::devices::DeviceHandle,
        relay: crate::relay_dial::RelayPlan,
        settings_path: std::path::PathBuf,
        settings: crate::settings::Settings,
    ) -> Self {
        let interfaces = interfaces();
        let selected = startup_bind.and_then(|bind| {
            interfaces
                .iter()
                .position(|interface| interface.ip == bind.ip())
        });
        // Seeded from what is in force, stored or not, so an operator running
        // with RD_RELAY can remember that relay with one click instead of
        // retyping an address they have already typed once.
        let relay_input = relay
            .address()
            .map(|a| a.to_string())
            .or_else(|| settings.relay.address.clone())
            .unwrap_or_default();
        Console {
            devices,
            host,
            state: HostState::Stopped,
            interfaces,
            selected,
            port: startup_bind.map_or(DEFAULT_PORT, |bind| bind.port()),
            peers: Vec::new(),
            fault: None,
            fingerprint,
            invite: None,
            qr_texture: None,
            shutting_down: false,
            startup_bind,
            startup_sent: false,
            startup_invite_sent: false,
            grant: input_grant::initial_state(),
            grant_rx: None,
            grant_checked: Instant::now(),
            test_revoke: TestRevokeTrigger::from_env(),
            settings_path,
            settings,
            settings_fault: None,
            relay,
            relay_input,
            relay_retry: None,
            relay_refused: None,
            dial_on_start_prompt: false,
            startup_relay_sent: false,
        }
    }

    /// Allow or revoke a capability: write it down, then show what was written.
    ///
    /// The file is the authority. If the write fails nothing is granted, the
    /// reason is shown, and the console keeps showing the truth.
    fn change_capability(&mut self, cap: crate::settings::Capability, allow: bool) {
        let result = if allow {
            crate::settings::allow(&self.settings_path, cap)
        } else {
            crate::settings::revoke(&self.settings_path, cap)
        };
        self.record_change(result);
    }

    /// Remember a relay address, or forget the one stored.
    fn change_relay_address(&mut self, address: Option<&str>) {
        let result = crate::settings::set_relay_address(&self.settings_path, address);
        let stored_ok = result.is_ok();
        self.record_change(result);
        if stored_ok {
            // The plan is what the console shows everywhere else, and it must
            // not keep describing the address that was there a moment ago. The
            // DIALLER is not rebuilt: the controller holds it, and a relay this
            // host is already dialling is not changed underneath the operator.
            // The new address is what the next run dials.
            self.relay =
                crate::relay_dial::plan(&self.settings.relay, |name| std::env::var(name).ok());
        }
    }

    /// Turn "connect through the relay whenever RemoteDexter starts" on or off.
    fn change_dual_route_codes(&mut self, on: bool) {
        let result = crate::settings::set_dual_route_codes(&self.settings_path, on);
        self.record_change(result);
    }

    fn change_dial_on_start(&mut self, on: bool) {
        let result = crate::settings::set_dial_on_start(&self.settings_path, on);
        self.record_change(result);
    }

    /// Take the outcome of a settings write: refresh what is drawn, or show why
    /// nothing changed.
    ///
    /// The file is the authority. If the write fails nothing is in force, the
    /// reason is shown, and the console keeps showing the truth — a setting the
    /// console displayed and the disk did not carry would be a lie after a
    /// restart, which is exactly the class of bug this file exists to end.
    fn record_change(&mut self, result: Result<(), crate::settings::SaveError>) {
        match result {
            Ok(()) => {
                self.settings = crate::settings::current();
                self.settings_fault = None;
            }
            Err(e) => self.settings_fault = Some(e.message()),
        }
    }

    /// Run one helper action on a thread. The administrator prompt is modal and
    /// can sit there for a minute; the GUI has to keep painting behind it, and
    /// the controller has to keep draining events.
    fn start_grant_action(&mut self, action: input_grant::Action) {
        if self.grant_rx.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(input_grant::run_action(action));
        });
        self.grant_rx = Some(rx);
        self.grant = InputGrantState::Working(action);
    }

    fn drain_grant(&mut self) {
        let settled = match self.grant_rx.as_ref().map(|rx| rx.try_recv()) {
            None | Some(Err(TryRecvError::Empty)) => return,
            Some(Ok(state)) => state,
            // The worker died without answering. Say so rather than leaving a
            // spinner on screen forever.
            Some(Err(TryRecvError::Disconnected)) => {
                InputGrantState::Failed(input_grant::FailureReason::UnreadableOutput)
            }
        };
        self.grant_rx = None;
        self.grant = settled;
        self.grant_checked = Instant::now();
    }

    /// Keep the displayed state honest between actions.
    ///
    /// Access can appear or vanish without RemoteDexter doing anything — a
    /// different seat becomes active, the user signs out and back in and
    /// logind finally applies the ACL, an administrator removes the rule by
    /// hand. The device answers all of those; a remembered success does not.
    fn reconcile_grant(&mut self) {
        if self.grant_rx.is_some() || self.grant_checked.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.grant_checked = Instant::now();
        let writable = input_grant::uinput_is_writable();
        self.grant = match (&self.grant, writable) {
            // Refusals and failures are answers about a specific attempt; the
            // user must see them until they act, not have them cleared by a
            // background poll.
            (InputGrantState::RefusedUnsafe(_), _)
            | (InputGrantState::Failed(_), _)
            | (InputGrantState::Cancelled, _)
            | (InputGrantState::Unsupported(_), _)
            | (InputGrantState::Working(_), _) => return,
            (InputGrantState::NeedsSessionRefresh, false) => return,
            // The rule is gone and the access is not. Hold that statement until
            // the device agrees it is finally gone.
            (InputGrantState::DisabledPendingSignOut, true) => return,
            (InputGrantState::DisabledPendingSignOut, false) => InputGrantState::Disabled,
            (_, true) => InputGrantState::Available,
            (_, false) => InputGrantState::NotEnabled,
        };
    }

    /// Act on the test revoke trigger, if this run armed one.
    ///
    /// Deny-by-default: [`TestRevokeTrigger::from_env`] returns `None` unless
    /// the operator named a path, and on that ordinary path this function
    /// returns without touching the filesystem at all.
    ///
    /// **The file is consumed BEFORE the revoke is attempted.** If it were
    /// removed afterwards, a revoke that failed — or a path that cannot be
    /// deleted — would leave the request in place and re-fire it on the next
    /// poll, four times a second, against a device store that binds
    /// immediately. Losing one deliberate test request is a far smaller cost
    /// than a loop that revokes.
    fn poll_test_revoke_trigger(&mut self) {
        let Some(trigger) = &mut self.test_revoke else {
            return;
        };
        if trigger.last_poll.elapsed() < REVOKE_POLL_INTERVAL {
            return;
        }
        trigger.last_poll = Instant::now();
        let Ok(body) = std::fs::read_to_string(&trigger.path) else {
            return;
        };
        let path = trigger.path.clone();
        if let Err(e) = std::fs::remove_file(&path) {
            // Consume-first failed, so refuse to act: acting now would repeat
            // on every poll for as long as the file is unreadable-but-present.
            eprintln!(
                "[host_app] TEST REVOKE: could not consume {} ({e}); refusing to act on it.",
                path.display()
            );
            return;
        }
        match device_to_revoke(&body, &self.devices.snapshot()) {
            RevokeRequest::Revoke(key) => {
                let short = short_fingerprint(&key);
                let changed = self.devices.revoke(&key, crate::now_epoch_secs());
                eprintln!("[host_app] TEST REVOKE: revoked {short} (store changed: {changed})");
            }
            RevokeRequest::Empty => eprintln!(
                "[host_app] TEST REVOKE: the trigger file was empty — revoking nothing. \
                 Write a device's 8-character fingerprint into it."
            ),
            RevokeRequest::TooShort => eprintln!(
                "[host_app] TEST REVOKE: request too short — give at least the 8 characters \
                 the Paired devices row shows."
            ),
            RevokeRequest::NoMatch => {
                eprintln!("[host_app] TEST REVOKE: no paired device matches that fingerprint.")
            }
            RevokeRequest::Ambiguous(n) => eprintln!(
                "[host_app] TEST REVOKE: {n} paired devices match that fingerprint — \
                 refusing to guess which to cut off."
            ),
            RevokeRequest::AlreadyRevoked => {
                eprintln!("[host_app] TEST REVOKE: that device is already revoked; nothing to do.")
            }
        }
    }

    fn drain_events(&mut self) {
        while let Some(evt) = self.host.try_next_event() {
            // Said out loud before it is drawn. The window is not always where
            // the operator is looking, and a host started from a terminal
            // reports to that terminal.
            if let Some(note) = terminal_note(&evt) {
                eprintln!("[host] {note}");
            }
            if !invite_outlives(&evt) {
                self.invite = None;
                self.qr_texture = None;
            }
            match evt {
                HostEvent::StateChanged(s) => {
                    if !matches!(s, HostState::Error { .. }) {
                        self.fault = None;
                    }
                    // The retry line describes an attempt in progress. Once the
                    // relay is connected, or the host has stopped trying, it is
                    // history — and a stale "retrying" under a live relay would
                    // be the console contradicting itself.
                    if !retry_line_is_current(&s) {
                        self.relay_retry = None;
                    }
                    if s.reach().and_then(|r| r.relay()).is_some() {
                        self.relay_refused = None;
                    }
                    if matches!(s, HostState::Stopped) {
                        self.peers.clear();
                    }
                    self.state = s;
                }
                HostEvent::PeerConnected { peer, .. } => self.peers.push(peer),
                HostEvent::PeerDisconnected { peer, .. } => self.peers.retain(|p| *p != peer),
                HostEvent::InviteReady(view) => self.invite = Some(view),
                // Already cleared above, by `invite_outlives`.
                HostEvent::InviteWithdrawn => {}
                HostEvent::RelayRetrying {
                    attempt,
                    in_seconds,
                    why,
                } => {
                    // Printed by `terminal_note` above, with every other
                    // event worth a line, so there is one place that decides
                    // what the terminal hears.
                    self.relay_retry = Some(relay_retry_line(attempt, in_seconds, &why));
                    self.relay_refused = None;
                }
                HostEvent::RelayRefused { why } => {
                    self.relay_refused = Some(why);
                    self.relay_retry = None;
                }
                HostEvent::Fault { message } => self.fault = Some(message),
            }
        }
    }

    fn selected_addr(&self) -> Option<SocketAddr> {
        let i = self.selected?;
        let iface = self.interfaces.get(i)?;
        Some(SocketAddr::new(iface.ip, self.port))
    }
}

impl eframe::App for Console {
    // eframe 0.36's `App` requires `ui(&mut self, &mut Ui, &mut Frame)`; the
    // older `update(&mut self, &Context, &mut Frame)` was removed. The `Ui`
    // handed in has no margin or background, so the body is wrapped in a
    // central-panel frame here rather than by the runner.
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        self.drain_grant();
        self.reconcile_grant();
        self.poll_test_revoke_trigger();
        // "Connect through the relay whenever RemoteDexter starts", the stored
        // choice. Once per run, and only when the owner has said so: the
        // default is off, and a fresh install dials nothing.
        //
        // Dialling out is not sharing. Nothing is captured, injected or offered
        // by this — the host holds one outbound connection and waits, and a
        // phone still has to pair before anything crosses it.
        if self.settings.relay.dial_on_start
            && !self.startup_relay_sent
            && self.startup_bind.is_none()
            && self.relay.address().is_some()
        {
            let _ = self.host.send(HostCommand::StartViaRelay);
            self.relay_refused = None;
            self.startup_relay_sent = true;
        }
        if let Some(bind) = self.startup_bind {
            if !self.startup_sent {
                let _ = self.host.send(HostCommand::Start { bind });
                self.startup_sent = true;
            } else if !self.startup_invite_sent && self.state.is_listening() {
                let _ = self.host.send(HostCommand::CreateInvite);
                self.startup_invite_sent = true;
            }
        }
        let ctx = root.ctx().clone();
        // Events arrive on the controller thread, so the GUI must wake up to
        // notice them rather than waiting for a mouse move.
        ctx.request_repaint_after(Duration::from_millis(100));

        // Paint the whole viewport first. `Frame::show` sizes itself to its
        // CONTENT, so on a window taller than the console it left everything
        // below the last widget unpainted — which renders as a black slab,
        // because the viewport has no background of its own. Caught in the VM
        // screenshot; it is not visible at all if the window happens to be
        // exactly content-height.
        let style = root.style().clone();
        root.painter()
            .rect_filled(root.max_rect(), 0.0, style.visuals.panel_fill);
        egui::Frame::central_panel(&style).show(root, |ui| {
            // A scroller, because the content is taller than the window on a
            // laptop screen: the pairing QR alone is 220px under a status
            // block, and the operator was resizing the window by hand to see
            // all of it.
            //
            // auto_shrink false on both axes so the area still FILLS the
            // window when the content is short. Left to shrink, it would size
            // itself to its content and leave the rest of the viewport unpainted
            // — the same black slab the explicit rect_filled above exists to
            // prevent, reintroduced one layer in.
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                ui.heading("RemoteDexter — host");
                ui.add_space(4.0);

                // ── status ───────────────────────────────────────────────
                let (dot, detail) = match &self.state {
                    HostState::Stopped => (
                        "\u{25cf} Stopped",
                        "No listener. Nothing is shared.".to_string(),
                    ),
                    HostState::Starting => ("\u{25cf} Starting", "Starting…".to_string()),
                    HostState::Pairable { reach } => (
                        "\u{25cf} Pairable",
                        format!("{} — no device connected", reach_detail(reach)),
                    ),
                    HostState::Connected { reach, peers } => (
                        "\u{25cf} Connected",
                        format!("{} — {peers} device(s) connected", reach_detail(reach)),
                    ),
                    HostState::Stopping => ("\u{25cf} Stopping", "Closing…".to_string()),
                    HostState::Error { message } => ("\u{25cf} Error", message.clone()),
                };
                ui.label(egui::RichText::new(dot).strong());
                ui.label(detail);
                if let Some(line) = relay_line(
                    self.relay.address().is_some(),
                    &self.state,
                    self.relay_retry.as_deref(),
                    self.relay_refused.as_deref(),
                ) {
                    let text = egui::RichText::new(line.text());
                    ui.label(match line {
                        RelayLine::Refused(_) => {
                            text.color(egui::Color32::from_rgb(0xC0, 0x39, 0x2B)).strong()
                        }
                        RelayLine::Reconnecting(_) => {
                            text.color(egui::Color32::from_rgb(0xB5, 0x6A, 0x00))
                        }
                        _ => text,
                    });
                }

                // ── capture health, separate from the connection ─────────
                //
                // Defect C: capture could stop while this panel went on saying
                // "Connected — 1 device(s) connected", because HostState is derived
                // from the listener and the peer count and knows nothing about
                // whether pixels are moving. The phone showed a frozen or black
                // picture and the operator's own screen said all was well, which
                // reads as "the phone is broken" and sends them to the wrong
                // machine.
                //
                // Its own line rather than folded into the state: the session IS
                // connected, and input still works if it was granted. Saying
                // "Error" would be false, and would lose the difference between
                // "nobody connected" and "connected but seeing nothing".
                let peers = match &self.state {
                    HostState::Connected { peers, .. } => *peers,
                    _ => 0,
                };
                if let crate::capture_status::CaptureBanner::Faulted { reason } =
                    crate::capture_status::banner(peers, crate::CAPTURE_FAULT.get().as_deref())
                {
                    ui.label(
                        egui::RichText::new(format!("\u{26a0} Not sharing — {reason}"))
                            .color(egui::Color32::from_rgb(0xC0, 0x39, 0x2B))
                            .strong(),
                    );
                    ui.label("The device is still connected. Press Stop, then Start, to retry.");
                }

                ui.add_space(6.0);
                ui.separator();

                // ── interface selection ──────────────────────────────────
                // Choosable whenever a listener could be started: before
                // anything runs, and beside a relay (P5: the LAN route is added
                // by a click and the host serves both). Not while listening —
                // moving to another interface is Stop listening, then Start.
                let c = controls(&self.state, self.shutting_down);
                // The picker is disabled while listening, so once a
                // pairing code is on screen it is inert furniture competing
                // with the credential for vertical room. Round 10 measured
                // that competition at 1 px/module.
                if !(self.state.is_listening() && self.invite.is_some()) {
                    ui.add_space(6.0);
                    ui.label("Network interface");
                    // Choosable whenever a listener could be started — which
                    // now includes a host serving through the relay.
                    ui.add_enabled_ui(c.start.is_some(), |ui| {
                        let current = self
                            .selected
                            .and_then(|i| self.interfaces.get(i))
                            .map(|i| i.label())
                            .unwrap_or_else(|| "— choose an interface —".to_string());
                        egui::ComboBox::from_id_salt("iface")
                            .selected_text(current)
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                for (i, iface) in self.interfaces.iter().enumerate() {
                                    ui.selectable_value(&mut self.selected, Some(i), iface.label());
                                }
                            });
                        ui.horizontal(|ui| {
                            ui.label("Port");
                            ui.add(egui::DragValue::new(&mut self.port).range(1..=65535));
                        });
                    });
                    ui.small("RemoteDexter binds one interface you choose. It never binds all of them.");
                }

                // ── start / stop ─────────────────────────────────────────
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let can_start = c.start.is_some() && self.selected_addr().is_some();
                    if ui
                        .add_enabled(can_start, egui::Button::new(c.start.unwrap_or("Start host")))
                        .clicked()
                    {
                        if let Some(bind) = self.selected_addr() {
                            let _ = self.host.send(HostCommand::Start { bind });
                        }
                    }
                    // Closes the port and the LAN sessions, and keeps the relay.
                    // Offered only while listening; enabled only beside a relay,
                    // because on its own it would be Stop host under another name.
                    if self.state.is_listening()
                        && ui
                            .add_enabled(c.stop_listening, egui::Button::new("Stop listening"))
                            .on_disabled_hover_text(
                                "The listener is this host's only route — use Stop host.",
                            )
                            .clicked()
                    {
                        let _ = self.host.send(HostCommand::StopListening);
                    }
                    if ui
                        .add_enabled(c.stop, egui::Button::new("Stop host"))
                        .clicked()
                    {
                        let _ = self.host.send(HostCommand::Stop);
                    }
                    // Only shown when a relay is actually usable. Dialling out
                    // BINDS NOTHING: the host opens an outbound connection and
                    // no port is opened here at all.
                    if self.relay.address().is_some() {
                        if ui
                            .add_enabled(
                                c.dial.is_some(),
                                egui::Button::new(c.dial.unwrap_or("Connect via relay")),
                            )
                            .clicked()
                        {
                            let _ = self.host.send(HostCommand::StartViaRelay);
                            self.relay_refused = None;
                        }
                    }
                });
                if c.start.is_some() && self.selected_addr().is_none() {
                    ui.small("Choose an interface to enable Start.");
                }

                // ── relay ────────────────────────────────────────────────
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Relay").strong());
                ui.small(self.relay.summary());
                ui.small(
                    "A relay lets a phone reach this host from anywhere. It carries the session \
                     sealed — it cannot read your screen, your keystrokes or your clipboard.",
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("Address");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.relay_input)
                            .hint_text("203.0.113.9:9443")
                            .desired_width(200.0),
                    );
                });
                ui.horizontal(|ui| {
                    let typed = self.relay_input.trim().to_string();
                    let stored = self.settings.relay.address.clone().unwrap_or_default();
                    let can_remember = !typed.is_empty() && typed != stored;
                    if ui
                        .add_enabled(can_remember, egui::Button::new("Remember this relay"))
                        .clicked()
                    {
                        self.change_relay_address(Some(&typed));
                    }
                    if ui
                        .add_enabled(!stored.is_empty(), egui::Button::new("Forget"))
                        .clicked()
                    {
                        self.relay_input.clear();
                        self.change_relay_address(None);
                    }
                });

                // "Connect on start". Off until the owner says otherwise, and
                // the first time they say it they are told what it means.
                let stored_on = self.settings.relay.dial_on_start;
                let blocked = dial_on_start_blocked(&self.settings.relay, &self.relay);
                let asking = self.dial_on_start_prompt;
                let mut ticked = stored_on;
                let changed = ui
                    .add_enabled(
                        blocked.is_none() && !asking,
                        egui::Checkbox::new(
                            &mut ticked,
                            "Connect through the relay whenever RemoteDexter starts",
                        ),
                    )
                    .changed();
                if changed {
                    if ticked {
                        // Explain BEFORE writing it, never after. The setting
                        // is what makes this machine announce itself to someone
                        // else's server every time it runs.
                        self.dial_on_start_prompt = true;
                    } else {
                        self.change_dial_on_start(false);
                    }
                }
                if let Some(why) = &blocked {
                    ui.small(why);
                } else if stored_on {
                    ui.small(
                        "RemoteDexter connects to the relay when it starts. Nothing is shared \
                         until a phone you have paired connects.",
                    );
                }
                if asking {
                    ui.add_space(4.0);
                    ui.small(
                        "While RemoteDexter runs it will hold an outbound connection to this \
                         relay. The relay's operator can see that this host is online, for how \
                         long, and how many bytes crossed — never what they are. It still shares \
                         nothing: no screen, no input, no clipboard, until a phone you paired \
                         connects and you allow it.",
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Connect on start").clicked() {
                            self.change_dial_on_start(true);
                            self.dial_on_start_prompt = false;
                        }
                        if ui.button("Not now").clicked() {
                            self.dial_on_start_prompt = false;
                        }
                    });
                }

                // ── pairing ──────────────────────────────────────────────
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                // `is_running`, not `is_listening`: both routes can be invited
                // to now. A bound host mints v4 naming its socket; a dialled-out
                // host mints v5 naming the relay and the session it was issued.
                // Neither is derived from the other, and a host still cannot
                // advertise a route it is not on.
                let can_invite = self.state.is_running();
                if ui
                    .add_enabled(can_invite, egui::Button::new("Create pairing QR"))
                    .clicked()
                {
                    let _ = self.host.send(HostCommand::CreateInvite);
                }
                if !can_invite {
                    ui.small("Start the host to create a pairing code.");
                }
                let mut dual = self.settings.pairing.dual_route_codes;
                if ui
                    .checkbox(&mut dual, "Pairing codes carry both routes")
                    .changed()
                {
                    self.change_dual_route_codes(dual);
                }
                ui.small(dual_route_note(dual));
                if let Some(inv) = &self.invite {
                    // Rebuild the texture only when the invite actually changes:
                    // this runs ten times a second.
                    let stale = qr_cache_is_stale(
                        self.qr_texture
                            .as_ref()
                            .map(|(f, _)| (f.as_str(), inv.qr_size)),
                        (inv.token_fingerprint.as_str(), inv.qr_size),
                    );
                    if stale {
                        let px: Vec<egui::Color32> = inv
                            .qr_modules
                            .iter()
                            .map(|d| {
                                if *d {
                                    egui::Color32::BLACK
                                } else {
                                    egui::Color32::WHITE
                                }
                            })
                            .collect();
                        let image = egui::ColorImage {
                            size: [inv.qr_size, inv.qr_size],
                            pixels: px,
                            source_size: egui::vec2(inv.qr_size as f32, inv.qr_size as f32),
                        };
                        let tex = ctx.load_texture("pairing-qr", image, egui::TextureOptions::NEAREST);
                        self.qr_texture = Some((inv.token_fingerprint.clone(), tex));
                    }
                    if let Some((_, tex)) = &self.qr_texture {
                        ui.add_space(6.0);
                        // Room left in the VISIBLE viewport below the cursor,
                        // less the two lines that follow the code. clip_rect is
                        // the visible rectangle; available_height() inside a
                        // ScrollArea describes the scrollable content, which is
                        // exactly the number that let the code run off-screen.
                        const BELOW_THE_CODE: f32 = 56.0;
                        let room = (ui.clip_rect().bottom()
                            - ui.next_widget_position().y
                            - BELOW_THE_CODE)
                            .max(0.0);
                        let side = qr_display_side(inv.qr_size, ui.available_width(), room);
                        ui.add(egui::Image::new(tex).fit_to_exact_size(egui::vec2(side, side)));
                        if !qr_is_scannable(side, inv.qr_size) {
                            // Never let a too-small code look like a working
                            // one. The operator refused to scan a 97px
                            // thumbnail and was right to; without this line the
                            // only signal is that pairing quietly does not work.
                            ui.colored_label(
                                egui::Color32::from_rgb(0xC0, 0x70, 0x20),
                                "Enlarge or maximize the window — this code is too small to scan.",
                            );
                        }
                    }
                    ui.small(format!(
                        "Scan within 60 seconds. Code {} names {} and expires at {}.",
                        inv.token_fingerprint, inv.carries, inv.expires_at
                    ));
                    ui.small(
                        "Anyone who can see this screen can use this code. Press Stop, or \
                         create another, to revoke it.",
                    );
                }

                // These sections stay present while a pairing code is up, and
                // the panel scrolls to reach them.
                //
                // THEY USED TO BE HIDDEN, and the reason was good at the time:
                // Windows round 10 measured the QR at 97x97 -- ONE pixel per
                // module -- because it was fourth in a single scrolling column
                // and got whatever vertical room was left.
                //
                // WINDOWS ROUND 14 FOUND WHAT THAT COST. Hiding the block also
                // hid `Paired devices`, and with it the per-device **Revoke**
                // button -- while the caption six lines above says "Anyone who
                // can see this screen can use this code". The control you reach
                // for when a code has been seen by the wrong person was the one
                // control not on screen. It also made round 14 §C untestable:
                // with Revoke unreachable, no revoke could be issued before the
                // 30-second idle watchdog released the held input instead.
                //
                // Restoring them does NOT re-open the 97x97 defect, and the
                // reason is worth stating rather than trusting: `qr_display_side`
                // is given `room` measured from `ui.clip_rect()` -- the VISIBLE
                // viewport -- minus the cursor's position, and both of those are
                // settled before any of this renders. Nothing placed BELOW the
                // code can shrink it. That is the same distinction the sizing
                // function was rewritten around after round 9: the scrollable
                // content and the visible viewport are different numbers, and
                // the scrollable one is the one that hides the bug.
                //
                // So the code keeps its room and the operator keeps the remedy;
                // what they pay is a scroll to reach the administrative panels
                // while a code happens to be displayed.
                if admin_sections_visible(self.invite.is_some()) {
                    // ── enrolled devices ─────────────────────────────────────
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("Paired devices").strong());
                    let records = self.devices.snapshot();
                    if records.is_empty() {
                        ui.small("None yet. A device is enrolled the first time it pairs with a QR.");
                    } else {
                        // Stable order, so a row does not move under the pointer
                        // between repaints — this panel redraws ten times a second and
                        // it carries a destructive button.
                        for record in ordered_devices(records) {
                            ui.horizontal(|ui| {
                                let short = short_fingerprint(&record.public_key);
                                let name = if record.display_name.is_empty() {
                                    "(unnamed device)".to_string()
                                } else {
                                    record.display_name.clone()
                                };
                                if record.is_revoked() {
                                    ui.label(
                                        egui::RichText::new(format!("\u{2717} {name} — {short}")).weak(),
                                    );
                                    ui.small("revoked");
                                    // Only revoked rows offer this, and that ordering
                                    // is the safety property rather than a UI nicety.
                                    // Removing an ACTIVE record would be a revoke
                                    // without the tombstone, which reopens the race
                                    // the tombstone exists to lose: `enroll` clears a
                                    // revocation, so an enrolment already in flight
                                    // would recreate an identity the owner had just
                                    // withdrawn. Once revoked, the record holds
                                    // history rather than authority — an absent key
                                    // and a revoked key are refused identically.
                                    if ui.small_button("Forget").clicked() {
                                        self.devices.forget(&record.public_key);
                                    }
                                } else {
                                    ui.label(format!("\u{2022} {name} — {short}"));
                                    if ui.button("Revoke").clicked() {
                                        // Binds immediately, on the same store the
                                        // connection path checks.
                                        self.devices
                                            .revoke(&record.public_key, crate::now_epoch_secs());
                                    }
                                }
                            });
                        }
                        // Shown HERE rather than in the general fault line: this
                        // is the moment the operator has just been told a device
                        // is revoked, and it is the moment they need to know the
                        // decision will not survive a restart.
                        if let Some(why) = crate::DEVICE_SAVE_FAULT.get() {
                            ui.colored_label(
                                egui::Color32::from_rgb(0xC0, 0x70, 0x20),
                                format!("\u{26a0} {why}"),
                            );
                        }
                        ui.small(
                            "A revoked device cannot reconnect, and any session it currently \
                             holds is closed. The record is kept, so revoking \
                             cannot be undone by a replayed pairing — only by pairing it again \
                             with a fresh QR. Forget removes the row once you no longer need \
                             the record; the device stays locked out either way.",
                        );
                    }

                    // ── what this host may do ────────────────────────────────
                    // Standing permissions, and the date each was given. A
                    // grant that survives a restart must be visible, and one
                    // click must be enough to take it back.
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("What this host may do").strong());
                    for cap in crate::settings::Capability::ALL {
                        let env_grants = std::env::var(cap.env_var()).as_deref() == Ok("1");
                        let view = crate::settings::grant_view(cap, &self.settings, env_grants);
                        ui.add_space(4.0);
                        ui.label(view.headline);
                        ui.small(view.detail);
                        match view.action {
                            crate::settings::GrantAction::Allow => {
                                if ui.small_button(format!("Allow {}", cap.label().to_lowercase())).clicked() {
                                    self.change_capability(cap, true);
                                }
                            }
                            crate::settings::GrantAction::Revoke => {
                                if ui.small_button("Revoke").clicked() {
                                    self.change_capability(cap, false);
                                }
                            }
                            // Nothing to offer: the variable, not this file,
                            // is what the session loop is reading.
                            crate::settings::GrantAction::EnvironmentHolds => {}
                        }
                    }
                    if let Some(fault) = &self.settings_fault {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xC0, 0x70, 0x20),
                            format!("\u{26a0} settings not saved: {fault}"),
                        );
                    }
                    ui.small(format!("Stored in {}", self.settings_path.display()));

                    // ── input access ─────────────────────────────────────────
                    // The host can stream a screen without this; it cannot move a
                    // pointer without it. Saying which is true is the whole feature.
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(self.grant.headline()).strong());
                    ui.small(self.grant.detail());
                    if !matches!(self.grant, InputGrantState::Unsupported(_)) {
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(self.grant.can_enable(), egui::Button::new("Enable input"))
                                .clicked()
                            {
                                self.start_grant_action(input_grant::Action::Enable);
                            }
                            if ui
                                .add_enabled(self.grant.can_disable(), egui::Button::new("Disable input"))
                                .clicked()
                            {
                                self.start_grant_action(input_grant::Action::Disable);
                            }
                            if self.grant.is_working() {
                                ui.spinner();
                            }
                        });
                        ui.small(
                            "Asks for an administrator password and installs one udev rule. It does not \
                             add you to the 'input' group and never makes /dev/input/event* readable.",
                        );
                    }

                    // ── connected devices ────────────────────────────────────
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("Connected devices").strong());
                    if self.peers.is_empty() {
                        ui.small("None.");
                    } else {
                        for p in &self.peers {
                            ui.horizontal(|ui| {
                                ui.label(format!("\u{25cf} {p}"));
                                if ui.small_button("Disconnect").clicked() {
                                    let _ = self.host.send(HostCommand::RevokePeer { peer: p.clone() });
                                }
                            });
                        }
                    }

                    // ── identity ─────────────────────────────────────────────
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("This host's fingerprint").strong());
                    ui.monospace(&self.fingerprint);
                    ui.small("Public. Compare it with what the phone shows when pairing.");

                    // AGPL-3.0 §13. See SOURCE_URL for why this is an
                    // obligation and not a courtesy.
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.small(LICENCE_NOTICE);
                    ui.hyperlink(SOURCE_URL);

                }

                if let Some(f) = &self.fault {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::from_rgb(200, 90, 60), f);
                }
                });
        });

        // ── window close ─────────────────────────────────────────────
        if ctx.input(|i| i.viewport().close_requested()) && !self.shutting_down {
            self.shutting_down = true;
            // Bounded. If the host will not close in time the process exits
            // anyway and the OS reclaims the socket and the uinput devices.
            let clean = self.host.shutdown_and_join(SHUTDOWN_GRACE);
            if !clean {
                eprintln!(
                    "[host] controller did not exit within {SHUTDOWN_GRACE:?}; \
                     exiting anyway — the OS closes the socket and input devices"
                );
            }
        }
    }
}

/// Open the console. Returns when the window is closed.
pub fn run(
    build_backend: impl FnOnce() -> crate::RdBackend + Send + 'static,
    fingerprint: String,
    startup_bind: Option<SocketAddr>,
    devices: pairing::devices::DeviceHandle,
    settings_path: std::path::PathBuf,
    settings: crate::settings::Settings,
) -> Result<(), eframe::Error> {
    // A relay is configured or it is not, and it is worked out ONCE: the
    // console and the controller must not be able to disagree about whether
    // this host has a relay. When it has none, this is exactly the controller
    // that existed before — `StartViaRelay` is refused because there is no
    // route, rather than silently falling back to binding.
    let relay = crate::relay_dial::RelayDialOut::configure(
        &settings.relay,
        |name| std::env::var(name).ok(),
        crate::host_signing_identity(),
    );
    if let crate::relay_dial::RelayPlan::Unusable { why, .. } = &relay.plan {
        // Said out loud as well as shown. A host launched from the icon with a
        // broken relay is one whose operator is looking at a window, but a host
        // launched from a terminal is one whose operator is looking at a log.
        eprintln!("[host] no relay is usable: {why}");
    }
    let plan = relay.plan.clone();
    let host = match relay.dial_out {
        Some(dial_out) => host_controller::spawn_with_dial_out(build_backend, dial_out),
        None => host_controller::spawn_with(build_backend),
    };
    let options = native_options();
    eframe::run_native(
        "RemoteDexter",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(Console::new(
                host,
                fingerprint,
                startup_bind,
                devices,
                plan,
                settings_path,
                settings,
            )))
        }),
    )
}

/// Parse the isolated Block 6 startup bind.
///
/// This is deliberately narrower than the ordinary interface picker: only
/// exact IPv4 loopback is accepted. The harness reaches it through adb reverse
/// and an SSH local forward, so widening it to a LAN or wildcard address would
/// create an unnecessary listener outside the isolated proof route.
pub fn e2e_loopback_bind(value: Option<&str>) -> Result<Option<SocketAddr>, String> {
    let Some(value) = value else { return Ok(None) };
    let bind: SocketAddr = value
        .parse()
        .map_err(|_| "RD_E2E_LOOPBACK must be 127.0.0.1:<port>".to_string())?;
    if bind.ip() != IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) || bind.port() == 0 {
        return Err("RD_E2E_LOOPBACK accepts only 127.0.0.1 with a nonzero port".to_string());
    }
    Ok(Some(bind))
}

/// The environment variable that arms the test revoke trigger.
///
/// Named for what it is. A reader who finds it set on a machine they did not
/// set it on should be able to tell from the name alone that this run carries a
/// test instrument.
pub(crate) const REVOKE_TRIGGER_VAR: &str = "RD_TEST_REVOKE_TRIGGER";

/// How often the trigger file is looked for. The panel repaints ten times a
/// second and the instrument does not need that.
const REVOKE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Whether an environment value arms the trigger, and with which path.
///
/// Split out from [`TestRevokeTrigger::from_env`] so deny-by-default can be
/// proven without setting a process-global variable — an env-mutating test
/// races every other test in the binary, and the property being proven here is
/// too important to rest on a test that is sometimes right.
///
/// Unset arms nothing. Empty or whitespace arms nothing, which matters because
/// `set RD_TEST_REVOKE_TRIGGER=` is what an operator types to turn it OFF, and
/// a run that treated that as "armed, path empty" would be armed by the very
/// gesture meant to disarm it.
pub(crate) fn armed_path(raw: Option<&str>) -> Option<&str> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
}

/// A file-driven revoke, for the one measurement a person cannot take by hand.
///
/// # Why this exists
///
/// Windows round 14 tried three times to show that a **revoke** releases held
/// input, and could not: the 30-second idle watchdog let go first every time,
/// because the gap between holding a key and a person reaching the Revoke
/// button is longer than 30 seconds. The desktop ended clean each time, so
/// nothing was broken — but the revoke's own release path was never the thing
/// that ran, and round 14 rightly refused to call it proved.
///
/// # Why a file, and not a port or a signal
///
/// A localhost port would be a new network surface on a remote-control host,
/// which is the last place to add one. `SIGUSR1` does not exist on Windows, and
/// Windows is where this has to run. A file is local, needs no new listener,
/// works identically on both platforms, and is trivially drivable from the
/// PowerShell these rounds are already written in.
///
/// # What it can and cannot do
///
/// It can only **revoke**, and revoking is the safe direction: it withdraws
/// access, it can never grant any. It cannot start a session, grant control,
/// reach a host, or read anything. The worst an attacker with write access to
/// the operator's chosen path could achieve is cutting the operator off from
/// their own phone — and they already had local filesystem access.
///
/// It is nonetheless **deny-by-default** (Article XIII.4): unset the variable
/// and this is `None`, no path is stored, and nothing here touches the disk.
struct TestRevokeTrigger {
    path: std::path::PathBuf,
    last_poll: Instant,
}

impl TestRevokeTrigger {
    /// Arm from the environment, loudly, or not at all.
    fn from_env() -> Option<Self> {
        let raw = std::env::var(REVOKE_TRIGGER_VAR).ok();
        let Some(path) = armed_path(raw.as_deref()) else {
            if raw.is_some() {
                eprintln!(
                    "[host_app] {REVOKE_TRIGGER_VAR} is set but empty — no test revoke trigger armed."
                );
            }
            return None;
        };
        // Said loudly and unconditionally. An instrument that can cut a device
        // off must never be quietly present on a run its operator thought was
        // ordinary, and this is the only place that can say so.
        eprintln!("[host_app] TEST INSTRUMENT ARMED: revoke-on-command watching {path}");
        eprintln!(
            "[host_app]   write a paired device's 8-character fingerprint to that file to \
             revoke it. An empty file revokes NOTHING."
        );
        Some(Self {
            path: std::path::PathBuf::from(path),
            last_poll: Instant::now(),
        })
    }
}

/// The short fingerprint shown beside a paired device, and the one a test
/// trigger names.
///
/// One definition, used by the row and by [`device_to_revoke`], so the string an
/// operator reads off the screen is by construction the string the instrument
/// matches. Two copies of "first four bytes as hex" would agree until one of
/// them changed.
pub(crate) fn short_fingerprint(public_key: &[u8; 32]) -> String {
    public_key
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What a test revoke trigger asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RevokeRequest {
    /// Revoke exactly this key.
    Revoke([u8; 32]),
    /// The file was empty. Refuse: an empty request must never mean "all".
    Empty,
    /// Shorter than a displayed fingerprint. Refuse rather than match loosely.
    TooShort,
    /// No paired device matches.
    NoMatch,
    /// More than one matches. Refuse rather than guess which device to cut off.
    Ambiguous(usize),
    /// Already revoked; there is nothing to do and nothing to report as new.
    AlreadyRevoked,
}

/// Which paired device a test revoke trigger names, if any.
///
/// # Why this exists
///
/// Windows round 14 could not prove that a **revoke** releases held input,
/// three attempts running, because the 30-second idle watchdog released it
/// first every time — the window between holding a key and a person reaching
/// the Revoke button is simply longer than 30 seconds. A correct outcome
/// produced by a mechanism other than the one under test proves nothing about
/// the mechanism under test, and round 14 declined to report it as proved.
///
/// The instrument removes the race by making the revoke happen on command. This
/// is the half that can be reasoned about without a filesystem or a GUI.
///
/// # Why it refuses so much
///
/// Revoking cuts a device off, and the record is deliberately not undoable
/// except by pairing again with a fresh QR. So every ambiguous reading is a
/// refusal, not a guess — Article XIII.4, and the same instinct as the
/// capability gate's exact `== "1"`. In particular an EMPTY file never means
/// "revoke everything": the easiest possible accident must be the safest.
///
/// Matching is case-insensitive against the hex of the key, and the request must
/// be at least as long as the eight characters the UI displays.
pub(crate) fn device_to_revoke(
    request: &str,
    records: &[pairing::devices::DeviceRecord],
) -> RevokeRequest {
    let want = request.trim().to_ascii_lowercase();
    if want.is_empty() {
        return RevokeRequest::Empty;
    }
    if want.len() < 8 {
        return RevokeRequest::TooShort;
    }
    let matches: Vec<&pairing::devices::DeviceRecord> = records
        .iter()
        .filter(|r| {
            let full: String = r.public_key.iter().map(|b| format!("{b:02x}")).collect();
            full.starts_with(&want)
        })
        .collect();
    match matches.as_slice() {
        [] => RevokeRequest::NoMatch,
        [one] if one.is_revoked() => RevokeRequest::AlreadyRevoked,
        [one] => RevokeRequest::Revoke(one.public_key),
        many => RevokeRequest::Ambiguous(many.len()),
    }
}

/// Whether the administrative sections render while a pairing code is displayed.
///
/// Split out from the panel so the rule can be proven without an egui context,
/// the same way [`crate::inject::should_release_idle`] is split out from its
/// clock. There is nothing to branch on any more — the answer is always yes —
/// and that is precisely why it is a named function with a test: the previous
/// answer was `!invite_displayed`, it was a deliberate decision, and it cost
/// the operator the Revoke button for four rounds without anyone noticing.
///
/// **Windows round 14, 2026-09-09.** While a code was up the window showed only
/// status, Start/Stop, Create pairing QR and the code itself. `Paired devices`
/// — and its per-device **Revoke** — was absent, along with Network interface,
/// Input access, Connected devices and the fingerprint. Reproduced at 536x679
/// and again maximized at 1456x876 with an empty half-screen beside the code,
/// so it was never a space problem; the panel did not scroll because there was
/// nothing below the fold to scroll to.
///
/// If this is ever made conditional again, the thing to preserve is the
/// remedy's reachability, not the panel's tidiness.
/// What the status line says about how the host is reachable.
///
/// A dialled-out host is NOT listening, and the line must not say it is. The
/// operator's whole question when looking at this app is "what of mine is
/// exposed right now", and "Listening on ..." for a host with no open port
/// answers it wrongly in the direction that matters.
pub(crate) fn reach_detail(reach: &Reach) -> String {
    match reach {
        Reach::Bound(addr) => format!("Listening on {addr}"),
        Reach::ViaRelay { relay, .. } => {
            format!("Reachable through relay {relay} — nothing is listening here")
        }
        Reach::Both { bound, relay, .. } => {
            format!("Listening on {bound}, and reachable through relay {relay}")
        }
    }
}

/// Whether a pairing code on screen is still worth showing after `event`.
///
/// It dies with the host, and with any route it may name: the controller
/// withdraws it when one of a running host's routes goes away. Showing it after
/// either is showing a QR for a port nothing is on, or a session the relay has
/// forgotten.
pub(crate) fn invite_outlives(event: &HostEvent) -> bool {
    !matches!(
        event,
        HostEvent::StateChanged(HostState::Stopped) | HostEvent::InviteWithdrawn
    )
}

pub(crate) fn admin_sections_visible(_invite_displayed: bool) -> bool {
    true
}

/// What the console says while a relay is being retried.
///
/// Says the relay is unreachable and that the host is still trying, in that
/// order, because those are the operator's two questions. It never says the
/// host has failed: it has not, and a line that reads like a failure would have
/// them clicking at a console that is already doing the right thing.
/// What a host launched from a terminal should be told about an event, or
/// `None` when the window is the right and only place for it.
///
/// **Why this exists.** As P3 shipped, a relay that connected said nothing, a
/// relay that REFUSED said nothing — it reached the window alone — and only a
/// retry printed. So the one outcome needing no attention was the only one that
/// spoke, and the operator watching a live start could not tell from stderr
/// whether it had worked. Found by running it, not by the gate.
///
/// Ordinary session traffic stays out: a peer connecting is the window's job,
/// and a line per peer would bury the two lines that matter.
pub(crate) fn terminal_note(event: &HostEvent) -> Option<String> {
    match event {
        HostEvent::StateChanged(HostState::Pairable { reach }) => Some(reach_detail(reach)),
        // Every fault, not just the relay's. A fault is by definition something
        // the operator may have to act on, and the window is not always where
        // they are looking.
        HostEvent::Fault { message } => Some(message.clone()),
        HostEvent::RelayRetrying {
            attempt,
            in_seconds,
            why,
        } => Some(relay_retry_line(*attempt, *in_seconds, why)),
        HostEvent::RelayRefused { why } => Some(relay_refused_line(why)),
        _ => None,
    }
}

/// What the start/stop row offers, decided from the host's state alone.
///
/// A host can now serve the LAN and the relay at once, so each route has its
/// own way on and off: Start adds a listener beside a relay, Connect via relay
/// adds the relay beside a listener, Stop listening closes only the port, and
/// Stop host ends everything. A listener is still only ever opened by a click.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Controls {
    /// The Start button's label when a listener could be started now.
    pub start: Option<&'static str>,
    /// Whether Stop listening would leave the host serving through the relay.
    pub stop_listening: bool,
    /// The relay button's label when a dial could be started now.
    pub dial: Option<&'static str>,
    /// Whether Stop host has anything to stop.
    pub stop: bool,
}

pub(crate) fn controls(state: &HostState, shutting_down: bool) -> Controls {
    let busy = shutting_down || matches!(state, HostState::Stopping);
    let running = state.is_running();
    let starting = matches!(state, HostState::Starting);
    let listening = state.is_listening();
    let relayed = state.reach().and_then(|r| r.relay()).is_some();
    Controls {
        start: (!listening && !busy).then_some(if running {
            "Also listen on this interface"
        } else {
            "Start host"
        }),
        stop_listening: listening && relayed && !busy,
        dial: (!relayed && !starting && !busy).then_some(if running {
            "Also connect via relay"
        } else {
            "Connect via relay"
        }),
        stop: (running || starting) && !busy,
    }
}

/// What the "Pairing codes carry both routes" setting means, in the window.
pub(crate) fn dual_route_note(on: bool) -> &'static str {
    if on {
        "While this host is listening AND connected to the relay, a new code names both, and \
         the phone uses whichever answers first. Only the RemoteDexter app from this release \
         reads it; an older app says the code needs a newer one."
    } else {
        "A code names one route: the relay while it is connected, otherwise the network \
         interface. Every RemoteDexter app reads it."
    }
}

/// What the console says about the relay, in one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayLine {
    /// Connected to this relay.
    Connected(SocketAddr),
    /// A first dial is in progress.
    Connecting,
    /// Unreachable, and being tried again. Carries the retry line.
    Reconnecting(String),
    /// Refused this host; nothing will retry. Carries the relay's reason.
    Refused(String),
    /// Configured, and nothing is connected or in progress.
    NotConnected,
}

impl RelayLine {
    pub(crate) fn text(&self) -> String {
        match self {
            RelayLine::Connected(relay) => format!("Relay: connected to {relay}"),
            RelayLine::Connecting => "Relay: connecting…".to_string(),
            RelayLine::Reconnecting(retry) => retry.clone(),
            RelayLine::Refused(why) => relay_refused_line(why),
            RelayLine::NotConnected => {
                "Relay: not connected — a phone cannot reach this host through it".to_string()
            }
        }
    }
}

/// The relay's one line, or `None` for a host with no relay configured.
///
/// **Reconnecting and refused are never shown alike.** A relay that cannot be
/// reached is being retried and needs nothing from the operator; a relay that
/// refused this host will not be retried and needs a human. Found 2026-09-17:
/// a host lost its relay at 09:32 and the console gave no way to tell which,
/// or that anything had happened.
pub(crate) fn relay_line(
    relay_configured: bool,
    state: &HostState,
    retry: Option<&str>,
    refused: Option<&str>,
) -> Option<RelayLine> {
    if !relay_configured {
        return None;
    }
    if let Some((relay, _)) = state.reach().and_then(|r| r.relay()) {
        return Some(RelayLine::Connected(relay));
    }
    if let Some(why) = refused {
        return Some(RelayLine::Refused(why.to_string()));
    }
    if let Some(retry) = retry {
        return Some(RelayLine::Reconnecting(retry.to_string()));
    }
    if matches!(state, HostState::Starting) {
        return Some(RelayLine::Connecting);
    }
    Some(RelayLine::NotConnected)
}

/// Whether a retry line still describes something in progress after `state`.
///
/// A first dial is `Starting`; a host that lost its relay while listening keeps
/// serving on the LAN, `Pairable` or `Connected` with no relay in its reach,
/// while it dials again. Once the relay is connected, or the host has stopped,
/// the line is history.
pub(crate) fn retry_line_is_current(state: &HostState) -> bool {
    match state {
        HostState::Starting => true,
        s if s.is_running() => s.reach().and_then(|r| r.relay()).is_none(),
        _ => false,
    }
}

pub(crate) fn relay_refused_line(why: &str) -> String {
    format!(
        "Relay refused this host: {why}. It will not be retried — the relay has to accept this \
         host, or the address is wrong."
    )
}

pub(crate) fn relay_retry_line(attempt: u32, in_seconds: u64, why: &str) -> String {
    let again = match in_seconds {
        0 => "trying again now".to_string(),
        1 => "trying again in 1 second".to_string(),
        n => format!("trying again in {n} seconds"),
    };
    format!("Relay unreachable ({why}) — {again}. Attempt {attempt} so far.")
}

/// Why the "connect on start" checkbox cannot be ticked, or `None` when it can.
///
/// Its own function because the reason must be SHOWN. A control that is greyed
/// out with no explanation is one the operator has to experiment on to
/// understand, and the experiment here is "restart the host and see".
pub(crate) fn dial_on_start_blocked(
    stored: &crate::settings::RelaySettings,
    plan: &crate::relay_dial::RelayPlan,
) -> Option<String> {
    match stored.address.as_deref() {
        None => Some(
            "Remember a relay address first — this setting is about the relay this host \
             connects to every time it starts."
                .to_string(),
        ),
        Some(addr) if crate::settings::validated_relay_address(addr).is_err() => Some(format!(
            "The remembered relay address `{addr}` is not an address and port."
        )),
        Some(addr) => match plan {
            // Configured wrongly in a way that is not the address: no
            // credential, say. Ticking a box that cannot work is worse than a
            // greyed one with the reason next to it.
            crate::relay_dial::RelayPlan::Unusable { why, .. } => {
                Some(format!("This host cannot use a relay right now: {why}"))
            }
            // The environment is pointing this run somewhere else. The setting
            // still applies — it is about the REMEMBERED relay — so it is not
            // blocked, and the note below the box says which is which.
            _ => {
                let _ = addr;
                None
            }
        },
    }
}

/// Where the Corresponding Source is published.
///
/// AGPL-3.0 §13 — the clause that distinguishes AGPL from GPL — requires a
/// modified version to "prominently offer all users interacting with it
/// remotely through a computer network" an opportunity to receive the source.
/// RemoteDexter is AGPL-3.0-only, and a phone driving this host over a network
/// is exactly the remote user the clause is about. The notice is surfaced here
/// rather than left implicit: a licence promising source a user cannot find is
/// worth nothing, and every downstream fork is bound by §13.
///
/// That the operator and the phone user are usually the same person does not
/// discharge it: the obligation is about what the software offers, not about
/// who happens to be holding the phone.
///
/// The source lives in the public repository. Each release attaches the
/// allowlist export of its exact commit (`scripts/make-public-export.sh`), with
/// its digest, beside the binaries it corresponds to -- so a user holding any
/// release can fetch the source that built it.
pub const SOURCE_URL: &str = "https://github.com/BaxtersLab/RemoteDexter";

/// The one-line notice shown wherever a user can see it.
pub const LICENCE_NOTICE: &str = "RemoteDexter — AGPL-3.0-only. Source:";

/// The application ID the host's window carries, and the packaged desktop
/// entry's file name (`baxters-remotedexter.desktop`).
///
/// GNOME on Wayland matches a window to its launcher by app_id. eframe sets
/// none unless asked, so the dock could not tell that the host's window belongs
/// to RemoteDexter's desktop entry: a generic icon, and a window detached from
/// the launcher that opened it -- the defect A1 s5 exists to stop. The entry
/// also declares StartupWMClass and Icon by this name, and
/// `the_window_app_id_matches_the_desktop_entry` keeps all of them in step.
pub const APP_ID: &str = "baxters-remotedexter";

/// The host window's options, in one place so the identity it carries can be
/// tested without opening a window.
fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([520.0, 640.0])
            .with_min_inner_size([440.0, 520.0])
            .with_title("RemoteDexter — host")
            .with_app_id(APP_ID),
        ..Default::default()
    }
}

/// The smallest scale a camera has actually paired from on this project's
/// hardware. Windows round 9 paired at 5 and measured 4.22 px/module surviving
/// a bad webcam; round 10 measured 4 px/module maximized, and the operator
/// declined to even attempt 1. Below this the code is a picture of a credential
/// rather than a usable one.
const MIN_SCANNABLE_PX_PER_MODULE: f32 = 4.0;

/// Whether a rendered code is big enough to be worth pointing a camera at.
///
/// WHY THIS IS SEPARATE FROM `qr_display_side`
///
/// Windows round 10 named the gap exactly: the visibility tests "prove
/// visibility but do not protect a minimum scannable scale". Making the code
/// FIT is not the same as making it USABLE, and I had tested only the first.
///
/// Three versions of this feature, each fixing the last and breaking something
/// new: 220 px fixed (2.27 px/module, ragged); width-sized at 600 (5 px/module
/// but 215 of 485 px visible, clipped below the fold); viewport-fitted (fully
/// visible, and 1 px/module at the default window -- a 97 px thumbnail the
/// operator refused to scan).
///
/// So when the room genuinely is not there, SAY SO. A silent thumbnail looks
/// like a working feature and is not one.
fn qr_is_scannable(side: f32, qr_size: usize) -> bool {
    let modules = qr_size.max(1) as f32;
    side / modules >= MIN_SCANNABLE_PX_PER_MODULE
}

/// How many screen pixels wide to draw the pairing QR.
///
/// Windows round 8 measured the rendered code at 206x208 px and counted "~69
/// modules" off the image, giving ~3 px per module. **That module count was
/// wrong** -- 69 modules is QR version 13, whose capacity cannot hold a 522-byte
/// invite at EC level M, and nobody checked the arithmetic before quoting it.
/// Asking the encoder instead (`crates/pairing/tests/qr_density.rs`) gives
/// **97 modules** including the quiet zone, version 18. So the real figure at
/// the old fixed 220.0 was **2.27 px/module**, worse than the 3.19 being
/// quoted, and below the floor a decoder can work with *before* optics. After a lens, an angle, screen glare and a camera pipeline
/// that rescales, it arrives at 1-2. That is why the invite pairs from a 12MP
/// autofocus phone camera and not from a webcam, and why a user on an older
/// phone or in poor light is on the same edge.
///
/// The operator's correction is the one that matters: **the code is not small,
/// the payload is big.** An ordinary URL QR is version 3-6 (29-41 modules) and
/// would get 5-7 px/module at this same physical size. A signed invite v4 needs
/// ~69, which halves it.
///
/// Two things are wrong with a fixed 220.0 and only one is size:
///
/// * **Scale must be a whole number.** 220/69 = 3.19, and the texture is
///   sampled NEAREST, so some modules land 3 px wide and their neighbours 4.
///   A decoder samples module centres on an estimated grid; unevenness moves
///   those centres off. Uniform 3 px beats ragged 3-or-4.
/// * 220 is smaller than the panel usually allows.
///
/// So: the largest whole-number scale that fits, capped so it stays a pairing
/// code rather than a poster, and never below 1 -- a zero would draw nothing.
///
/// **It must fit the VIEWPORT, not just the column.** Windows round 9 found the
/// code rendered 485 px tall with only 215 px visible: it ran off the bottom of
/// the window and was completed only by scrolling. A camera cannot decode a
/// partially visible code, and to a user that reads as "the QR does not work" --
/// with no reason to suspect scrolling. Sizing on width alone caused it, and
/// raising the target from 440 to 600 made it worse, so this was a defect
/// introduced by the fix for the previous defect.
///
/// `height` is the room left in the visible viewport, not in the scrollable
/// content: inside a `ScrollArea` those differ, and the scrollable one is the
/// number that hides the bug.
fn qr_display_side(qr_size: usize, available_width: f32, available_height: f32) -> f32 {
    // 97 modules is what a real invite encodes to. 440 px would give 4
    // px/module; 600 gives 6, which is where an ordinary camera stops
    // struggling. Both dimensions clamp this when the room is not there.
    const TARGET_PX: f32 = 600.0;
    const MIN_SIDE: f32 = 120.0;
    let modules = qr_size.max(1) as f32;
    // NaN propagates through `min`, so fold it out first: an unmeasured
    // dimension must not silently win the comparison.
    let w = if available_width.is_finite() {
        available_width
    } else {
        0.0
    };
    let h = if available_height.is_finite() {
        available_height
    } else {
        0.0
    };
    let budget = w.min(h).clamp(MIN_SIDE, TARGET_PX);
    let scale = (budget / modules).floor().max(1.0);
    scale * modules
}

/// Whether the cached QR image still depicts the current invitation.
///
/// Keyed on the invitation's fingerprint, **not** its pixel size. Two different
/// invitations are almost always the same number of modules, so a size
/// comparison cannot tell them apart: minting a fresh code leaves the cache
/// looking valid and the panel goes on showing the previous, expiring QR while
/// the log correctly reports a new token. Observed on Windows on 2026-08-26 —
/// repeated "Create pairing QR" produced codes the phone rejected as expired
/// until the host was stopped and started, which cleared the cache by dropping
/// the invite.
///
/// The fingerprint is the short non-secret handle `InviteView` already exposes
/// for log correlation; the modules themselves are the token and never leave
/// the widget.
fn qr_cache_is_stale(cached: Option<(&str, usize)>, current: (&str, usize)) -> bool {
    match cached {
        Some((cached_fingerprint, cached_size)) => {
            cached_fingerprint != current.0 || cached_size != current.1
        }
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(key: u8, created: u64) -> pairing::devices::DeviceRecord {
        pairing::devices::DeviceRecord {
            public_key: [key; 32],
            display_name: format!("device {key}"),
            created_at: created,
            last_seen_at: created,
            revoked_at: None,
        }
    }

    fn revoked(key: u8, created: u64) -> pairing::devices::DeviceRecord {
        let mut r = record(key, created);
        r.revoked_at = Some(created + 1);
        r
    }

    /// **The terminal must say whether the relay worked.**
    ///
    /// As P3 shipped it did not: success was silent, a refusal reached only the
    /// window, and a retry was the single thing that printed — so the outcome
    /// needing no attention was the only one that spoke. The operator watched a
    /// live start and could not tell from stderr whether it had connected.
    #[test]
    fn the_terminal_hears_the_relay_connect_and_hears_it_refuse() {
        let relay: SocketAddr = "203.0.113.9:9443".parse().unwrap();
        let connected = terminal_note(&HostEvent::StateChanged(HostState::Pairable {
            reach: Reach::ViaRelay {
                relay,
                session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            },
        }))
        .expect("a host that reached its relay said nothing to the terminal");
        assert!(connected.contains("203.0.113.9:9443"), "{connected}");
        assert!(
            connected.contains("nothing is listening"),
            "the line must still say a dialled-out host binds no port: {connected}"
        );

        let refused = terminal_note(&HostEvent::Fault {
            message: "the relay refused this host: not enrolled".into(),
        })
        .expect("a refused relay said nothing to the terminal");
        assert!(refused.contains("not enrolled"), "{refused}");

        let retrying = terminal_note(&HostEvent::RelayRetrying {
            attempt: 1,
            in_seconds: 1,
            why: "could not reach the relay".into(),
        })
        .expect("a retry said nothing to the terminal");
        assert!(retrying.contains("trying again"), "{retrying}");
    }

    /// **A host serving both routes says both**, and still says it is listening:
    /// the operator's question is what of theirs is exposed, and the answer is
    /// a port AND a relay.
    #[test]
    fn a_host_serving_both_routes_says_it_is_listening_and_relayed() {
        let line = reach_detail(&Reach::Both {
            bound: "192.168.1.20:8082".parse().unwrap(),
            relay: "203.0.113.9:9443".parse().unwrap(),
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        });
        assert!(line.contains("Listening on 192.168.1.20:8082"), "{line}");
        assert!(line.contains("relay 203.0.113.9:9443"), "{line}");
        assert!(
            !line.contains("nothing is listening"),
            "a host with a listener must not say nothing is listening: {line}"
        );
        assert!(
            !line.contains("AAAAAAAAAAAAAAAAAAAAAA"),
            "the session id reached the status line"
        );
    }

    /// **A withdrawn code leaves the screen**, as a stopped host's always did.
    /// A host serving both routes keeps running when one route goes, so
    /// `Stopped` alone no longer covers it.
    #[test]
    fn a_withdrawn_code_or_a_stopped_host_takes_the_code_off_screen() {
        assert!(!invite_outlives(&HostEvent::InviteWithdrawn));
        assert!(!invite_outlives(&HostEvent::StateChanged(
            HostState::Stopped
        )));
        let relay: SocketAddr = "203.0.113.9:9443".parse().unwrap();
        for kept in [
            HostEvent::StateChanged(HostState::Pairable {
                reach: Reach::ViaRelay {
                    relay,
                    session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                },
            }),
            HostEvent::PeerConnected {
                peer: "phone".into(),
                count: 1,
            },
            HostEvent::Fault {
                message: "the relay connection closed — reconnecting".into(),
            },
        ] {
            assert!(invite_outlives(&kept), "{kept:?} took the code off screen");
        }
    }

    /// **Each route has its own way on and off**, and a listener is still only
    /// ever opened by a click: Start adds one beside a relay, Connect via relay
    /// adds the relay beside a listener, Stop listening closes only the port —
    /// and only where that leaves the host serving — and Stop host ends it all.
    #[test]
    fn each_route_can_be_added_and_closed_on_its_own() {
        let relay: SocketAddr = "203.0.113.9:9443".parse().unwrap();
        let bound: SocketAddr = "192.168.1.20:8082".parse().unwrap();
        let session = "AAAAAAAAAAAAAAAAAAAAAA".to_string();

        assert_eq!(
            controls(&HostState::Stopped, false),
            Controls {
                start: Some("Start host"),
                stop_listening: false,
                dial: Some("Connect via relay"),
                stop: false,
            }
        );

        let relay_only = controls(
            &HostState::Pairable {
                reach: Reach::ViaRelay {
                    relay,
                    session: session.clone(),
                },
            },
            false,
        );
        assert_eq!(relay_only.start, Some("Also listen on this interface"));
        assert_eq!(
            relay_only.dial, None,
            "a second relay connection was offered"
        );
        assert!(!relay_only.stop_listening, "nothing is listening");
        assert!(relay_only.stop);

        let lan_only = controls(
            &HostState::Pairable {
                reach: Reach::Bound(bound),
            },
            false,
        );
        assert_eq!(
            lan_only.start, None,
            "moving interface is Stop listening, then Start"
        );
        assert_eq!(lan_only.dial, Some("Also connect via relay"));
        assert!(
            !lan_only.stop_listening,
            "Stop listening on the only route would be Stop host under another name"
        );

        let both = HostState::Connected {
            reach: Reach::Both {
                bound,
                relay,
                session,
            },
            peers: 1,
        };
        let serving_both = controls(&both, false);
        assert_eq!(serving_both.start, None);
        assert_eq!(serving_both.dial, None);
        assert!(serving_both.stop_listening);
        assert!(serving_both.stop);

        let dialling = controls(&HostState::Starting, false);
        assert_eq!(
            dialling.start,
            Some("Start host"),
            "a listener may be started while the relay is still dialling"
        );
        assert_eq!(dialling.dial, None, "a dial is already under way");
        assert!(dialling.stop, "a dial in progress must be stoppable");

        let nothing = Controls {
            start: None,
            stop_listening: false,
            dial: None,
            stop: false,
        };
        assert_eq!(controls(&HostState::Stopping, false), nothing);
        assert_eq!(controls(&both, true), nothing, "the window is closing");
    }

    /// The code-format setting says what turning it on costs, and what off means.
    #[test]
    fn the_code_format_setting_says_what_it_costs() {
        assert!(dual_route_note(true).contains("from this release"));
        assert!(dual_route_note(true).contains("whichever answers first"));
        assert!(dual_route_note(false).contains("Every RemoteDexter app"));
    }

    /// **Reconnecting and refused never read alike** — found 2026-09-17, when a
    /// host lost its relay and the console could not say whether it would come
    /// back or needed a human. One line, five answers.
    #[test]
    fn the_relay_line_tells_connected_reconnecting_refused_and_not_connected_apart() {
        let relay: SocketAddr = "203.0.113.9:9443".parse().unwrap();
        let session = "AAAAAAAAAAAAAAAAAAAAAA".to_string();
        let via = HostState::Pairable {
            reach: Reach::ViaRelay {
                relay,
                session: session.clone(),
            },
        };
        let lan = HostState::Pairable {
            reach: Reach::Bound("192.168.1.20:8082".parse().unwrap()),
        };
        let retry = relay_retry_line(2, 1, "the relay connection closed");

        assert_eq!(
            relay_line(false, &via, None, None),
            None,
            "no relay, no relay line"
        );
        assert_eq!(
            relay_line(true, &via, Some(&retry), Some("stale")),
            Some(RelayLine::Connected(relay)),
            "a connected relay outranks anything left over"
        );
        assert_eq!(
            relay_line(true, &HostState::Starting, None, None),
            Some(RelayLine::Connecting)
        );
        assert_eq!(
            relay_line(true, &HostState::Starting, Some(&retry), None),
            Some(RelayLine::Reconnecting(retry.clone()))
        );
        assert_eq!(
            relay_line(true, &lan, Some(&retry), None),
            Some(RelayLine::Reconnecting(retry.clone())),
            "a host still listening while it re-dials its relay"
        );
        let refused = relay_line(
            true,
            &HostState::Error {
                message: "x".into(),
            },
            None,
            Some("the relay refused this host: not enrolled"),
        )
        .unwrap();
        assert_eq!(
            refused,
            RelayLine::Refused("the relay refused this host: not enrolled".into())
        );
        assert_eq!(
            relay_line(true, &HostState::Stopped, None, None),
            Some(RelayLine::NotConnected)
        );

        let refused_text = refused.text();
        let retry_text = RelayLine::Reconnecting(retry).text();
        assert!(refused_text.contains("not enrolled"), "{refused_text}");
        assert!(
            refused_text.contains("will not be retried"),
            "{refused_text}"
        );
        assert!(retry_text.contains("trying again"), "{retry_text}");
        assert!(
            !refused_text.contains("trying again") && !retry_text.contains("refused"),
            "the two lines say the same kind of thing: {refused_text} / {retry_text}"
        );
        assert!(
            !RelayLine::Connected(relay).text().contains(&session),
            "the session id reached the status line"
        );
    }

    /// A retry line lasts exactly as long as a dial is under way: through a
    /// first connect, and while a listening host re-dials a relay it lost.
    #[test]
    fn a_retry_line_lasts_while_the_relay_is_being_dialled_and_no_longer() {
        let relay: SocketAddr = "203.0.113.9:9443".parse().unwrap();
        let bound: SocketAddr = "192.168.1.20:8082".parse().unwrap();
        let session = "AAAAAAAAAAAAAAAAAAAAAA".to_string();
        assert!(retry_line_is_current(&HostState::Starting));
        assert!(retry_line_is_current(&HostState::Pairable {
            reach: Reach::Bound(bound)
        }));
        assert!(retry_line_is_current(&HostState::Connected {
            reach: Reach::Bound(bound),
            peers: 1
        }));
        for over in [
            HostState::Pairable {
                reach: Reach::ViaRelay {
                    relay,
                    session: session.clone(),
                },
            },
            HostState::Connected {
                reach: Reach::Both {
                    bound,
                    relay,
                    session,
                },
                peers: 1,
            },
            HostState::Stopped,
            HostState::Stopping,
            HostState::Error {
                message: "x".into(),
            },
        ] {
            assert!(
                !retry_line_is_current(&over),
                "{over:?} kept a stale retry line"
            );
        }
    }

    /// The terminal hears a refusal as a refusal, not as one more retry.
    #[test]
    fn the_terminal_hears_a_refusal_as_a_refusal() {
        let line = terminal_note(&HostEvent::RelayRefused {
            why: "the relay refused this host: not enrolled".into(),
        })
        .expect("a refusal said nothing to the terminal");
        assert!(line.contains("not enrolled"), "{line}");
        assert!(line.contains("will not be retried"), "{line}");
    }

    /// Ordinary session traffic stays out of the terminal. A line per peer
    /// would bury the lines that matter under the ones that do not.
    #[test]
    fn the_terminal_is_not_told_about_every_peer() {
        for quiet in [
            HostEvent::PeerConnected {
                peer: "phone".into(),
                count: 1,
            },
            HostEvent::PeerDisconnected {
                peer: "phone".into(),
                count: 0,
            },
            HostEvent::StateChanged(HostState::Starting),
            HostEvent::StateChanged(HostState::Stopped),
        ] {
            assert_eq!(
                terminal_note(&quiet),
                None,
                "the terminal was told about {quiet:?}"
            );
        }
    }

    /// **A retry says the host is still trying.**
    ///
    /// The relay being briefly unreachable is an ordinary event on a laptop,
    /// and the line the operator reads must not sound like a failure they have
    /// to act on — or they learn to ignore the lines that are.
    #[test]
    fn a_relay_retry_says_what_is_wrong_and_that_it_is_still_trying() {
        let line = relay_retry_line(1, 1, "could not reach the relay: connection refused");
        assert!(line.contains("trying again in 1 second"), "{line}");
        assert!(line.contains("connection refused"), "{line}");
        assert!(
            !line.to_lowercase().contains("failed"),
            "a retry in progress was described as a failure: {line}"
        );
        assert!(
            relay_retry_line(4, 8, "x").contains("trying again in 8 seconds"),
            "the plural second is wrong"
        );
        assert!(
            relay_retry_line(1, 0, "x").contains("trying again now"),
            "a zero wait was rendered as `in 0 seconds`"
        );
    }

    /// **A greyed-out checkbox always says why.**
    ///
    /// Without the reason, the only way for the operator to find out why they
    /// cannot tick it is to experiment on a live host.
    #[test]
    fn connect_on_start_explains_why_it_cannot_be_ticked() {
        use crate::relay_dial::{Origin, RelayPlan};
        let none = crate::settings::RelaySettings::default();
        let blocked = dial_on_start_blocked(&none, &RelayPlan::Unset)
            .expect("connect-on-start was offered with no relay remembered");
        assert!(blocked.contains("Remember a relay address"), "{blocked}");

        let stored = crate::settings::RelaySettings {
            address: Some("203.0.113.9:9443".to_string()),
            ..Default::default()
        };
        assert_eq!(
            dial_on_start_blocked(
                &stored,
                &RelayPlan::Dial {
                    relay: "203.0.113.9:9443".parse().unwrap(),
                    origin: Origin::Stored
                }
            ),
            None,
            "a remembered, usable relay did not allow connect-on-start"
        );

        // A relay this run cannot use: the box would tick and do nothing.
        let unusable = dial_on_start_blocked(
            &stored,
            &RelayPlan::Unusable {
                origin: Origin::Stored,
                why: "there is no signing identity".to_string(),
            },
        )
        .expect("connect-on-start was offered for a relay this host cannot use");
        assert!(unusable.contains("signing identity"), "{unusable}");

        // A remembered address that is not an address at all — hand-edited into
        // the file, which is a thing an owner is invited to do.
        let bad = crate::settings::RelaySettings {
            address: Some("relay.example.com:9443".to_string()),
            ..Default::default()
        };
        let named = dial_on_start_blocked(&bad, &RelayPlan::Unset)
            .expect("connect-on-start was offered for an address that is not one");
        assert!(named.contains("relay.example.com:9443"), "{named}");
    }

    /// The instrument is absent unless it is asked for.
    ///
    /// This is the deny-by-default half. An ordinary run — an operator who has
    /// never heard of this variable — must not poll, must not read a file, and
    /// must not be able to revoke anything by accident.
    #[test]
    fn the_revoke_trigger_is_absent_unless_asked_for() {
        assert_eq!(
            armed_path(None),
            None,
            "an unset variable armed the instrument"
        );
        for blank in ["", " ", "\t", "\n", "   \r\n"] {
            assert_eq!(
                armed_path(Some(blank)),
                None,
                "a blank value ({blank:?}) armed the instrument — and that is what an \
                 operator types to turn it off"
            );
        }
    }

    #[test]
    fn an_armed_path_is_taken_without_the_shells_whitespace() {
        assert_eq!(armed_path(Some("rd-revoke")), Some("rd-revoke"));
        assert_eq!(armed_path(Some("  rd-revoke \n")), Some("rd-revoke"));
        // Backslashes, because Windows is where this instrument has to run —
        // but NO drive letter. Article XI: a drive letter in source is a
        // portability defect even inside a test, and the letter was never the
        // subject here. What is being proven is that the shell's whitespace
        // comes off and nothing else is touched.
        assert_eq!(armed_path(Some(r"rd\revoke.txt")), Some(r"rd\revoke.txt"));
    }

    /// The trigger names a device by the fingerprint the screen shows.
    #[test]
    fn a_named_device_is_the_one_revoked() {
        let a = record(0x11, 100);
        let b = record(0x22, 100);
        let want = short_fingerprint(&b.public_key);
        assert_eq!(
            device_to_revoke(&want, &[a, b.clone()]),
            RevokeRequest::Revoke(b.public_key)
        );
    }

    /// The instrument matches what the operator can actually read off the row.
    #[test]
    fn the_trigger_matches_the_fingerprint_the_ui_displays() {
        let r = record(0xab, 1);
        assert_eq!(short_fingerprint(&r.public_key).len(), 8);
        assert_eq!(
            device_to_revoke(&short_fingerprint(&r.public_key), &[r.clone()]),
            RevokeRequest::Revoke(r.public_key)
        );
    }

    /// AN EMPTY FILE MUST NEVER MEAN "ALL".
    ///
    /// `echo > trigger` and a stray `touch` are the two easiest accidents
    /// available, and revoking every paired device cuts the operator off from
    /// their own machine with no undo short of pairing each one again.
    #[test]
    fn an_empty_trigger_revokes_nothing() {
        let a = record(1, 1);
        let b = record(2, 1);
        for empty in ["", "   ", "\n", "\t \n"] {
            assert_eq!(
                device_to_revoke(empty, &[a.clone(), b.clone()]),
                RevokeRequest::Empty,
                "an empty trigger ({empty:?}) asked for a revoke"
            );
        }
    }

    /// A short request could match several devices; refuse rather than guess.
    #[test]
    fn a_request_shorter_than_the_displayed_fingerprint_is_refused() {
        let r = record(0xcd, 1);
        assert_eq!(
            device_to_revoke("cd", &[r.clone()]),
            RevokeRequest::TooShort
        );
        assert_eq!(device_to_revoke("cdcdcdc", &[r]), RevokeRequest::TooShort);
    }

    /// Two devices sharing a prefix must not be resolved by picking one.
    #[test]
    fn an_ambiguous_request_refuses_rather_than_choosing() {
        // Same first four bytes, so the displayed fingerprints are identical.
        let mut a = record(0x77, 1);
        let mut b = record(0x77, 2);
        a.public_key[31] = 1;
        b.public_key[31] = 2;
        assert_eq!(
            device_to_revoke(&short_fingerprint(&a.public_key), &[a, b]),
            RevokeRequest::Ambiguous(2)
        );
    }

    #[test]
    fn an_unknown_fingerprint_matches_nothing() {
        let r = record(1, 1);
        assert_eq!(device_to_revoke("deadbeef", &[r]), RevokeRequest::NoMatch);
    }

    /// Re-firing the trigger must not report a fresh revoke.
    #[test]
    fn an_already_revoked_device_is_reported_as_such() {
        let r = revoked(0x5a, 1);
        assert_eq!(
            device_to_revoke(&short_fingerprint(&r.public_key), &[r]),
            RevokeRequest::AlreadyRevoked
        );
    }

    /// Case and stray whitespace are what a shell redirect actually produces.
    #[test]
    fn the_request_survives_the_shell_that_wrote_it() {
        let r = record(0xbe, 1);
        let want = short_fingerprint(&r.public_key).to_ascii_uppercase();
        assert_eq!(
            device_to_revoke(&format!("  {want}\r\n"), &[r.clone()]),
            RevokeRequest::Revoke(r.public_key)
        );
    }

    /// The Revoke button must be reachable while a pairing code is on screen.
    ///
    /// Windows round 14 found it was not: the whole administrative block,
    /// `Paired devices` included, was hidden whenever an invite was displayed —
    /// while the caption under the code reads "Anyone who can see this screen
    /// can use this code". Revoking is exactly what that caption's reader
    /// reaches for, and the control was off screen.
    ///
    /// It also blocked round 14 §C: with no reachable Revoke, the 30-second
    /// idle watchdog released held input before any revoke could, three
    /// attempts running, so the revoke's own release path stayed unexercised.
    #[test]
    fn the_admin_sections_are_shown_even_while_a_pairing_code_is_displayed() {
        assert!(
            admin_sections_visible(true),
            "a pairing code is displayed and the Paired devices section — with \
             the per-device Revoke — is hidden again. That is Windows round 14 §G."
        );
        assert!(admin_sections_visible(false));
    }

    /// A destructive button beside a row that can move is a bug waiting for a
    /// mistimed click.
    #[test]
    fn the_device_list_order_does_not_depend_on_map_order() {
        let a = record(1, 100);
        let b = record(2, 50);
        let c = record(3, 100);

        let one = ordered_devices(vec![a.clone(), b.clone(), c.clone()]);
        let two = ordered_devices(vec![c, a, b]);
        assert_eq!(
            one.iter().map(|r| r.public_key[0]).collect::<Vec<_>>(),
            two.iter().map(|r| r.public_key[0]).collect::<Vec<_>>(),
            "the same devices must list in the same order however they arrive"
        );
        assert_eq!(one[0].created_at, 50, "oldest enrolment first");
        assert_eq!(
            (one[1].public_key[0], one[2].public_key[0]),
            (1, 3),
            "a tie on enrolment time must break on the key, not on chance"
        );
    }

    #[test]
    fn an_empty_device_list_orders_to_nothing() {
        assert!(ordered_devices(vec![]).is_empty());
    }

    /// The picker must never offer a wildcard. The controller would refuse it,
    /// and an option the product always refuses should not be presented.
    #[test]
    fn no_enumerated_interface_is_a_wildcard() {
        for iface in interfaces() {
            match iface.ip {
                IpAddr::V4(v4) => assert!(!v4.is_unspecified(), "{} is a wildcard", iface.name),
                IpAddr::V6(v6) => assert!(!v6.is_unspecified(), "{} is a wildcard", iface.name),
            }
            assert!(
                host_controller::validate_bind(SocketAddr::new(iface.ip, DEFAULT_PORT)).is_ok(),
                "the console offered {} which the controller would refuse",
                iface.label()
            );
        }
    }

    /// Loopback sorts last, so the first entry a user sees is one a phone could
    /// actually reach.
    #[test]
    fn loopback_is_offered_but_ranked_last() {
        let ifaces = interfaces();
        if ifaces.iter().any(|i| !i.loopback) {
            let first_loopback = ifaces.iter().position(|i| i.loopback);
            let last_routable = ifaces.iter().rposition(|i| !i.loopback);
            if let (Some(fl), Some(lr)) = (first_loopback, last_routable) {
                assert!(fl > lr, "loopback must sort after routable interfaces");
            }
        }
        assert!(
            ifaces.iter().any(|i| i.loopback),
            "loopback must still be offered — it is how the host is developed"
        );
    }

    #[test]
    fn e2e_loopback_accepts_exact_ipv4_loopback() {
        assert_eq!(
            e2e_loopback_bind(Some("127.0.0.1:8082")),
            Ok(Some("127.0.0.1:8082".parse().unwrap()))
        );
        assert_eq!(e2e_loopback_bind(None), Ok(None));
    }

    #[test]
    fn e2e_loopback_rejects_lan_wildcard_and_ipv6() {
        for value in ["10.0.2.15:8082", "0.0.0.0:8082", "[::1]:8082"] {
            assert!(e2e_loopback_bind(Some(value)).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn e2e_loopback_rejects_malformed_and_zero_port() {
        for value in ["127.0.0.1", "localhost:8082", "127.0.0.1:0"] {
            assert!(e2e_loopback_bind(Some(value)).is_err(), "accepted {value}");
        }
    }

    /// A freshly minted invitation is a different code even when it renders to
    /// the same number of modules — which it almost always does. Comparing size
    /// alone leaves the previous QR on screen after Create pairing QR, so the
    /// operator scans an expiring code and the phone rejects it.
    ///
    /// Observed on Windows 2026-08-26; cleared only by stopping and starting the
    /// host, which drops the invite and with it the cache.

    #[test]
    fn the_e2e_hook_cannot_open_a_listener_off_the_loopback() {
        // The one property that makes an autostart hook safe to ship: it can
        // bind 127.0.0.1 and nothing else. If it accepted a routable address it
        // would be a way to start a network listener with no operator present,
        // bypassing the deliberate act that Start is meant to be — and it is an
        // ENVIRONMENT VARIABLE, so anything that can set one could use it.
        //
        // Windows round 8 verified this by reading the code, and found nothing
        // pinning it. Nothing did. A convenience edit ("allow the LAN for a
        // quick test") would have passed every gate this project has.
        for hostile in [
            "0.0.0.0:8082",      // every interface
            "192.168.1.20:8082", // a real LAN address
            "[::1]:8082",        // v6 loopback is still not 127.0.0.1
            "127.0.0.1:0",       // port 0 asks the OS to choose
            "10.0.0.7:9100",
            "255.255.255.255:8082",
            "example.com:8082",
            "8082",
            "",
        ] {
            assert!(
                e2e_loopback_bind(Some(hostile)).is_err(),
                "RD_E2E_LOOPBACK accepted {hostile:?} — that is a network \
                 listener started without the operator"
            );
        }
    }

    #[test]
    fn the_e2e_hook_is_absent_unless_asked_for() {
        // Unset must mean unset: `startup_bind` is the only thing that
        // auto-starts the host, so a default of Some(..) would make every
        // launch start listening on its own.
        assert_eq!(e2e_loopback_bind(None), Ok(None));
        assert_eq!(
            e2e_loopback_bind(Some("127.0.0.1:8082")),
            Ok(Some("127.0.0.1:8082".parse().unwrap()))
        );
    }

    #[test]
    fn the_qr_is_drawn_at_a_whole_number_of_pixels_per_module() {
        // The defect this guards: 220.0 / 69 modules = 3.19 px each, sampled
        // NEAREST, so modules come out 3 px and 4 px alternately and a decoder
        // reading module centres finds them displaced.
        // 97 is the real one; the others bracket it.
        for qr_size in [21usize, 25, 41, 57, 77, 97, 105] {
            for available in [130.0f32, 240.0, 300.0, 500.0, 700.0, 4000.0] {
                let side = qr_display_side(qr_size, available, available);
                let per_module = side / qr_size as f32;
                assert_eq!(
                    per_module.fract(),
                    0.0,
                    "qr_size {qr_size} at {available}px gave {per_module} px/module — \
                     a fractional scale makes neighbouring modules different widths"
                );
                assert!(per_module >= 1.0, "never draw a sub-pixel module");
            }
        }
    }

    #[test]
    fn a_dense_invite_still_gets_more_pixels_per_module_than_it_used_to() {
        // 97 modules is what a signed invite v4 ACTUALLY produces, measured
        // from the encoder in crates/pairing/tests/qr_density.rs. This test
        // previously used 69 -- a figure counted off a photograph that is
        // arithmetically impossible for this payload -- and so it was passing
        // against a case that cannot occur.
        const REAL_MODULES: f32 = 97.0;
        let side = qr_display_side(REAL_MODULES as usize, 800.0, 800.0);
        let per_module = side / REAL_MODULES;
        assert!(
            per_module >= 6.0,
            "a 97-module invite got {per_module} px/module. The old fixed 220.0 \
             gave it 2.27, and the measured failure was at 2-3 BEFORE optics — \
             a decoder wants 3-4 AT THE SENSOR, after a lens, an angle, glare \
             and a rescaling camera pipeline."
        );
    }

    #[test]
    fn the_source_offer_is_reachable_and_is_not_a_placeholder() {
        // AGPL-3.0 §13 is a LICENCE OBLIGATION, not a nicety: a modified AGPL
        // work must prominently offer its source to users interacting with it
        // over a network. RemoteDexter is AGPL-3.0-only and the phone is that
        // remote user.
        //
        // Until 2026-09-04 neither the host console nor the client surfaced any
        // licence notice at all. This test exists so that stops being possible
        // to lose quietly — a UI tidy-up that deletes the line is a licence
        // violation, and nothing else in the suite would notice.
        assert!(
            SOURCE_URL.starts_with("https://"),
            "the source offer must be fetchable over TLS: {SOURCE_URL}"
        );
        assert!(
            !SOURCE_URL.contains("example.")
                && !SOURCE_URL.contains("localhost")
                && !SOURCE_URL.contains("<"),
            "SOURCE_URL is still a placeholder: {SOURCE_URL}"
        );
        assert!(
            LICENCE_NOTICE.contains("AGPL-3.0"),
            "the notice must name the licence: {LICENCE_NOTICE}"
        );
    }

    #[test]
    fn the_client_and_the_host_offer_the_same_source_address() {
        // Two artifacts, one obligation. If they drift, one of them is telling
        // a user to look somewhere the source is not — and the client's copy is
        // the load-bearing one, because the phone user is the remote user §13
        // is about.
        let strings = include_str!("../../apk/app/src/main/res/values/strings.xml");
        assert!(
            strings.contains(SOURCE_URL),
            "the Android client does not carry {SOURCE_URL}; the two notices have drifted"
        );
        assert!(
            strings.contains("licence_notice"),
            "the Android client has no licence notice string"
        );

        let layout = include_str!("../../apk/app/src/main/res/layout/activity_settings.xml");
        assert!(
            layout.contains("txtLicenceSource"),
            "the notice string exists but the settings screen never shows it — \
             an offer nobody can read is not an offer"
        );
    }

    /// The window, the desktop entry the package installs, and the icon it
    /// ships must all answer to one name, or GNOME shows the host as a generic
    /// window detached from its launcher. Checked against the files that ship,
    /// not against a copy of them.
    #[test]
    fn the_window_app_id_matches_the_desktop_entry() {
        assert_eq!(
            native_options().viewport.app_id.as_deref(),
            Some(APP_ID),
            "the host window does not carry the app_id its desktop entry is named for"
        );

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let desktop_src = root.join(format!("packaging/linux/{APP_ID}.desktop"));
        let desktop = std::fs::read_to_string(&desktop_src).unwrap_or_else(|e| {
            panic!(
                "no desktop entry named for the app_id at {}: {e}",
                desktop_src.display()
            )
        });
        let field = |key: &str| {
            desktop
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .unwrap_or_else(|| panic!("the desktop entry has no {key}"))
                .trim()
                .to_string()
        };
        assert_eq!(
            field("StartupWMClass="),
            APP_ID,
            "StartupWMClass must be the app_id"
        );
        assert_eq!(
            field("Icon="),
            APP_ID,
            "the icon must be the one the package ships"
        );

        // GNOME matches app_id to the INSTALLED desktop file's name, so the
        // package must install the entry under exactly that name.
        let build_deb = std::fs::read_to_string(root.join("scripts/build-deb.sh")).unwrap();
        assert!(
            build_deb.contains(&format!(
                "\"$PKGDIR/usr/share/applications/{APP_ID}.desktop\""
            )),
            "scripts/build-deb.sh does not install the desktop entry as {APP_ID}.desktop"
        );
        assert!(
            build_deb.contains(&format!("apps/{APP_ID}.png")),
            "scripts/build-deb.sh does not install an icon named {APP_ID}"
        );
    }

    #[test]
    fn a_code_too_small_to_scan_is_reported_as_such() {
        // WINDOWS ROUND 10, and the gap they named: the visibility tests
        // "prove visibility but do not protect a minimum scannable scale".
        // At the default 520x640 window the code rendered 97x97 -- ONE pixel
        // per module -- fully visible and completely useless. The operator
        // refused to attempt a scan, correctly, and called it a thumbnail.
        //
        // Fitting is not the same as usable. This is the invariant that was
        // missing while three versions of the feature shipped.
        assert!(!qr_is_scannable(97.0, 97), "1 px/module is a thumbnail");
        assert!(!qr_is_scannable(194.0, 97), "2 px/module");
        assert!(
            !qr_is_scannable(291.0, 97),
            "3 px/module — still under the floor"
        );
        assert!(
            qr_is_scannable(388.0, 97),
            "4 px/module is what maximized measured"
        );
        assert!(qr_is_scannable(485.0, 97), "5 px/module paired first try");

        // The floor is a property of the code, not of a fixed pixel count: a
        // smaller symbol needs proportionally fewer pixels for the same
        // per-module scale.
        assert!(qr_is_scannable(84.0, 21), "21 modules at 4 px each");
        assert!(!qr_is_scannable(63.0, 21), "21 modules at 3 px each");
    }

    #[test]
    fn the_scannable_floor_matches_what_hardware_actually_paired_from() {
        // Not a guess. Round 9 paired first try at 5 px/module and measured
        // 4.22 surviving a bad webcam; round 10 measured 4 maximized. Setting
        // this floor above 5 would reject a configuration that demonstrably
        // works; below 4 would bless one the operator refused to try.
        assert_eq!(MIN_SCANNABLE_PX_PER_MODULE, 4.0);

        // And the render target must be able to clear its own floor in a window
        // that can actually hold it — otherwise the check can never pass and
        // the warning becomes permanent furniture.
        let side = qr_display_side(97, 600.0, 600.0);
        assert!(
            qr_is_scannable(side, 97),
            "at 600x600 the code renders {side} px, which is below its own floor"
        );
    }

    #[test]
    fn the_code_is_never_taller_than_the_room_it_was_given() {
        // WINDOWS ROUND 9: the code rendered 485 px tall with 215 px visible --
        // it ran off the bottom of the window and was only completed by
        // scrolling. A camera cannot decode a partially visible code, so to a
        // user it reads as "the QR does not work", with no reason to suspect
        // scrolling.
        //
        // This was introduced BY the fix for the previous defect: sizing on
        // width alone, then raising the target from 440 to 600, made a code
        // that fits fewer windows than the one it replaced.
        for height in [90.0f32, 150.0, 215.0, 300.0, 485.0, 600.0, 1200.0] {
            for width in [200.0f32, 400.0, 536.0, 1000.0] {
                let side = qr_display_side(97, width, height);
                assert!(
                    side <= height.max(120.0),
                    "at {width}x{height} the code is {side} px tall — taller \
                     than the space it was given, so it renders below the fold"
                );
                assert!(
                    side <= width.max(120.0),
                    "at {width}x{height} the code is {side} px wide"
                );
            }
        }
    }

    #[test]
    fn a_short_window_costs_resolution_rather_than_hiding_the_code() {
        // The trade this makes explicit: on a window too short for 6 px/module
        // the code gets smaller, not clipped. Smaller is legible and obvious;
        // clipped is invisible and reads as a broken feature.
        let roomy = qr_display_side(97, 700.0, 700.0);
        let short = qr_display_side(97, 700.0, 300.0);
        assert!(
            short < roomy,
            "a short window must reduce the code, not crop it"
        );
        assert_eq!(
            short % 97.0,
            0.0,
            "and it stays a whole number of pixels per module"
        );
    }

    #[test]
    fn a_cramped_panel_never_produces_a_zero_sized_qr() {
        // available_width() can report absurd values mid-layout. A zero scale
        // draws nothing at all, which looks like the host failing to mint an
        // invite rather than a window being too narrow.
        for available in [0.0f32, 1.0, -50.0, f32::NAN, f32::INFINITY] {
            let side = qr_display_side(97, available, available);
            assert!(side > 0.0, "available {available} produced side {side}");
            let side = qr_display_side(97, 600.0, available);
            assert!(side > 0.0, "height {available} produced side {side}");
            let side = qr_display_side(97, available, 600.0);
            assert!(side > 0.0, "width {available} produced side {side}");
        }
        assert!(
            qr_display_side(0, 300.0, 300.0) > 0.0,
            "a zero-module QR must not divide by zero"
        );
    }

    #[test]
    fn a_new_invitation_of_the_same_size_invalidates_the_qr_cache() {
        assert!(
            qr_cache_is_stale(Some(("8d4709cc", 33)), ("f3ada774", 33)),
            "a new token must rebuild the QR; size is not identity"
        );
    }

    /// The same invitation must NOT rebuild: this runs ten times a second and
    /// rebuilding a texture every frame is the reason the cache exists.
    #[test]
    fn the_same_invitation_keeps_its_cached_qr() {
        assert!(!qr_cache_is_stale(Some(("8d4709cc", 33)), ("8d4709cc", 33)));
    }

    /// No cache yet is always stale.
    #[test]
    fn an_empty_qr_cache_is_stale() {
        assert!(qr_cache_is_stale(None, ("8d4709cc", 33)));
    }

    /// A size change must still rebuild — a longer payload can push the QR to a
    /// larger version, and the texture dimensions would otherwise disagree.
    #[test]
    fn a_size_change_still_rebuilds_the_qr() {
        assert!(qr_cache_is_stale(Some(("8d4709cc", 33)), ("f3ada774", 37)));
    }
}
