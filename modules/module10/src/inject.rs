//! OS-level input injection — turns an [`InputControlMessage`] into real
//! mouse/keyboard input.
//!
//! Windows: `SendInput` (mouse move/button/scroll, key by scan code). This is
//! the piece the module was built around ("translating them into OS input
//! events (SendInput on Windows, etc.)") — previously an empty maintenance
//! loop.
//!
//! Linux: `uinput` — a kernel-level virtual input device that libinput and the
//! compositor cannot distinguish from real hardware. This is what makes the
//! host work on Wayland, where XTEST reaches only XWayland and no native
//! Wayland client ever sees the events. See `inject_linux`.
//!
//! Everywhere else: a no-op that reports the events it *would* have injected
//! (so the module builds cross-platform and the wiring is testable off-Windows).
//!
//! Control/among-band messages (`FocusGained`, `InputPause`, `Capabilities`,
//! `SessionCommand`, …) are not OS input — [`inject`] ignores them and returns
//! `Ok(false)` ("nothing injected"); actionable events return `Ok(true)`.

use crate::errors::InputControlError;
use crate::message::InputControlMessage;

/// Split a Set 1 scan code into the byte Windows wants and whether it is
/// extended.
///
/// Set 1 encodes a second bank of keys with an `0xE0` prefix byte — Print
/// Screen, the arrow cluster, right Control, the keypad's Enter and slash.
/// `SendInput` does not take the prefix: it wants the **low byte** in `wScan`
/// and the prefix expressed as `KEYEVENTF_EXTENDEDKEY`.
///
/// Passing `0xE037` through whole, which is what happened before Print Screen
/// had a button, hands Windows a scan code no keyboard produces. It does not
/// fail — nothing returns an error — the keystroke simply is not the one that
/// was asked for. Linux never had this problem because
/// `inject_linux::set1_to_evdev` already decodes the prefix.
///
/// Pure and not `cfg(windows)`, so the decision is tested on every platform
/// this repo builds on rather than only on the one box that can run it.
// Called by `win::key_input` and by the tests below, so on a non-Windows
// build without tests it really is unused. Allowed only there, rather than
// blanket-allowed: on Windows it must stay live, and a bare #[allow] would
// hide it going dead on the platform that needs it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn split_extended(scan_code: u16) -> (u16, bool) {
    if scan_code >> 8 == 0xE0 {
        (scan_code & 0x00FF, true)
    } else {
        (scan_code, false)
    }
}

/// Inject one input event into the OS. Returns `Ok(true)` if an OS event was
/// synthesized, `Ok(false)` for non-input control messages.
pub fn inject(msg: &InputControlMessage) -> Result<bool, InputControlError> {
    #[cfg(windows)]
    {
        win::inject(msg)
    }
    #[cfg(all(target_os = "linux", feature = "linux-input"))]
    {
        // Control messages are classified identically on every backend, and
        // must not fail merely because uinput is unavailable — they inject
        // nothing by definition.
        if !is_os_input(msg) {
            return Ok(false);
        }
        crate::inject_linux::inject(msg)
    }
    #[cfg(not(any(windows, all(target_os = "linux", feature = "linux-input"))))]
    {
        Ok(noop::would_inject(msg))
    }
}

/// What the host currently has pressed down, in the terms the **wire** uses:
/// Set 1 scan codes, modifier bits, and client button ids.
///
/// ## Why this has to exist
///
/// A press and its release are two separate wire messages, and the host had no
/// way to release anything except [`shutdown`] — which only runs on host
/// **Stop**. So any press whose Up never arrived stayed down. The operator
/// found the consequence the hard way: the desktop stopped accepting clicks
/// while still highlighting on hover, which is what a held button looks like
/// from the far side, and the only way out was the power button on the tower.
///
/// There are several ways for an Up to go missing — the phone backgrounded
/// mid-drag, the session dropped between the Down and the Up, a client bug
/// emitting a press nobody asked for. They do not need to be enumerated,
/// because a host that cannot be left holding input is immune to all of them.
///
/// ## Why wire identities rather than each backend's own codes
///
/// The record lived in `inject_linux` and held evdev codes, which meant
/// Windows — where a key is a scan code, a modifier is a virtual key and a
/// button is a `MOUSEEVENTF` flag — could not share it and had no release path
/// at all. Recording what the client SAID keeps one record for both, and each
/// backend translates on the way out through the same functions the press went
/// through.
///
/// Deliberately **exact**: only what was actually pressed is released. A sweep
/// of every key code is right for a shutdown and wrong on a live desktop, where
/// it would release the key under the finger of whoever is sitting at it.
pub(crate) struct HeldInput {
    keys: std::collections::BTreeSet<u16>,
    modifiers: u8,
    buttons: std::collections::BTreeSet<u8>,
}

impl HeldInput {
    /// A `const` constructor, so a backend that needs this in a `static` does
    /// not have to reach for a lazy cell to get one.
    pub(crate) const fn new() -> Self {
        Self {
            keys: std::collections::BTreeSet::new(),
            modifiers: 0,
            buttons: std::collections::BTreeSet::new(),
        }
    }

    /// Record a key event that has just been emitted.
    ///
    /// The modifiers are tracked alongside the key because both backends press
    /// them as real key events — a chord's Ctrl is as capable of sticking down
    /// as its C is, and a stuck Ctrl is much the more damaging, since window
    /// managers bind modifier-plus-click.
    pub(crate) fn observe_key(&mut self, scan_code: u16, modifiers: u8, down: bool) {
        if down {
            self.keys.insert(scan_code);
            self.modifiers |= modifiers;
        } else {
            self.keys.remove(&scan_code);
            self.modifiers &= !modifiers;
        }
    }

    /// Keep only what is still down, after a release was verified.
    ///
    /// Windows round 16 established that a release can partly land: an ordinary
    /// key comes up and a modifier does not, from the same call. The record then
    /// has to describe what is ACTUALLY still held — not everything, which would
    /// re-send an Up for a key already up (on a modifier, that is how a second
    /// application takes it back down), and not nothing, which is the silent
    /// stuck desktop round 15 measured.
    ///
    /// Modifier bits are left alone. They are read back through their own probe
    /// and are not addressed by scan code here, so this only prunes the two sets
    /// it is given.
    /// Only the Windows backend has a read-back to call this with, so on Linux
    /// it is exercised by its tests and nothing else. Marked rather than left
    /// to warn: a new warning in `cargo build --workspace` is noise the Windows
    /// rounds read as a change, and they report a clean build every round.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn retain_still_down(&mut self, keys_down: &[u16], buttons_down: &[u8]) {
        self.keys.retain(|scan| keys_down.contains(scan));
        self.buttons.retain(|b| buttons_down.contains(b));
    }

    pub(crate) fn observe_button(&mut self, button: u8, down: bool) {
        if down {
            self.buttons.insert(button);
        } else {
            self.buttons.remove(&button);
        }
    }

    /// Held keys as Set 1 scan codes.
    pub(crate) fn keys(&self) -> Vec<u16> {
        self.keys.iter().copied().collect()
    }

    /// Held modifier bits, as `MOD_SHIFT | MOD_CTRL | MOD_ALT`.
    pub(crate) fn modifiers(&self) -> u8 {
        self.modifiers
    }

    /// Held buttons as client button ids (0 left, 1 right, 2 middle).
    pub(crate) fn buttons(&self) -> Vec<u8> {
        self.buttons.iter().copied().collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.modifiers == 0 && self.buttons.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.keys.clear();
        self.modifiers = 0;
        self.buttons.clear();
    }
}

/// How long the host may hold input while hearing nothing at all from the
/// client before it lets go on its own.
///
/// Thirty seconds. The number is a judgement between two costs, and they are
/// not symmetrical:
///
/// * **Releasing too eagerly** interrupts an operator who is genuinely holding
///   a button — reading with the pointer parked on a scrollbar, say. They press
///   again. Any pointer movement at all resets the clock, so this only reaches
///   a drag that is being held perfectly still.
/// * **Releasing too late** leaves a desktop that highlights on hover and
///   accepts no click, on a machine that may be in another building. The
///   operator's exit was the power button on the tower.
///
/// So it errs toward letting go.
pub const INPUT_IDLE_RELEASE: std::time::Duration = std::time::Duration::from_secs(30);

/// How many modifier keys a modifier bitmask stands for.
///
/// Pure and not `cfg`-gated, so the arithmetic behind a release message is
/// tested on every platform rather than only where it runs. Both backends press
/// modifiers as real key events, so a held Ctrl is a held key and must be
/// counted as one — the Linux backend's `modifier_keys` builds the same set as
/// a `Vec` because it needs the codes; here only the count is wanted.
pub(crate) fn modifier_count(modifiers: u8) -> usize {
    use crate::message::{MOD_ALT, MOD_CTRL, MOD_SHIFT};
    ((modifiers & MOD_SHIFT != 0) as usize)
        + ((modifiers & MOD_CTRL != 0) as usize)
        + ((modifiers & MOD_ALT != 0) as usize)
}

/// Whether an environment value arms the delayed release probe.
///
/// Shared rather than Windows-only so deny-by-default can be proven on any
/// platform, and exact rather than truthy for the same reason the host's
/// capability gate is: `set RD_TEST_RELEASE_PROBE=1 && run.bat` stores `"1 "` on
/// Windows, and a gate that accepted that would be a gate that accepts almost
/// anything. An instrument that arms itself by accident is worse than one that
/// refuses to arm when asked, because only the second gets noticed.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn release_probe_armed(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// What a release read-back found: what is still down, and what it could not
/// answer for.
///
/// Shared rather than Windows-only so the CLASSIFICATION can be tested on any
/// platform. The probing is inherently per-platform; deciding what the answers
/// mean is not, and it is the part that was wrong.
/// Only the Windows backend constructs this; on Linux it is exercised by its
/// tests and nothing else. Marked rather than left to warn — a new warning in
/// `cargo build --workspace` is noise the Windows rounds read as a change, and
/// they report a clean build every round.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadBack {
    pub(crate) stuck_keys: Vec<u16>,
    pub(crate) stuck_buttons: Vec<u8>,
    /// Scan codes whose probe returned `None` — the question could not be asked.
    pub(crate) unanswered_keys: Vec<u16>,
    /// Buttons whose probe returned `None`.
    pub(crate) unanswered_buttons: Vec<u8>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl ReadBack {
    /// True only when every held thing was positively observed released.
    ///
    /// **An unanswered probe is not a released key.** The first version of the
    /// release verification filtered on `== Some(true)`, so a `None` fell out
    /// of the stuck list and the record was cleared on an answer nobody gave.
    /// Windows round 17 printed `released input state: 1 key(s), 0 button(s)`
    /// while an independent probe measured LeftShift down across ~280 samples
    /// over 20 seconds, and the log could not distinguish "the probe said no"
    /// from "the probe could not say".
    pub(crate) fn all_clear(&self) -> bool {
        self.stuck_keys.is_empty()
            && self.stuck_buttons.is_empty()
            && self.unanswered_keys.is_empty()
            && self.unanswered_buttons.is_empty()
    }
}

/// Whether held input has gone quiet long enough to be released.
///
/// Split out from the clock and the devices so the rule can be proven without
/// either. This is the last of the three ways the host could be left holding a
/// machine down: [`release_input_state`] covers a client that goes away, and
/// [`shutdown`] covers host Stop, but neither covers a client that is still
/// connected and has simply stopped saying anything.
pub fn should_release_idle(anything_held: bool, since_last_input: std::time::Duration) -> bool {
    anything_held && since_last_input >= INPUT_IDLE_RELEASE
}

/// Whether the host is currently holding any key, modifier or mouse button.
///
/// Product API, not a test hook: a host that can hold a machine down should be
/// able to say whether it is doing so, and the three release paths are
/// otherwise invisible from outside. It is also what lets those paths be tested
/// without reading back from `/dev/input/event*`, which needs root — the events
/// themselves are proven separately by `hw-input-release`.
pub fn is_holding_input() -> bool {
    #[cfg(all(target_os = "linux", feature = "linux-input"))]
    {
        crate::inject_linux::is_holding_input()
    }
    #[cfg(windows)]
    {
        win::is_holding()
    }
    #[cfg(not(any(windows, all(target_os = "linux", feature = "linux-input"))))]
    {
        false
    }
}

/// Release held input if it has gone quiet for [`INPUT_IDLE_RELEASE`].
///
/// Returns true if anything was actually released. Cheap enough to call on a
/// timer: with nothing held it is a lock and a comparison.
pub fn release_if_idle() -> bool {
    #[cfg(all(target_os = "linux", feature = "linux-input"))]
    {
        crate::inject_linux::release_if_idle()
    }
    #[cfg(windows)]
    {
        win::release_if_idle()
    }
    #[cfg(not(any(windows, all(target_os = "linux", feature = "linux-input"))))]
    {
        false
    }
}

/// Release everything the host is currently holding, leaving the devices in
/// place so the next session does not pay for a fresh set.
///
/// Call this whenever the client goes away. A press and its release are two
/// wire messages; if the second never arrives, the host holds the desktop down
/// until it is stopped outright — and a desktop held down by a stuck button is
/// exactly the state in which stopping it is hardest.
///
/// BOTH backends implement it. This comment used to say "Only the Linux
/// backend implements it… it is not written here because it cannot be run",
/// which stopped being true when Windows round 4 built and proved
/// `win::release_input_state` on 2026-08-31. A comment that survives the work
/// it describes is worse than none: it was read on 2026-09-06 as evidence that
/// Windows had no release path, when the real gap was one line below.
pub fn release_input_state() {
    #[cfg(all(target_os = "linux", feature = "linux-input"))]
    crate::inject_linux::release_input_state();
    #[cfg(windows)]
    win::release_input_state();
}

/// Release any process-global OS input devices owned by this module, and let
/// go of anything still held.
///
/// THIS PATH DID NOTHING ON WINDOWS UNTIL 2026-09-06. It had one arm, for
/// Linux. `host_app::close_input` calls it on host Stop and on window close —
/// shared, platform-independent code — so on Windows a button still held at
/// that moment was never released and stayed down on the operator's desktop.
///
/// That is exactly P9 ("clean shutdown releases every pressed button"), which
/// was proven on hardware the day before — on Ubuntu. The Linux run needed
/// three attempts precisely because the instrumentation was on the OTHER
/// release path, and the same two-path confusion is what hid this: Windows had
/// `release_input_state` (the client-disappeared path) implemented and proven
/// by round 4, so the backend looked complete. The capability was there the
/// whole time and shutdown simply never called it.
///
/// Windows owns no devices to destroy — `SendInput` synthesizes into the
/// system — so releasing what is held IS the whole job here.
pub fn shutdown() {
    #[cfg(all(target_os = "linux", feature = "linux-input"))]
    crate::inject_linux::shutdown();
    #[cfg(windows)]
    win::shutdown();
}

/// Classify whether a message is an actionable OS input event (shared by both
/// the real and no-op backends so behavior is identical cross-platform).
/// Referenced by the no-op backend and by tests; the Windows backend
/// classifies inline via its `match`.
#[cfg(any(test, not(windows)))]
pub fn is_os_input(msg: &InputControlMessage) -> bool {
    matches!(
        msg,
        InputControlMessage::KeyEvent { .. }
            | InputControlMessage::MouseMove { .. }
            | InputControlMessage::MouseButton { .. }
            | InputControlMessage::MouseScroll { .. }
    )
}

#[cfg(not(any(windows, all(target_os = "linux", feature = "linux-input"))))]
mod noop {
    use super::*;
    pub fn would_inject(msg: &InputControlMessage) -> bool {
        is_os_input(msg)
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use crate::message::{ButtonAction, KeyAction, MouseMoveMode, ScrollMode};
    use windows::Win32::Foundation::{GetLastError, POINT};
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, MapVirtualKeyW, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE,
        KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE,
        MAP_VIRTUAL_KEY_TYPE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
        MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL,
        MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetCursorPos, GetForegroundWindow, GetSystemMetrics, GetWindowTextW, SM_CXVIRTUALSCREEN,
        SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };

    // Standard scroll wheel notch.
    const WHEEL_DELTA: i32 = 120;

    // Modifier bit flags (match the Android side's InputControlMessage.modifiers).
    const MOD_SHIFT: u8 = 0x01;
    const MOD_CTRL: u8 = 0x02;
    const MOD_ALT: u8 = 0x04;
    // Virtual-key codes for the modifiers we synthesize.
    const VK_SHIFT: u16 = 0x10;
    const VK_CONTROL: u16 = 0x11;
    const VK_MENU: u16 = 0x12; // ALT

    /// The one mapping from a wire modifier bit to the virtual key that is
    /// pressed for it.
    ///
    /// One table, read by both the sender ([`push_modifiers`]) and the
    /// read-back ([`modifier_is_down`]), because two copies of it would be a
    /// read-back that can silently disagree with what was actually sent -- and
    /// a read-back that checks the wrong key reports a clean desktop over a
    /// held one, which is the failure this whole path exists to catch.
    const MODIFIER_VKS: [(u8, u16); 3] = [
        (MOD_SHIFT, VK_SHIFT),
        (MOD_CTRL, VK_CONTROL),
        (MOD_ALT, VK_MENU),
    ];

    pub fn inject(msg: &InputControlMessage) -> Result<bool, InputControlError> {
        // Stamped before the result is known: an event the OS refused is still
        // the client talking, and the idle watchdog asks whether the client has
        // gone quiet, not whether it has succeeded.
        state().last_input = Some(std::time::Instant::now());
        match msg {
            InputControlMessage::MouseMove {
                mode,
                dx,
                dy,
                abs_x,
                abs_y,
            } => {
                let input = match mode {
                    MouseMoveMode::Relative => mouse_input(*dx, *dy, 0, MOUSEEVENTF_MOVE),
                    MouseMoveMode::Absolute => {
                        let (nx, ny) = normalize_abs(*abs_x as i32, *abs_y as i32);
                        mouse_input(
                            nx,
                            ny,
                            0,
                            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                        )
                    }
                };
                send(&[input])?;
                Ok(true)
            }
            InputControlMessage::MouseButton { button, action } => {
                let flag = button_flag(*button, *action)?;
                send(&[mouse_input(0, 0, 0, flag)])?;
                state()
                    .held
                    .observe_button(*button, matches!(action, ButtonAction::Down));
                Ok(true)
            }
            InputControlMessage::MouseScroll { dx, dy, mode } => {
                // Lines -> wheel notches; Pixels -> approx notch per WHEEL_DELTA px.
                let scale = match mode {
                    ScrollMode::Lines => WHEEL_DELTA,
                    ScrollMode::Pixels => 1,
                };
                let mut inputs = Vec::new();
                if *dy != 0 {
                    inputs.push(mouse_input(
                        0,
                        0,
                        dy.saturating_mul(scale),
                        MOUSEEVENTF_WHEEL,
                    ));
                }
                if *dx != 0 {
                    inputs.push(mouse_input(
                        0,
                        0,
                        dx.saturating_mul(scale),
                        MOUSEEVENTF_HWHEEL,
                    ));
                }
                if !inputs.is_empty() {
                    send(&inputs)?;
                }
                Ok(true)
            }
            InputControlMessage::KeyEvent {
                scan_code,
                action,
                modifiers,
            } => {
                let mut inputs = Vec::new();
                // Press modifiers before a key-down; release after a key-up.
                let down = matches!(action, KeyAction::Down);
                if down {
                    push_modifiers(&mut inputs, *modifiers, true);
                }
                inputs.push(key_input(*scan_code, matches!(action, KeyAction::Up)));
                if !down {
                    push_modifiers(&mut inputs, *modifiers, false);
                }
                send(&inputs)?;
                state().held.observe_key(*scan_code, *modifiers, down);
                Ok(true)
            }
            // Non-OS-input control messages: nothing to inject.
            _ => Ok(false),
        }
    }

    /// What this backend currently has pressed, and when it last heard
    /// anything. The Linux backend keeps the same pair inside its injector;
    /// here there is no device object to hang it on, so it is a plain static.
    struct InputState {
        held: HeldInput,
        last_input: Option<std::time::Instant>,
    }

    static STATE: std::sync::Mutex<InputState> = std::sync::Mutex::new(InputState {
        held: HeldInput::new(),
        last_input: None,
    });

    /// Poisoning is recovered from rather than propagated: a panic somewhere
    /// else must not be the reason the host cannot let go of a mouse button.
    fn state() -> std::sync::MutexGuard<'static, InputState> {
        STATE.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The Up events for everything currently held, translated back through the
    /// same functions the presses went through.
    fn release_events(held: &HeldInput) -> Vec<INPUT> {
        let mut inputs = Vec::new();
        for scan in held.keys() {
            inputs.push(key_input(scan, true));
        }
        push_modifiers(&mut inputs, held.modifiers(), false);
        for b in held.buttons() {
            if let Ok(flag) = button_flag(b, ButtonAction::Up) {
                inputs.push(mouse_input(0, 0, 0, flag));
            }
        }
        inputs
    }

    /// Whether this backend is holding anything down.
    ///
    /// A function rather than the parent reaching into `state().held`: a parent
    /// module cannot see a child's private items, and the first attempt did
    /// exactly that. It compiled here — where the whole `win` module is
    /// `cfg`-ed out — and failed only on the Windows target, which is what the
    /// `windows-compiles` gate row exists to catch.
    pub(super) fn is_holding() -> bool {
        !state().held.is_empty()
    }

    /// The environment variable that arms the delayed release probe.
    pub(crate) const RELEASE_PROBE_VAR: &str = "RD_TEST_RELEASE_PROBE";

    /// Offsets, in milliseconds from the release, at which the probe samples.
    const RELEASE_PROBE_OFFSETS_MS: [u64; 8] = [0, 50, 100, 250, 500, 1000, 2000, 3000];

    /// Watch what the host's OWN read-back says over the next few seconds, and
    /// only watch. **This changes no decision.**
    ///
    /// # Why it exists
    ///
    /// Windows round 19 measured the release being applied LATE rather than
    /// ignored. With an independent probe, on a freshly rebooted machine:
    ///
    /// ```text
    /// LeftShift  DOWN at 0/100/250 ms, UP by 500 ms, stays up
    /// F13        DOWN through 2000 ms, UP by 3000 ms, stays up
    /// ```
    ///
    /// while the host printed a clean `released input state: 1 key(s), 0
    /// button(s)`. Two readings fit: the host's immediate read-back sampled
    /// after the Up landed and was right, or it disagreed with the independent
    /// probe. **The external samples are too coarse to tell**, and the 15-20
    /// second stick from rounds 16 and 17 DID NOT REPRODUCE at all on that
    /// clean boot — so the long case may be state-dependent and the framing may
    /// need revisiting rather than fixing.
    ///
    /// So this samples the host's own probe at known offsets and prints them
    /// beside the external transcript. It answers whether our read-back tracks
    /// an independent one, which is the question a policy change would have to
    /// rest on.
    ///
    /// # Why it changes nothing
    ///
    /// Round 19's caution: *"test a bounded delayed same-process read-back
    /// before changing retry or record-pruning policy. Do not blindly resend Up
    /// while delivery is still pending."* Operator decision on 2026-09-11 was
    /// instrument-only.
    ///
    /// * **Deny by default.** Unarmed, this returns before starting anything,
    ///   so an ordinary run does not gain a thread or a log line.
    /// * **Off the release path.** It samples on its own thread, so the release
    ///   decision is not delayed by a single millisecond. Blocking here would
    ///   itself be the behaviour change this is meant to avoid.
    /// * **Read-only and bounded.** It reads key state and prints. It never
    ///   injects, never touches the held record, and stops after 3 seconds.
    fn spawn_release_probe(keys: Vec<u16>, buttons: Vec<u8>) {
        if !super::release_probe_armed(std::env::var(RELEASE_PROBE_VAR).ok().as_deref()) {
            return;
        }
        if keys.is_empty() && buttons.is_empty() {
            return;
        }
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            for offset in RELEASE_PROBE_OFFSETS_MS {
                let due = std::time::Duration::from_millis(offset);
                if let Some(wait) = due.checked_sub(start.elapsed()) {
                    std::thread::sleep(wait);
                }
                let t = start.elapsed().as_millis();
                for scan in &keys {
                    eprintln!(
                        "[module10] release probe t={t}ms scan={scan} down={:?}",
                        scan_code_is_down(*scan)
                    );
                }
                for b in &buttons {
                    eprintln!(
                        "[module10] release probe t={t}ms button={b} down={:?}",
                        button_is_down(*b)
                    );
                }
            }
            eprintln!("[module10] release probe finished");
        });
    }

    /// Read every held key and button back off Windows after a release.
    ///
    /// # `None` is not "released", and the first version of this treated it as
    /// one
    ///
    /// `scan_code_is_down` returns `None` when the question cannot be asked —
    /// an unmapped scan code, a button id with no virtual key. The first
    /// version filtered on `== Some(true)`, so a `None` fell out of the stuck
    /// list and the record was cleared on the strength of an answer nobody
    /// gave.
    ///
    /// **Windows round 17 hit exactly that.** The read-back reported nothing
    /// down and printed `released input state: 1 key(s), 0 button(s)`, while an
    /// independent probe measured LeftShift DOWN across ~280 samples over 20
    /// seconds. Whether the probe returned `None` or a wrong `Some(false)` was
    /// not distinguishable from the log, because both took the same silent
    /// branch. They are separated here so the next run says which.
    ///
    /// The round also ruled out the easy explanation from its side: it measured
    /// `MapVirtualKeyW(0x2A, MAPVK_VSC_TO_VK_EX)` returning `0xA0` (VK_LSHIFT)
    /// on that box, the exact virtual key its own probe read as down. So the
    /// mapping is not the difference.
    fn read_back(held: &HeldInput) -> ReadBack {
        let mut rb = ReadBack {
            stuck_keys: Vec::new(),
            stuck_buttons: Vec::new(),
            unanswered_keys: Vec::new(),
            unanswered_buttons: Vec::new(),
        };
        for scan in held.keys() {
            match scan_code_is_down(scan) {
                Some(true) => rb.stuck_keys.push(scan),
                Some(false) => {}
                None => rb.unanswered_keys.push(scan),
            }
        }
        for b in held.buttons() {
            match button_is_down(b) {
                Some(true) => rb.stuck_buttons.push(b),
                Some(false) => {}
                None => rb.unanswered_buttons.push(b),
            }
        }
        rb
    }

    /// The Ups for exactly the keys and buttons named, and nothing else.
    ///
    /// Separate from [`release_events`] because a retry must re-send only what
    /// is still down. Re-sending the whole set would emit an Up for something
    /// already released, which on a modifier is how a second application takes
    /// it back down again.
    fn release_events_for(keys: &[u16], buttons: &[u8]) -> Vec<INPUT> {
        let mut inputs = Vec::new();
        for scan in keys {
            inputs.push(key_input(*scan, true));
        }
        for b in buttons {
            if let Ok(flag) = button_flag(*b, ButtonAction::Up) {
                inputs.push(mouse_input(0, 0, 0, flag));
            }
        }
        inputs
    }

    /// Release everything this backend is holding. See the module-level
    /// [`super::release_input_state`] for why this exists at all.
    ///
    /// # It says what it let go, in the SAME shape as the Linux backend
    ///
    /// It did not until 2026-09-09, and that silence is why Windows round 15
    /// could not diagnose the defect it found. `inject_linux::release_input_state`
    /// gained this exact instrumentation on 2026-09-05, for exactly the reason
    /// its comment gives — a path that prints nothing on success cannot be told
    /// apart from a path that never ran. **The fix was applied to one backend
    /// and not the other**, and the divergence survived four rounds.
    ///
    /// WHAT ROUND 15 MEASURED, and why this line is the thing that will resolve
    /// it: a host-initiated device revoke closed the session while LeftShift was
    /// physically down, and the key was **still down 90 seconds later**, 360
    /// consecutive OS-level samples, with no product release. Three revokes in
    /// that run, not one followed by any release line. Afterwards `shutdown`
    /// reported `nothing was held`.
    ///
    /// Two readings fit every observation and this log line separates them:
    ///
    /// * `released input state: 1 key(s), 0 button(s)` — the record WAS held,
    ///   the Up was emitted, and Windows did not apply it. `SendInput` success
    ///   means queued, not applied.
    /// * `released input state: nothing was held` — the record was already
    ///   empty, so the release had nothing to send and the key was never
    ///   tracked in the first place.
    ///
    /// Do not guess between them. Round 16 reads the line.
    pub(super) fn release_input_state() {
        let mut st = state();
        // Counted BEFORE the release, because clearing the record makes asking
        // afterwards always report nothing. Same ordering as the Linux backend.
        let keys = st.held.keys().len() + super::modifier_count(st.held.modifiers());
        let buttons = st.held.buttons().len();
        if st.held.is_empty() {
            // Said out loud, not returned in silence. An empty release and no
            // release at all leave an identical desktop, and telling them apart
            // is the whole reason this prints -- `shutdown` already argues this
            // and this path was the one that never listened.
            eprintln!("[module10] released input state: nothing was held");
            return;
        }
        let inputs = release_events(&st.held);
        if let Err(e) = send(&inputs) {
            eprintln!("[module10] could not release held input state: {e:?}");
            return;
        }

        // VERIFY, DO NOT ASSUME. `send` returning Ok means the events were
        // accepted into the input queue, not that Windows applied them.
        //
        // Windows round 16 measured the difference and it is SELECTIVE: an
        // ordinary key (F13) released in 4 s, and LeftShift — same Rust route,
        // same call, same `1 key(s), 0 button(s)` line — was still down 15
        // seconds later. Both logged `key Down modifiers=0x00`, so both sat in
        // `held.keys` and both were released by `key_input`; the divergence is
        // below this code, at the Win32 boundary. The Win32 reason is still
        // unknown and this does not depend on knowing it.
        //
        // A stuck modifier is the damaging case — every click becomes a
        // range-select, every keystroke uppercases — so it is exactly the one
        // that must not be silent.
        // Observational only, and armed by env. Started BEFORE the decision so
        // its t=0 sample is as close as possible to the host's own read-back,
        // and on its own thread so the decision below is not delayed.
        spawn_release_probe(st.held.keys(), st.held.buttons());
        let rb = read_back(&st.held);
        if rb.all_clear() {
            st.held.clear();
            eprintln!("[module10] released input state: {keys} key(s), {buttons} button(s)");
            return;
        }
        if !rb.unanswered_keys.is_empty() || !rb.unanswered_buttons.is_empty() {
            // Say so rather than treat silence as success. This is the branch
            // round 17's run may have taken while printing a clean line.
            eprintln!(
                "[module10] release read-back COULD NOT ANSWER for {:?} key(s) and {:?} \
                 button(s) — not treating that as released. Foreground window: {:?}",
                rb.unanswered_keys,
                rb.unanswered_buttons,
                foreground_window_title()
            );
        }

        // One retry, aimed at exactly what is still down. Re-sending the whole
        // set would emit an Up for something already up, which on a modifier is
        // how a second application takes it back down.
        if let Err(e) = send(&release_events_for(&rb.stuck_keys, &rb.stuck_buttons)) {
            eprintln!("[module10] the release retry was refused: {e:?}");
        }
        let after = read_back(&st.held);
        let keys_after = after.stuck_keys;
        let buttons_after = after.stuck_buttons;
        if keys_after.is_empty()
            && buttons_after.is_empty()
            && after.unanswered_keys.is_empty()
            && after.unanswered_buttons.is_empty()
        {
            st.held.clear();
            eprintln!(
                "[module10] released input state: {keys} key(s), {buttons} button(s) \
                 (the second attempt was the one that landed)"
            );
            return;
        }

        // THE RECORD IS KEPT ON PURPOSE, for what is still down.
        //
        // Clearing it here would make the host believe it holds nothing while
        // the desktop is held, which is precisely the state round 15 measured
        // and could not see. Keeping it means `shutdown` and `release_if_idle`
        // each get another attempt, and `is_holding_input()` stays truthful.
        //
        // Only the entries CONFIRMED up are dropped, so a later attempt does
        // not re-Up something already released.
        // Anything unanswered is kept too: an unanswered probe is not a
        // released key, and dropping it here is the mistake that made round
        // 17's run look clean.
        let mut keep_keys = keys_after.clone();
        keep_keys.extend(after.unanswered_keys.iter().copied());
        let mut keep_buttons = buttons_after.clone();
        keep_buttons.extend(after.unanswered_buttons.iter().copied());
        st.held.retain_still_down(&keep_keys, &keep_buttons);
        eprintln!(
            "[module10] COULD NOT RELEASE {} key(s) and {} button(s) after two attempts \
             ({} key(s) and {} button(s) unanswered). The record is KEPT so shutdown and the \
             idle watchdog try again. Stuck scan codes: {:?}, buttons: {:?}. \
             Foreground window: {:?}",
            keys_after.len(),
            buttons_after.len(),
            after.unanswered_keys.len(),
            after.unanswered_buttons.len(),
            keys_after,
            buttons_after,
            foreground_window_title()
        );
    }

    /// The clean-shutdown release: let go of everything, and SAY WHAT WAS LET
    /// GO in the same shape the Linux backend uses.
    ///
    /// The message is deliberately identical to `inject_linux::shutdown`'s, so
    /// one runbook and one log grep serve both platforms — P9 on Linux was
    /// proven by finding exactly this line, and a Windows round needs the same
    /// artifact to make the same claim.
    ///
    /// The "nothing was held" case is reported too. An empty release and no
    /// release at all leave an identical desktop, and telling them apart is the
    /// whole reason this prints.
    pub(super) fn shutdown() {
        let mut st = state();
        let keys = st.held.keys().len() + super::modifier_count(st.held.modifiers());
        let buttons = st.held.buttons().len();
        if st.held.is_empty() {
            eprintln!("[module10] shutdown released input state: nothing was held");
            return;
        }
        let inputs = release_events(&st.held);
        match send(&inputs) {
            Ok(()) => {
                st.held.clear();
                eprintln!(
                    "[module10] shutdown released input state: {keys} key(s), {buttons} button(s)"
                );
            }
            Err(e) => {
                eprintln!("[module10] could not release all input state during shutdown: {e:?}")
            }
        }
    }

    /// Release held input if the client has gone quiet for
    /// [`super::INPUT_IDLE_RELEASE`].
    pub(super) fn release_if_idle() -> bool {
        let mut st = state();
        let Some(last) = st.last_input else {
            return false;
        };
        let idle = last.elapsed();
        if !super::should_release_idle(!st.held.is_empty(), idle) {
            return false;
        }
        let inputs = release_events(&st.held);
        match send(&inputs) {
            Ok(()) => {
                eprintln!(
                    "[module10] released input held with no client traffic for {}s",
                    idle.as_secs()
                );
                st.held.clear();
                true
            }
            Err(e) => {
                eprintln!("[module10] could not release idle input state: {e:?}");
                false
            }
        }
    }

    fn push_modifiers(inputs: &mut Vec<INPUT>, modifiers: u8, down: bool) {
        for (bit, vk) in MODIFIER_VKS {
            if modifiers & bit != 0 {
                inputs.push(vk_input(vk, !down));
            }
        }
    }

    fn mouse_input(dx: i32, dy: i32, mouse_data: i32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: mouse_data as u32,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn key_input(scan_code: u16, key_up: bool) -> INPUT {
        // The 0xE0 prefix is a FLAG here, not part of the code. See
        // `super::split_extended`.
        let (scan, extended) = super::split_extended(scan_code);
        let mut flags = KEYEVENTF_SCANCODE;
        if extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        if key_up {
            flags |= KEYEVENTF_KEYUP;
        }
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn vk_input(vk: u16, key_up: bool) -> INPUT {
        let flags = if key_up {
            KEYEVENTF_KEYUP
        } else {
            KEYBD_EVENT_FLAGS(0)
        };
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(vk),
                    wScan: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn button_flag(
        button: u8,
        action: ButtonAction,
    ) -> Result<MOUSE_EVENT_FLAGS, InputControlError> {
        let down = matches!(action, ButtonAction::Down);
        // 0 = left, 1 = right, 2 = middle (matches the client button ids).
        Ok(match (button, down) {
            (0, true) => MOUSEEVENTF_LEFTDOWN,
            (0, false) => MOUSEEVENTF_LEFTUP,
            (1, true) => MOUSEEVENTF_RIGHTDOWN,
            (1, false) => MOUSEEVENTF_RIGHTUP,
            (2, true) => MOUSEEVENTF_MIDDLEDOWN,
            (2, false) => MOUSEEVENTF_MIDDLEUP,
            _ => return Err(InputControlError::Malformed),
        })
    }

    /// Map a virtual-desktop pixel coordinate to SendInput's 0..=65535
    /// absolute range across the whole virtual screen.
    fn normalize_abs(x: i32, y: i32) -> (i32, i32) {
        unsafe {
            let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
            let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);
            let nx = ((x - vx) as i64 * 65535 / (vw - 1).max(1) as i64) as i32;
            let ny = ((y - vy) as i64 * 65535 / (vh - 1).max(1) as i64) as i32;
            (nx.clamp(0, 65535), ny.clamp(0, 65535))
        }
    }

    /// Put events on the wire.
    ///
    /// # The count is the signal. `GetLastError` is NOT.
    ///
    /// A check on `GetLastError()` after a SUCCESSFUL `SendInput` was added on
    /// 2026-09-10 and **shipped a regression**. It is removed, and the reasoning
    /// is kept here so it is not reinvented.
    ///
    /// `GetLastError` is only meaningful when a function REPORTS FAILURE. A full
    /// return count is success, and Windows APIs are free to set a last-error
    /// value during ordinary successful operation. `SetLastError(0)` first does
    /// not make the value meaningful — it only makes it fresh.
    ///
    /// **The evidence, from Windows rounds 17 and 18, in both directions:**
    ///
    /// * round 17 — an injection did NOT apply, and `GetLastError` was 5;
    /// * round 18 — an injection DID apply, and `GetLastError` was 5.
    ///
    /// So error 5 is uncorrelated with application either way. It can neither
    /// confirm nor deny that events landed, and round 17's repro reported two
    /// facts from one observation as cause and effect.
    ///
    /// # What the bad check actually cost
    ///
    /// `inject` calls `send(&inputs)?` and only then `observe_key`. A false
    /// `Err` short-circuits the `?`, so **the host kept no record of a key it
    /// really had pressed** — and then correctly reported `nothing was held` at
    /// the revoke while the desktop stayed held. That is precisely the stuck-key
    /// state this whole line of work exists to prevent. It also panicked a test
    /// after its F13 down had applied, leaving the key held on the operator's
    /// desktop for them to clear by hand.
    ///
    /// **Read-back is the signal that works.** The `live_input_release` tests
    /// verify by reading the key state back and they passed in the same process,
    /// in the same run, as the call that failed on an error code.
    fn send(inputs: &[INPUT]) -> Result<(), InputControlError> {
        let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent as usize != inputs.len() {
            // HERE the error code IS meaningful: the function has reported
            // failure, so the value describes that failure.
            let err = unsafe { GetLastError() };
            return Err(InputControlError::Injection(format!(
                "SendInput sent {sent}/{} events, error {} — foreground window: {:?}",
                inputs.len(),
                err.0,
                foreground_window_title()
            )));
        }
        Ok(())
    }

    /// Current cursor position — used by the live injection test to confirm a
    /// real absolute move landed.
    pub fn cursor_pos() -> Option<(i32, i32)> {
        unsafe {
            let mut p = POINT::default();
            GetCursorPos(&mut p).ok()?;
            Some((p.x, p.y))
        }
    }

    /// Whether Windows itself currently reports this mouse button as down.
    ///
    /// The counterpart to [`cursor_pos`] for buttons, and the Windows answer to
    /// a question the release tests cannot otherwise ask. `is_holding_input()`
    /// reports the host's own *record*; this reports the *operating system's*.
    /// They can disagree: `SendInput` returning success means the events were
    /// accepted into the input queue, not that they were applied — UIPI, a
    /// higher-integrity foreground window, or an injection blocker can swallow
    /// them, and the host would clear its record while the desktop stayed held.
    ///
    /// `button` uses the same numbering as `InputControlMessage::MouseButton`:
    /// 0 left, 1 right, 2 middle.
    pub fn button_is_down(button: u8) -> Option<bool> {
        let vk = match button {
            0 => 0x01, // VK_LBUTTON
            1 => 0x02, // VK_RBUTTON
            2 => 0x04, // VK_MBUTTON
            _ => return None,
        };
        key_is_down(vk)
    }

    /// Whether Windows reports this virtual key as currently down.
    ///
    /// The primitive under [`button_is_down`], [`modifier_is_down`] and
    /// [`scan_code_is_down`]: `GetAsyncKeyState` does not care whether a
    /// virtual key names a mouse button, a modifier or a letter, so neither
    /// does this.
    pub fn key_is_down(vk: u16) -> Option<bool> {
        // The high bit is "currently down". The low bit is "pressed since the
        // last call" and is deliberately ignored: this asks about now, not
        // about history.
        Some(unsafe { GetAsyncKeyState(vk as i32) } as u16 & 0x8000 != 0)
    }

    /// Whether Windows reports the modifier named by `bit` as currently down.
    ///
    /// `bit` is one of the wire flags -- `MOD_SHIFT`, `MOD_CTRL`, `MOD_ALT` --
    /// and is resolved through [`MODIFIER_VKS`], the same table
    /// [`push_modifiers`] sends from. A bit that names no modifier, or more
    /// than one bit at once, is `None`: "which key do you mean" has no honest
    /// yes/no answer, and returning `false` to it would read as "nothing is
    /// held".
    pub fn modifier_is_down(bit: u8) -> Option<bool> {
        let (_, vk) = MODIFIER_VKS.iter().copied().find(|(b, _)| *b == bit)?;
        key_is_down(vk)
    }

    /// The title of the window that currently has the foreground.
    ///
    /// Injection is delivered to the foreground window, so when a press does
    /// not arrive the first useful question is "what was in front?". UIPI
    /// silently discards synthesized input aimed at a window belonging to a
    /// higher-integrity process, and the symptom is indistinguishable from a
    /// backend that simply does not work -- unless the window is named.
    ///
    /// Empty string for a window with no title; `None` when there is no
    /// foreground window at all, which is a real state (during a desktop
    /// switch, or while the secure desktop is up).
    pub fn foreground_window_title() -> Option<String> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return None;
            }
            let mut buf = [0u16; 256];
            let n = GetWindowTextW(hwnd, &mut buf);
            Some(String::from_utf16_lossy(&buf[..n.max(0) as usize]))
        }
    }

    /// Whether Windows reports the key at this Set 1 scan code as down.
    ///
    /// Held keys are recorded as scan codes -- a scan code names a physical
    /// position, which is the only thing the phone can know -- while
    /// `GetAsyncKeyState` answers about virtual keys, so the two are bridged
    /// here with `MapVirtualKeyW`. `MAPVK_VSC_TO_VK_EX` rather than
    /// `MAPVK_VSC_TO_VK` so that left and right modifiers stay distinct
    /// instead of collapsing onto the generic key.
    ///
    /// `None` when the layout maps this position to no virtual key at all.
    /// That is not "the key is up": it means the question cannot be asked
    /// here, and a caller must not read it as proof of a released desktop.
    pub fn scan_code_is_down(scan_code: u16) -> Option<bool> {
        const MAPVK_VSC_TO_VK_EX: MAP_VIRTUAL_KEY_TYPE = MAP_VIRTUAL_KEY_TYPE(3);
        let (scan, extended) = super::split_extended(scan_code);
        // MapVirtualKey wants the 0xE0 prefix back in the high byte for an
        // extended key; `split_extended` is what took it off.
        let arg = if extended {
            0xE000u32 | scan as u32
        } else {
            scan as u32
        };
        match unsafe { MapVirtualKeyW(arg, MAPVK_VSC_TO_VK_EX) } {
            0 => None,
            vk => key_is_down(vk as u16),
        }
    }
}

/// Current cursor position (Windows only; `None` elsewhere). Public for tests
/// that verify a real absolute move.
///
/// It stays `None` on Linux/Wayland on purpose. There is no protocol for asking
/// a Wayland compositor where the pointer is — that is a deliberate design
/// decision upstream, not a gap to work around. A Linux absolute move is proved
/// instead by capturing the screen with the cursor composited in and looking at
/// where it landed; see `tests/live_inject.rs`.
pub fn cursor_pos() -> Option<(i32, i32)> {
    #[cfg(windows)]
    {
        win::cursor_pos()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Whether the OS reports this mouse button as currently down (Windows only;
/// `None` elsewhere).
///
/// This is the Windows equivalent of reading events back from
/// `/dev/input/event*` on Linux, and it answers the half that
/// [`is_holding_input`] cannot: that half reports what the host *believes* it
/// is holding, this reports what the desktop *actually* has down. A release
/// path can clear the first while leaving the second set, and that is precisely
/// the failure that leaves a machine held.
///
/// `None` on non-Windows rather than `false`: "no answer available here" and
/// "the button is up" are different claims, and a test that cannot tell them
/// apart is the kind that passes while proving nothing.
pub fn button_is_down(button: u8) -> Option<bool> {
    #[cfg(windows)]
    {
        win::button_is_down(button)
    }
    #[cfg(not(windows))]
    {
        let _ = button;
        None
    }
}

/// Whether the OS reports this modifier as currently down (Windows only;
/// `None` elsewhere).
///
/// [`button_is_down`] closed half the gap. This closes the half that matters
/// more: **a stuck modifier is worse than a stuck button.** A held Ctrl or Alt
/// does not merely sit there — it re-interprets every click and keystroke the
/// person at the machine makes, so the desktop appears to work while doing the
/// wrong thing, which is harder to diagnose than a desktop that is plainly
/// stuck. It is the shape of the lockup that cost a hard power-off on Linux.
///
/// `bit` is a wire modifier flag: `0x01` shift, `0x02` ctrl, `0x04` alt. Any
/// other value — including two flags at once — is `None`.
pub fn modifier_is_down(bit: u8) -> Option<bool> {
    #[cfg(windows)]
    {
        win::modifier_is_down(bit)
    }
    #[cfg(not(windows))]
    {
        let _ = bit;
        None
    }
}

/// Whether an injected press actually reached the operating system.
///
/// ## The defect this exists for
///
/// Windows round 5, 2026-09-01: with a higher-integrity window focused,
/// `SendInput` **returns the full event count while Windows applies nothing**.
/// The `sent != inputs.len()` guard does not fire, so `inject` reports success
/// for a press that never happened. The host then records it as held, later
/// "releases" it, and reports a clean desktop **it was never driving**.
///
/// That is worse than failing. A host that knows it cannot deliver input can
/// say so; a host that believes a phantom press is confidently wrong, and every
/// safeguard built this week — the release paths, the idle watchdog, the held
/// record — is reasoning about a machine it is not connected to.
///
/// ## Why the answer is checked per injection and not once at grant time
///
/// UIPI depends on **what is focused right now**. A grant-time probe is stale
/// the moment the operator alt-tabs to an elevated window, so a predictive
/// check would be wrong by construction. The question is asked of each press,
/// which is affordable because only Downs are readable and Downs are rare —
/// pointer moves, which arrive 60-120 a second, are not read back at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The OS agrees the press is down. Normal.
    Landed,
    /// The host injected it, `SendInput` reported success, and the OS says it
    /// is not down. **This is the UIPI case** and the grant must be refused.
    NotLanded,
    /// No read-back was available: a platform without one, or a key position
    /// the current layout does not map.
    ///
    /// **Never treated as failure.** Linux has no read-back at this layer and
    /// answers `None` every time, so conflating "I could not look" with "it did
    /// not land" would refuse every input grant on the platform the product
    /// mainly runs on. "I could not look" is not evidence of anything.
    Unknown,
}

/// How long to keep asking before calling an injected press undelivered.
///
/// **`SendInput` is asynchronous.** It queues events and returns; the system
/// applies them afterwards. Reading `GetAsyncKeyState` on the next line races
/// that, and the race is not theoretical -- measured on Windows 10 / RTX 3060,
/// 2026-09-01, with nothing elevated focused and every press legitimate:
///
/// ```text
/// keys    :   0/200 read back as not-down on the first look
/// buttons :  22/25  read back as not-down on the first look
/// ```
///
/// Keyboard Downs surface in ~50-120us, fast enough to hide the problem.
/// **Mouse button Downs take ~5ms**, so an immediate read-back called 88% of
/// ordinary clicks undelivered. Since `NotLanded` revokes the operator's
/// control grant, an unwaited check hands back control on roughly the first
/// click of every session -- on a desktop with no elevated window near it.
///
/// 500ms is ~90x the observed worst case. It is only ever spent in full when a
/// press genuinely never lands, and that path ends in a revoke, so it is paid
/// once per session rather than once per click.
pub const DELIVERY_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// How often to re-ask while waiting.
const DELIVERY_POLL: std::time::Duration = std::time::Duration::from_millis(1);

/// Resolve one press against a read-back that may not have caught up yet.
///
/// Asks the answerable question -- "does the press arrive?" -- instead of the
/// unanswerable one, "has it arrived within microseconds?". Returns as soon as
/// the press is observed, so a key that is already down costs one syscall and
/// nothing else; only a press that has not landed yet waits, and only one that
/// never lands waits the full [`DELIVERY_CONFIRM_TIMEOUT`].
///
/// Generic over the probe so the timing logic is testable on every platform,
/// including the one whose real probe can only ever answer `None`.
pub fn confirm_down(probe: impl Fn() -> Option<bool>) -> Delivery {
    // The first look costs no sleep: this is the whole cost for a key.
    match probe() {
        None => return Delivery::Unknown,
        Some(true) => return Delivery::Landed,
        Some(false) => {}
    }
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() >= DELIVERY_CONFIRM_TIMEOUT {
            return Delivery::NotLanded;
        }
        std::thread::sleep(DELIVERY_POLL);
        match probe() {
            None => return Delivery::Unknown,
            Some(true) => return Delivery::Landed,
            Some(false) => {}
        }
    }
}

/// Ask the OS whether the press this message just made actually landed.
///
/// Only **Downs** are checked. An Up that the OS agrees is up tells us nothing,
/// and pointer moves arrive 60-120 a second and have no read-back at all — so
/// the cost of this is one syscall per button or key press, which is rare.
///
/// Returns [`Delivery::Unknown`] on any platform without a read-back, which is
/// every platform but Windows today.
pub fn verify_delivery(msg: &InputControlMessage) -> Delivery {
    use crate::message::{ButtonAction, KeyAction};
    match msg {
        InputControlMessage::KeyEvent {
            scan_code, action, ..
        } => {
            let down = matches!(action, KeyAction::Down);
            if !down {
                return Delivery::Landed;
            }
            let scan = *scan_code;
            confirm_down(move || scan_code_is_down(scan))
        }
        InputControlMessage::MouseButton { button, action } => {
            let down = matches!(action, ButtonAction::Down);
            if !down {
                return Delivery::Landed;
            }
            let b = *button;
            confirm_down(move || button_is_down(b))
        }
        // Moves and scrolls are not readable, and asking would be a syscall per
        // sample on the highest-rate path in the product.
        _ => Delivery::Unknown,
    }
}

/// Judge one injected press against what the OS reports.
///
/// `recorded` is what the host believes it just did; `observed` is the
/// read-back, which is `None` wherever no read-back exists.
pub fn delivery_verdict(recorded_down: bool, observed: Option<bool>) -> Delivery {
    match (recorded_down, observed) {
        (_, None) => Delivery::Unknown,
        (true, Some(true)) => Delivery::Landed,
        (true, Some(false)) => Delivery::NotLanded,
        // A release is not the case this guards. Reporting NotLanded for an Up
        // the OS agrees is up would refuse a grant on every correct release.
        (false, Some(_)) => Delivery::Landed,
    }
}

/// The foreground window's title (Windows only; `None` elsewhere).
///
/// Diagnostic. Synthesized input goes to whatever holds the foreground, and
/// UIPI drops it without a word when that window outranks this process, so an
/// injection that vanishes is only interpretable alongside the name of the
/// window it vanished into.
pub fn foreground_window_title() -> Option<String> {
    #[cfg(windows)]
    {
        win::foreground_window_title()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Whether the OS reports the key at this Set 1 scan code as down (Windows
/// only; `None` elsewhere).
///
/// The third read-back, completing the set against what [`is_holding_input`]
/// records: buttons, modifiers and now ordinary keys. `HeldInput` stores keys
/// as scan codes, so this takes a scan code and does the translation to a
/// virtual key internally rather than making every caller do it.
///
/// `None` also when the current layout maps the position to no virtual key,
/// which is why this returns an `Option` and not a `bool`.
pub fn scan_code_is_down(scan_code: u16) -> Option<bool> {
    #[cfg(windows)]
    {
        win::scan_code_is_down(scan_code)
    }
    #[cfg(not(windows))]
    {
        let _ = scan_code;
        None
    }
}

#[cfg(test)]
mod tests {

    /// The delayed release probe is absent unless it is asked for, exactly.
    ///
    /// It spawns a thread and prints on every release, so an ordinary run must
    /// not gain either. And the value must be exactly "1": on Windows
    /// `set VAR=1 && run.bat` stores `"1 "`, which the host's capability gate
    /// already refuses for the same reason.
    #[test]
    fn the_release_probe_is_absent_unless_asked_for() {
        assert!(
            !release_probe_armed(None),
            "an unset variable armed the probe"
        );
        for not_armed in ["", " ", "0", "true", "yes", "1 ", " 1", "01"] {
            assert!(
                !release_probe_armed(Some(not_armed)),
                "{not_armed:?} armed the probe; only an exact \"1\" may"
            );
        }
        assert!(release_probe_armed(Some("1")));
    }

    /// An unanswered probe is NOT a released key.
    ///
    /// This is the rule the first version of the verification got wrong, and it
    /// is why Windows round 17 printed a clean release line over a key that was
    /// down for twenty seconds. `scan_code_is_down` returns `None` when the
    /// question cannot be asked; filtering on `== Some(true)` quietly turned
    /// that into "released" and cleared the record.
    #[test]
    fn an_unanswered_probe_is_not_a_clear_release() {
        let rb = ReadBack {
            unanswered_keys: vec![42],
            ..Default::default()
        };
        assert!(
            !rb.all_clear(),
            "a key whose probe could not answer was reported as released — that is \
             round 17's clean line over a stuck LeftShift"
        );
    }

    #[test]
    fn an_unanswered_button_is_not_a_clear_release() {
        let rb = ReadBack {
            unanswered_buttons: vec![2],
            ..Default::default()
        };
        assert!(!rb.all_clear());
    }

    #[test]
    fn a_stuck_key_is_not_a_clear_release() {
        let rb = ReadBack {
            stuck_keys: vec![42],
            ..Default::default()
        };
        assert!(!rb.all_clear());
    }

    /// The only state that may clear the record: everything positively observed
    /// up, and nothing left unasked.
    #[test]
    fn only_a_fully_answered_release_is_clear() {
        assert!(ReadBack::default().all_clear());
    }

    /// A release that only partly lands must leave the record describing what
    /// is ACTUALLY still held.
    ///
    /// Windows round 16: F13 came up and LeftShift did not, from the same call.
    /// Clearing everything there is the silent stuck desktop round 15 measured;
    /// keeping everything re-sends an Up for a key already up, and on a modifier
    /// a second application is how it goes back DOWN.
    #[test]
    fn a_partly_landed_release_keeps_only_what_is_still_down() {
        let mut held = HeldInput::new();
        held.observe_key(42, 0, true); // LeftShift
        held.observe_key(100, 0, true); // F13
        held.observe_button(2, true);

        // Windows reports LeftShift still down; F13 and the button came up.
        held.retain_still_down(&[42], &[]);

        assert_eq!(
            held.keys(),
            vec![42],
            "the stuck key must survive the prune"
        );
        assert!(held.buttons().is_empty(), "a released button was kept");
        assert!(
            !held.is_empty(),
            "the record must still say something is held"
        );
    }

    #[test]
    fn a_fully_landed_release_prunes_everything() {
        let mut held = HeldInput::new();
        held.observe_key(100, 0, true);
        held.observe_button(0, true);
        held.retain_still_down(&[], &[]);
        assert!(
            held.is_empty(),
            "nothing was still down, so nothing may be kept"
        );
    }

    #[test]
    fn retaining_what_was_never_held_adds_nothing() {
        // The probe answers about keys we asked about. It cannot introduce one.
        let mut held = HeldInput::new();
        held.observe_key(42, 0, true);
        held.retain_still_down(&[42, 100], &[1]);
        assert_eq!(held.keys(), vec![42]);
        assert!(held.buttons().is_empty());
    }

    #[test]
    fn a_stuck_button_survives_while_a_released_key_does_not() {
        let mut held = HeldInput::new();
        held.observe_key(100, 0, true);
        held.observe_button(2, true);
        held.retain_still_down(&[], &[2]);
        assert!(held.keys().is_empty());
        assert_eq!(held.buttons(), vec![2]);
    }
    use super::*;
    use crate::message::*;

    /// Print Screen is the reason this exists: it is `0xE037`, and until it had
    /// a button nothing on the wire ever carried an extended code to Windows.
    #[test]
    fn an_extended_scan_code_becomes_a_low_byte_and_a_flag() {
        assert_eq!(split_extended(0xE037), (0x37, true), "Print Screen");
        assert_eq!(split_extended(0xE04B), (0x4B, true), "Left arrow");
        assert_eq!(split_extended(0xE01D), (0x1D, true), "Right Control");
    }

    /// The count behind every release message, on both platforms.
    ///
    /// A modifier held down is a held KEY — both backends press them as real
    /// key events — so a message that counted only `held.keys()` would report
    /// "0 key(s)" while Ctrl was stuck down, which is the most damaging one to
    /// under-report because window managers bind modifier-plus-click.
    #[test]
    fn a_held_modifier_counts_as_a_held_key() {
        use crate::message::{MOD_ALT, MOD_CTRL, MOD_SHIFT};
        assert_eq!(modifier_count(0), 0);
        assert_eq!(modifier_count(MOD_SHIFT), 1);
        assert_eq!(modifier_count(MOD_CTRL), 1);
        assert_eq!(modifier_count(MOD_ALT), 1);
        assert_eq!(modifier_count(MOD_SHIFT | MOD_CTRL), 2);
        assert_eq!(modifier_count(MOD_SHIFT | MOD_CTRL | MOD_ALT), 3);
        // Bits outside the three defined modifiers must not inflate the count.
        assert_eq!(modifier_count(0xF8), 0);
        assert_eq!(modifier_count(0xFF), 3);
    }

    /// An ordinary key must not acquire the extended flag. Ctrl+C is `0x2E`,
    /// and marking it extended would send a key that is not C.
    #[test]
    fn an_ordinary_scan_code_is_left_alone() {
        assert_eq!(split_extended(0x2E), (0x2E, false), "C");
        assert_eq!(split_extended(0x2F), (0x2F, false), "V");
        assert_eq!(split_extended(0x01), (0x01, false), "Escape");
        assert_eq!(
            split_extended(0x58),
            (0x58, false),
            "F12, the top of the plain bank"
        );
    }

    /// Only 0xE0 is a prefix. 0xE1 leads the Pause sequence and is not this,
    /// and a code with any other high byte is not a Set 1 code at all — so
    /// neither may be silently truncated into a plausible-looking key.
    #[test]
    fn only_the_e0_prefix_counts_as_extended() {
        assert_eq!(
            split_extended(0xE11D),
            (0xE11D, false),
            "Pause's own prefix"
        );
        assert_eq!(split_extended(0x1234), (0x1234, false));
    }

    #[test]
    fn control_messages_inject_nothing() {
        for m in [
            InputControlMessage::FocusGained,
            InputControlMessage::FocusLost,
            InputControlMessage::InputPause,
            InputControlMessage::InputResume,
            InputControlMessage::Capabilities {
                flags: 0,
                max_coalesce: 4,
            },
        ] {
            assert!(!is_os_input(&m), "{m:?} should not be OS input");
            // inject() must succeed and report nothing injected.
            assert_eq!(inject(&m).unwrap(), false);
        }
    }

    #[test]
    fn os_input_events_are_classified() {
        assert!(is_os_input(&InputControlMessage::MouseMove {
            mode: MouseMoveMode::Relative,
            dx: 1,
            dy: 1,
            abs_x: 0,
            abs_y: 0
        }));
        assert!(is_os_input(&InputControlMessage::KeyEvent {
            scan_code: 0x1E,
            action: KeyAction::Down,
            modifiers: 0
        }));
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use std::time::Duration;

    /// Nothing held is nothing to release — the common case, and it must never
    /// emit a key event of its own.
    #[test]
    fn silence_with_nothing_held_releases_nothing() {
        assert!(!should_release_idle(false, Duration::from_secs(600)));
    }

    /// A held button that is still hearing traffic is a live drag.
    #[test]
    fn a_drag_that_is_still_talking_is_left_alone() {
        assert!(!should_release_idle(true, Duration::from_secs(0)));
        assert!(!should_release_idle(
            true,
            INPUT_IDLE_RELEASE - Duration::from_millis(1)
        ));
    }

    /// Held, and the client has said nothing at all for the grace period.
    #[test]
    fn held_input_that_has_gone_quiet_is_released() {
        assert!(should_release_idle(true, INPUT_IDLE_RELEASE));
        assert!(should_release_idle(true, Duration::from_secs(3600)));
    }
}

/// The record of what is held. Platform-neutral by construction — it stores
/// what the wire said, not what either backend emitted — so these run on every
/// target rather than only on the one that happens to be building.
#[cfg(test)]
mod held_tests {
    use super::*;
    use crate::message::{MOD_ALT, MOD_CTRL, MOD_SHIFT};

    /// A press whose release never arrives is still held. This is the whole
    /// premise: without it the host has no idea it is holding anything, which
    /// is why the only release it had was a full shutdown.
    #[test]
    fn a_press_without_its_release_stays_held() {
        let mut h = HeldInput::new();
        h.observe_button(0, true);
        assert!(!h.is_empty(), "a pressed button must be recorded as held");
        assert_eq!(h.buttons(), vec![0]);
        assert!(h.keys().is_empty(), "a mouse button is not a key");
    }

    /// Down then Up leaves nothing behind. The ordinary case must not
    /// accumulate, or the release would fire on every disconnect and send Ups
    /// for things nobody is pressing.
    #[test]
    fn a_matched_press_and_release_holds_nothing() {
        let mut h = HeldInput::new();
        h.observe_button(0, true);
        h.observe_button(0, false);
        assert!(h.is_empty(), "a released button was still recorded as held");
    }

    /// A chord's modifiers are pressed as real key events on both backends, so
    /// a stuck Ctrl is as reachable as a stuck C — and considerably worse,
    /// since window managers bind modifier-plus-click and a desktop that
    /// highlights on hover but swallows every click is what the operator saw.
    #[test]
    fn a_chord_holds_its_modifiers_until_the_key_goes_up() {
        let mut h = HeldInput::new();
        h.observe_key(0x2E, MOD_CTRL, true); // Ctrl+C
        assert_eq!(h.keys(), vec![0x2E]);
        assert_eq!(h.modifiers(), MOD_CTRL, "Ctrl must be recorded as held");
        assert!(!h.is_empty());
        h.observe_key(0x2E, MOD_CTRL, false);
        assert!(h.is_empty(), "the chord's Up must release the modifier too");
    }

    /// Releasing one chord must not clear a modifier another chord is still
    /// holding — the bits are a set, not a latch.
    #[test]
    fn releasing_one_chord_leaves_another_modifier_alone() {
        let mut h = HeldInput::new();
        h.observe_key(0x2E, MOD_CTRL, true);
        h.observe_key(0x2F, MOD_SHIFT, true);
        h.observe_key(0x2E, MOD_CTRL, false);
        assert_eq!(h.modifiers(), MOD_SHIFT, "Shift was still held");
        assert_eq!(h.keys(), vec![0x2F]);
        assert!(!h.is_empty());
    }

    /// Only what was pressed may be released. A sweep of every key code is
    /// right for a shutdown and wrong on a live desktop, where it would
    /// release the key under the finger of whoever is sitting at it.
    #[test]
    fn only_what_was_pressed_is_recorded() {
        let mut h = HeldInput::new();
        h.observe_key(0x2E, 0, true);
        h.observe_button(1, true);
        assert_eq!(h.keys().len(), 1, "exactly one key was pressed");
        assert_eq!(h.modifiers(), 0, "no modifier was pressed");
        assert_eq!(h.buttons(), vec![1]);
        h.clear();
        assert!(h.is_empty());
    }

    /// An Up for something never pressed must not invent a release.
    #[test]
    fn a_stray_release_holds_nothing() {
        let mut h = HeldInput::new();
        h.observe_key(0x2F, MOD_CTRL | MOD_ALT, false);
        h.observe_button(2, false);
        assert!(h.is_empty(), "a release with nothing held must stay empty");
    }
}

#[cfg(test)]
mod delivery_tests {
    use super::*;

    /// The race this exists for, as a test the Linux side can run.
    ///
    /// A press that needs a moment to surface must be `Landed`, not
    /// `NotLanded` -- because `NotLanded` revokes the operator's control grant.
    /// Measured on Windows 2026-09-01: **22 of 25 ordinary mouse clicks** read
    /// back as not-down on the first look, so an unwaited check refuses almost
    /// every click on a desktop with nothing elevated anywhere near it.
    #[test]
    fn a_press_that_surfaces_late_is_landed_not_dropped() {
        let looks = std::sync::atomic::AtomicUsize::new(0);
        let verdict = confirm_down(|| {
            let n = looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(n >= 3)
        });
        assert_eq!(verdict, Delivery::Landed);
        assert!(
            looks.load(std::sync::atomic::Ordering::SeqCst) >= 4,
            "it must actually have waited rather than guessing"
        );
    }

    /// A press already visible costs one look and no sleep -- the common case
    /// for keys, and why this is affordable on the input path.
    #[test]
    fn a_press_already_visible_is_landed_on_the_first_look() {
        let looks = std::sync::atomic::AtomicUsize::new(0);
        let started = std::time::Instant::now();
        let verdict = confirm_down(|| {
            looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(true)
        });
        assert_eq!(verdict, Delivery::Landed);
        assert_eq!(looks.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(started.elapsed() < DELIVERY_CONFIRM_TIMEOUT);
    }

    /// A press that never arrives is still refused. Waiting must not have
    /// turned the UIPI check off.
    #[test]
    fn a_press_that_never_arrives_is_still_not_landed() {
        let started = std::time::Instant::now();
        assert_eq!(confirm_down(|| Some(false)), Delivery::NotLanded);
        assert!(
            started.elapsed() >= DELIVERY_CONFIRM_TIMEOUT,
            "it must wait the full budget before condemning a press"
        );
    }

    /// "I could not look" is not "it did not land", however long we wait.
    #[test]
    fn a_probe_that_cannot_answer_is_unknown_even_after_waiting() {
        assert_eq!(confirm_down(|| None), Delivery::Unknown);
        let looks = std::sync::atomic::AtomicUsize::new(0);
        let verdict = confirm_down(|| {
            let n = looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Some(false)
            } else {
                None
            }
        });
        assert_eq!(verdict, Delivery::Unknown);
        assert_ne!(verdict, Delivery::NotLanded);
    }

    /// The UIPI case, and the only one that refuses a grant.
    #[test]
    fn a_press_the_os_denies_is_not_landed() {
        assert_eq!(
            delivery_verdict(true, Some(false)),
            Delivery::NotLanded,
            "SendInput reported success and the OS says the key is up — that is \
             the phantom press the whole check exists for"
        );
    }

    #[test]
    fn a_press_the_os_confirms_has_landed() {
        assert_eq!(delivery_verdict(true, Some(true)), Delivery::Landed);
    }

    /// The property that keeps Linux working.
    ///
    /// Linux has no read-back at this layer and answers `None` every time. If
    /// `None` were treated as failure, every input grant on the platform the
    /// product mainly runs on would be refused the first time anyone pressed
    /// anything.
    #[test]
    fn no_read_back_is_never_a_refusal() {
        assert_eq!(delivery_verdict(true, None), Delivery::Unknown);
        assert_eq!(delivery_verdict(false, None), Delivery::Unknown);
        assert_ne!(delivery_verdict(true, None), Delivery::NotLanded);
    }

    /// A release is not what this guards. Judging Ups would refuse a grant on
    /// every correct key release, which is most of them.
    #[test]
    fn a_release_the_os_agrees_is_up_is_not_a_failure() {
        assert_eq!(delivery_verdict(false, Some(false)), Delivery::Landed);
        assert_ne!(delivery_verdict(false, Some(false)), Delivery::NotLanded);
    }
}
