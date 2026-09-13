//! Linux input injection via `uinput` — the kernel's virtual input device.
//!
//! **Why uinput and not XTEST.** XTEST injects into the X server. Under a
//! native Wayland session there is no X server driving the desktop: XTEST
//! events reach XWayland, and no native Wayland client ever sees them. uinput
//! sits *below* the display server — the kernel publishes a real evdev device,
//! libinput reads it, and the compositor cannot tell it from a physical mouse
//! or keyboard. That is why it works on Wayland and X11 alike, and it is the
//! same mechanism `ydotool` and the sibling SOC suite use on this box.
//!
//! **Three devices, not one.** libinput classifies a device by the axes it
//! advertises, and a single device claiming relative motion, absolute motion
//! and keys at once is ambiguous. Each device here has a textbook shape:
//!
//! * `RemoteDexter Keyboard`     — EV_KEY over the key range
//! * `RemoteDexter Mouse`        — EV_REL X/Y/wheel + the three buttons
//! * `RemoteDexter Abs Pointer`  — EV_ABS X/Y over 0..=65535
//!
//! Buttons live on the relative mouse only. The compositor keeps one logical
//! cursor across all pointer devices, so an absolute move on one device
//! followed by a click on the other clicks at the new position.
//!
//! **Permissions.** `/dev/uinput` is not writable by ordinary users. Block 7
//! made the grant explicit and narrow: the host UI's **Enable input** action
//! installs one udev rule tagging this device with `uaccess`, so logind hands
//! it to whoever is at the machine. RemoteDexter deliberately does NOT ask
//! anyone to join the `input` group — that group also owns
//! `/dev/input/event*`, so joining it to move a cursor hands every process
//! running as that user a live keylogger. See `packaging/linux/README.md`.
//!
//! When the grant is absent, device creation fails and injection returns an
//! error on every event. It does not degrade to a silent no-op, and it does
//! not retry with anything weaker.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use evdev::uinput::VirtualDevice;
use evdev::{
    AbsInfo, AbsoluteAxisCode, AttributeSet, EventType, InputEvent, KeyCode, RelativeAxisCode,
    UinputAbsSetup,
};

use crate::errors::InputControlError;
use crate::message::{ButtonAction, InputControlMessage, KeyAction, MouseMoveMode, ScrollMode};

/// Absolute axis range. Deliberately the same 0..=65535 normalized space
/// `SendInput` uses on Windows, so both backends consume identical wire
/// coordinates and there is one normalization rule to reason about.
const ABS_MAX: i32 = 65535;

// Modifier bit flags come from `message`, so the backends cannot disagree.
use crate::message::{MOD_ALT, MOD_CTRL, MOD_SHIFT};

/// Hi-res wheel units per detent, per the kernel's REL_WHEEL_HI_RES contract.
/// Numerically the same 120 as Windows' `WHEEL_DELTA`, which is not a
/// coincidence — both inherited it from the original PS/2 wheel spec.
const WHEEL_DELTA: i32 = 120;

/// What to tell someone whose `/dev/uinput` is not writable.
///
/// This string used to say "add this account to the 'input' group". That
/// advice is what Block 7 exists to retract: the `input` group owns every
/// `/dev/input/event*` node, so taking it to move a pointer grants a permanent
/// read of every physical keyboard on the machine. The narrow grant is one
/// udev rule, installed only when the user asks for it.
pub const UINPUT_GUIDANCE: &str = "Open the RemoteDexter host and press \
    \"Enable input\". It installs one udev rule granting this seat write access \
    to /dev/uinput only; it does not add anyone to the 'input' group and does \
    not make keyboards or mice readable.";

/// How long to let udev and libinput notice a freshly created device. Events
/// emitted before the compositor has opened the node are simply lost, which
/// looks exactly like injection silently not working.
const DEVICE_SETTLE: Duration = Duration::from_millis(400);

struct InjectorSlot {
    injector: Option<UinputInjector>,
    attempted: bool,
    /// When the last input event was injected. `None` means none ever has
    /// been, which is not idleness — there is nothing held to release.
    last_input: Option<std::time::Instant>,
}

static INJECTOR: OnceLock<Mutex<InjectorSlot>> = OnceLock::new();
static SCREEN: OnceLock<Mutex<(u32, u32)>> = OnceLock::new();

/// Tell the injector the size of the desktop it is pointing at, so absolute
/// pixel coordinates can be normalized. The host sets this from the capture
/// backend's real frame size; without it the size is probed from
/// `/sys/class/drm`.
pub fn set_virtual_screen(width: u32, height: u32) {
    if width == 0 || height == 0 {
        return;
    }
    let cell = SCREEN.get_or_init(|| Mutex::new(detect_screen_size()));
    if let Ok(mut g) = cell.lock() {
        *g = (width, height);
    }
}

/// The desktop size absolute coordinates are normalized against. The host reads
/// this to describe the shareable surface's bounds without having to open a
/// capture session just to ask how big the screen is.
pub fn virtual_screen() -> (u32, u32) {
    *SCREEN
        .get_or_init(|| Mutex::new(detect_screen_size()))
        .lock()
        .map(|g| g)
        .unwrap_or_else(|p| p.into_inner())
}

/// Best-effort desktop size from the DRM connectors: the first mode listed for
/// a connector that has any is its current one. This is the same source the
/// sibling Hot Rod Tuner reads, and it needs no display-server connection —
/// which matters, because there is no portable way to ask a Wayland compositor
/// for this.
/// A FRESH read of the connector geometry, or `None` if nothing could be read.
///
/// Separate from [`detect_screen_size`] because of the fallback. That function
/// answers "what size should I aim input at", so it must always return
/// something and ends with a plausible `(1920, 1080)`. For CHANGE DETECTION
/// that guess is actively harmful: a probe that failed would be
/// indistinguishable from a display that had genuinely become 1920x1080, and a
/// host whose sysfs read broke would rebuild its capture forever.
///
/// So this reports failure honestly and the caller fails closed.
///
/// Also fresh on every call, unlike `virtual_screen()`, which caches — and is
/// then overwritten from the capture's own dimensions, making it useless as an
/// independent opinion about the display.
pub fn probe_screen_size() -> Option<(u32, u32)> {
    if let Ok(spec) = std::env::var("RD_SCREEN_SIZE") {
        if let Some((w, h)) = spec.split_once('x') {
            if let (Ok(w), Ok(h)) = (w.trim().parse::<u32>(), h.trim().parse::<u32>()) {
                if w > 0 && h > 0 {
                    return Some((w, h));
                }
            }
        }
    }
    let mut best = (0u32, 0u32);
    let entries = std::fs::read_dir("/sys/class/drm").ok()?;
    for e in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path().join("modes")) else {
            continue;
        };
        let Some(first) = text.lines().next() else {
            continue;
        };
        if let Some((w, h)) = first.trim().split_once('x') {
            if let (Ok(w), Ok(h)) = (w.parse::<u32>(), h.parse::<u32>()) {
                if w.saturating_mul(h) > best.0.saturating_mul(best.1) {
                    best = (w, h);
                }
            }
        }
    }
    if best.0 == 0 || best.1 == 0 {
        None
    } else {
        Some(best)
    }
}

fn detect_screen_size() -> (u32, u32) {
    // One reader, two answers: this one must always produce a size, so it
    // supplies the fallback the probe refuses to invent.
    probe_screen_size().unwrap_or((1920, 1080))
}

/// The three virtual devices, created on first use and held until host Stop.
pub struct UinputInjector {
    keyboard: VirtualDevice,
    mouse: VirtualDevice,
    abs_pointer: VirtualDevice,
    /// Everything currently pressed, so it can be released without a full sweep.
    held: crate::inject::HeldInput,
}

impl UinputInjector {
    pub fn new() -> std::io::Result<Self> {
        let mut keys = AttributeSet::<KeyCode>::new();
        // The whole standard key range. Advertising every key we might ever
        // translate to is required up front: the capability set is fixed when
        // the device is created, and a key outside it is dropped by the kernel.
        for code in 1u16..=248 {
            keys.insert(KeyCode::new(code));
        }
        let keyboard = VirtualDevice::builder()?
            .name("RemoteDexter Keyboard")
            .with_keys(&keys)?
            .build()?;

        let mut buttons = AttributeSet::<KeyCode>::new();
        buttons.insert(KeyCode::BTN_LEFT);
        buttons.insert(KeyCode::BTN_RIGHT);
        buttons.insert(KeyCode::BTN_MIDDLE);

        let mut rel = AttributeSet::<RelativeAxisCode>::new();
        rel.insert(RelativeAxisCode::REL_X);
        rel.insert(RelativeAxisCode::REL_Y);
        rel.insert(RelativeAxisCode::REL_WHEEL);
        rel.insert(RelativeAxisCode::REL_HWHEEL);
        rel.insert(RelativeAxisCode::REL_WHEEL_HI_RES);
        rel.insert(RelativeAxisCode::REL_HWHEEL_HI_RES);

        let mouse = VirtualDevice::builder()?
            .name("RemoteDexter Mouse")
            .with_keys(&buttons)?
            .with_relative_axes(&rel)?
            .build()?;

        // fuzz/flat both 0: any smoothing or dead zone would move the pointer
        // somewhere other than the exact coordinate the viewer asked for.
        let abs = AbsInfo::new(0, 0, ABS_MAX, 0, 0, 0);
        let abs_pointer = VirtualDevice::builder()?
            .name("RemoteDexter Abs Pointer")
            .with_keys(&buttons)?
            .with_absolute_axis(&UinputAbsSetup::new(AbsoluteAxisCode::ABS_X, abs))?
            .with_absolute_axis(&UinputAbsSetup::new(AbsoluteAxisCode::ABS_Y, abs))?
            .build()?;

        std::thread::sleep(DEVICE_SETTLE);
        Ok(Self {
            keyboard,
            mouse,
            abs_pointer,
            held: crate::inject::HeldInput::new(),
        })
    }

    /// Device node paths, for tests that want to read back what the kernel
    /// published.
    pub fn dev_nodes(&mut self) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for dev in [&mut self.keyboard, &mut self.mouse, &mut self.abs_pointer] {
            if let Ok(nodes) = dev.enumerate_dev_nodes_blocking() {
                out.extend(nodes.flatten());
            }
        }
        out
    }

    /// Inject through *this* injector rather than the process-wide one. The
    /// live hardware test drives it directly so it can read back from the very
    /// device nodes it created.
    pub fn inject(&mut self, msg: &InputControlMessage) -> Result<bool, InputControlError> {
        match msg {
            InputControlMessage::MouseMove {
                mode,
                dx,
                dy,
                abs_x,
                abs_y,
            } => {
                match mode {
                    MouseMoveMode::Relative => {
                        let mut evs = Vec::new();
                        if *dx != 0 {
                            evs.push(rel(RelativeAxisCode::REL_X, *dx));
                        }
                        if *dy != 0 {
                            evs.push(rel(RelativeAxisCode::REL_Y, *dy));
                        }
                        if !evs.is_empty() {
                            emit(&mut self.mouse, &evs)?;
                        }
                    }
                    MouseMoveMode::Absolute => {
                        let (nx, ny) = normalize_abs(*abs_x, *abs_y);
                        // Both axes in ONE batch, so the compositor sees a
                        // single atomic move rather than a horizontal hop
                        // followed by a vertical one.
                        emit(
                            &mut self.abs_pointer,
                            &[
                                abs_ev(AbsoluteAxisCode::ABS_X, nx),
                                abs_ev(AbsoluteAxisCode::ABS_Y, ny),
                            ],
                        )?;
                    }
                }
                Ok(true)
            }
            InputControlMessage::MouseButton { button, action } => {
                let key = button_key(*button)?;
                let down = matches!(action, ButtonAction::Down);
                emit(&mut self.mouse, &[key_ev(key, i32::from(down))])?;
                self.held.observe_button(*button, down);
                Ok(true)
            }
            InputControlMessage::MouseScroll { dx, dy, mode } => {
                let mut evs = Vec::new();
                // Lines are detents; pixels are hi-res units, 120 to a detent.
                // Both the coarse and the hi-res axis are sent because clients
                // read one or the other and a missing coarse event means older
                // toolkits scroll nothing at all.
                let (notch_y, hires_y) = match mode {
                    ScrollMode::Lines => (*dy, dy.saturating_mul(WHEEL_DELTA)),
                    ScrollMode::Pixels => (*dy / WHEEL_DELTA, *dy),
                };
                let (notch_x, hires_x) = match mode {
                    ScrollMode::Lines => (*dx, dx.saturating_mul(WHEEL_DELTA)),
                    ScrollMode::Pixels => (*dx / WHEEL_DELTA, *dx),
                };
                if hires_y != 0 {
                    evs.push(rel(RelativeAxisCode::REL_WHEEL_HI_RES, hires_y));
                }
                if notch_y != 0 {
                    evs.push(rel(RelativeAxisCode::REL_WHEEL, notch_y));
                }
                if hires_x != 0 {
                    evs.push(rel(RelativeAxisCode::REL_HWHEEL_HI_RES, hires_x));
                }
                if notch_x != 0 {
                    evs.push(rel(RelativeAxisCode::REL_HWHEEL, notch_x));
                }
                if !evs.is_empty() {
                    emit(&mut self.mouse, &evs)?;
                }
                Ok(true)
            }
            InputControlMessage::KeyEvent {
                scan_code,
                action,
                modifiers,
            } => {
                let key = set1_to_evdev(*scan_code).ok_or(InputControlError::Malformed)?;
                let down = matches!(action, KeyAction::Down);
                // Modifiers wrap the key: pressed before a key-down, released
                // after a key-up. Each goes in its own batch, because a
                // modifier and the key it modifies arriving in one SYN frame
                // can be processed as simultaneous and lose the combination.
                let mods = modifier_keys(*modifiers);
                if down {
                    for m in &mods {
                        emit(&mut self.keyboard, &[key_ev(*m, 1)])?;
                    }
                }
                emit(&mut self.keyboard, &[key_ev(key, i32::from(down))])?;
                if !down {
                    for m in &mods {
                        emit(&mut self.keyboard, &[key_ev(*m, 0)])?;
                    }
                }
                self.held.observe_key(*scan_code, *modifiers, down);
                Ok(true)
            }
            // Non-OS-input control messages: nothing to inject.
            _ => Ok(false),
        }
    }

    /// Release exactly what this injector is holding, leaving the devices in
    /// place.
    ///
    /// Unlike [`Self::release_all`] this is safe to call on a live desktop: it
    /// touches only codes the host itself pressed, so it cannot release a key
    /// the operator is holding on the machine's own keyboard.
    ///
    /// [`crate::inject::HeldInput`] records what the WIRE said — Set 1 scan
    /// codes, modifier bits, client button ids — so the same record serves both
    /// backends. The translation into evdev happens here, by the same two
    /// functions the press went through.
    pub fn release_held(&mut self) -> Result<(), InputControlError> {
        if self.held.is_empty() {
            return Ok(());
        }
        let mut keys: Vec<InputEvent> = self
            .held
            .keys()
            .iter()
            .filter_map(|scan| set1_to_evdev(*scan))
            .map(|code| key_ev(code, 0))
            .collect();
        keys.extend(
            modifier_keys(self.held.modifiers())
                .into_iter()
                .map(|m| key_ev(m, 0)),
        );
        if !keys.is_empty() {
            emit(&mut self.keyboard, &keys)?;
        }
        let buttons: Vec<InputEvent> = self
            .held
            .buttons()
            .iter()
            .filter_map(|b| button_key(*b).ok())
            .map(|code| key_ev(code, 0))
            .collect();
        if !buttons.is_empty() {
            emit(&mut self.mouse, &buttons)?;
        }
        self.held.clear();
        Ok(())
    }

    fn release_all(&mut self) -> Result<(), InputControlError> {
        let keyboard = (1u16..=248).map(|code| key_ev(code, 0)).collect::<Vec<_>>();
        emit(&mut self.keyboard, &keyboard)?;
        emit(
            &mut self.mouse,
            &[
                key_ev(KeyCode::BTN_LEFT.0, 0),
                key_ev(KeyCode::BTN_RIGHT.0, 0),
                key_ev(KeyCode::BTN_MIDDLE.0, 0),
            ],
        )
    }
}

fn emit(dev: &mut VirtualDevice, events: &[InputEvent]) -> Result<(), InputControlError> {
    dev.emit(events)
        .map_err(|e| InputControlError::Injection(format!("uinput emit: {e}")))
}

fn key_ev(code: u16, value: i32) -> InputEvent {
    InputEvent::new(EventType::KEY.0, code, value)
}

fn rel(axis: RelativeAxisCode, value: i32) -> InputEvent {
    InputEvent::new(EventType::RELATIVE.0, axis.0, value)
}

fn abs_ev(axis: AbsoluteAxisCode, value: i32) -> InputEvent {
    InputEvent::new(EventType::ABSOLUTE.0, axis.0, value)
}

fn button_key(button: u8) -> Result<u16, InputControlError> {
    // 0 = left, 1 = right, 2 = middle (matches the client button ids).
    Ok(match button {
        0 => KeyCode::BTN_LEFT.0,
        1 => KeyCode::BTN_RIGHT.0,
        2 => KeyCode::BTN_MIDDLE.0,
        _ => return Err(InputControlError::Malformed),
    })
}

fn modifier_keys(modifiers: u8) -> Vec<u16> {
    let mut out = Vec::new();
    if modifiers & MOD_SHIFT != 0 {
        out.push(KeyCode::KEY_LEFTSHIFT.0);
    }
    if modifiers & MOD_CTRL != 0 {
        out.push(KeyCode::KEY_LEFTCTRL.0);
    }
    if modifiers & MOD_ALT != 0 {
        out.push(KeyCode::KEY_LEFTALT.0);
    }
    out
}

/// Map a desktop pixel coordinate into the device's 0..=65535 absolute range —
/// the direct counterpart of the Windows backend's `normalize_abs`.
pub(crate) fn normalize_abs(x: u32, y: u32) -> (i32, i32) {
    let (w, h) = virtual_screen();
    let nx = (x as i64 * ABS_MAX as i64) / (w.saturating_sub(1).max(1) as i64);
    let ny = (y as i64 * ABS_MAX as i64) / (h.saturating_sub(1).max(1) as i64);
    ((nx as i32).clamp(0, ABS_MAX), (ny as i32).clamp(0, ABS_MAX))
}

/// Translate a PS/2 **set-1** scan code — what the wire carries, because the
/// Windows backend feeds it straight to `SendInput` with `KEYEVENTF_SCANCODE` —
/// into a Linux evdev key code.
///
/// For `0x01..=0x58` the translation is the identity. That is not luck: Linux
/// assigned `KEY_ESC = 1`, `KEY_1 = 2`, … deliberately to match AT set-1, and
/// the run holds unbroken through `KEY_F12 = 88 = 0x58`. Past that the two
/// numberings diverge and each code has to be named.
///
/// Extended keys arrive `0xE0`-prefixed in the high byte (`0xE04D` = Right
/// Arrow); the Windows path expresses the same thing as a separate
/// `KEYEVENTF_EXTENDEDKEY` flag, which this protocol has no room for.
pub(crate) fn set1_to_evdev(scan: u16) -> Option<u16> {
    match scan {
        0 => None,
        0x01..=0x58 => Some(scan),
        _ if scan >> 8 == 0xE0 => extended_to_evdev(scan as u8),
        _ => None,
    }
}

fn extended_to_evdev(low: u8) -> Option<u16> {
    Some(match low {
        0x1C => KeyCode::KEY_KPENTER.0,
        0x1D => KeyCode::KEY_RIGHTCTRL.0,
        0x20 => KeyCode::KEY_MUTE.0,
        0x2E => KeyCode::KEY_VOLUMEDOWN.0,
        0x30 => KeyCode::KEY_VOLUMEUP.0,
        0x35 => KeyCode::KEY_KPSLASH.0,
        0x37 => KeyCode::KEY_SYSRQ.0,
        0x38 => KeyCode::KEY_RIGHTALT.0,
        0x46 => KeyCode::KEY_PAUSE.0,
        0x47 => KeyCode::KEY_HOME.0,
        0x48 => KeyCode::KEY_UP.0,
        0x49 => KeyCode::KEY_PAGEUP.0,
        0x4B => KeyCode::KEY_LEFT.0,
        0x4D => KeyCode::KEY_RIGHT.0,
        0x4F => KeyCode::KEY_END.0,
        0x50 => KeyCode::KEY_DOWN.0,
        0x51 => KeyCode::KEY_PAGEDOWN.0,
        0x52 => KeyCode::KEY_INSERT.0,
        0x53 => KeyCode::KEY_DELETE.0,
        0x5B => KeyCode::KEY_LEFTMETA.0,
        0x5C => KeyCode::KEY_RIGHTMETA.0,
        0x5D => KeyCode::KEY_COMPOSE.0,
        _ => return None,
    })
}

fn injector_slot() -> &'static Mutex<InjectorSlot> {
    INJECTOR.get_or_init(|| {
        Mutex::new(InjectorSlot {
            injector: None,
            attempted: false,
            last_input: None,
        })
    })
}

fn initialize(slot: &mut InjectorSlot) {
    if slot.attempted {
        return;
    }
    slot.attempted = true;
    match UinputInjector::new() {
        Ok(injector) => slot.injector = Some(injector),
        Err(e) => {
            eprintln!("[module10] uinput unavailable ({e}); input injection is DISABLED. {UINPUT_GUIDANCE}");
        }
    }
}

/// Inject one event. The virtual devices are created on first use and held
/// until host Stop so the compositor has stable nodes for the whole session.
pub fn inject(msg: &InputControlMessage) -> Result<bool, InputControlError> {
    let mut guard = injector_slot().lock().unwrap_or_else(|p| p.into_inner());
    initialize(&mut guard);
    // Stamped before the result is known: an event the kernel refused is still
    // the client talking, and the idle watchdog is asking whether the client
    // has gone quiet, not whether it has succeeded.
    guard.last_input = Some(std::time::Instant::now());
    match guard.injector.as_mut() {
        Some(inj) => inj.inject(msg),
        None => Err(InputControlError::Injection(
            "uinput device unavailable".into(),
        )),
    }
}

/// Whether this backend is holding anything down.
pub fn is_holding_input() -> bool {
    let guard = injector_slot().lock().unwrap_or_else(|p| p.into_inner());
    guard.injector.as_ref().is_some_and(|i| !i.held.is_empty())
}

/// Release held input if the client has said nothing for
/// [`crate::inject::INPUT_IDLE_RELEASE`]. Returns true if anything was let go.
///
/// The third and last of the ways the host could be left holding a machine
/// down. [`release_input_state`] covers a client that goes away and
/// [`shutdown`] covers host Stop; neither covers a client that is still
/// connected and has simply stopped speaking.
pub fn release_if_idle() -> bool {
    let mut guard = injector_slot().lock().unwrap_or_else(|p| p.into_inner());
    let idle = match guard.last_input {
        Some(t) => t.elapsed(),
        None => return false,
    };
    let held = guard.injector.as_ref().is_some_and(|i| !i.held.is_empty());
    if !crate::inject::should_release_idle(held, idle) {
        return false;
    }
    let Some(inj) = guard.injector.as_mut() else {
        return false;
    };
    let keys = inj.held.keys().len();
    let buttons = inj.held.buttons().len();
    match inj.release_held() {
        Ok(()) => {
            eprintln!(
                "[module10] released input held with no client traffic for {}s: {keys} key(s), {buttons} button(s)",
                idle.as_secs()
            );
            true
        }
        Err(e) => {
            eprintln!("[module10] could not release idle input state: {e}");
            false
        }
    }
}

/// Release everything the host is holding **without** destroying the devices.
///
/// Called when the client goes away. Until this existed the only release was
/// [`shutdown`], which runs on host Stop — so a press whose Up never arrived
/// held the desktop hostage until the host was stopped, and if the desktop was
/// locked up there was no way left to stop it.
pub fn release_input_state() {
    let mut guard = injector_slot().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(inj) = guard.injector.as_mut() {
        // Count BEFORE releasing: release_held clears the record, so asking
        // afterwards always reports nothing.
        let keys = inj.held.keys().len() + crate::inject::modifier_count(inj.held.modifiers());
        let buttons = inj.held.buttons().len();
        match inj.release_held() {
            // Say what was let go, and say it even when the answer is nothing.
            //
            // P9 was run on hardware on 2026-09-05 and this path printed
            // NOTHING on success, so the operator run could not tell "the host
            // released the button, then exited" from "the host exited and the
            // kernel cleaned up when the uinput devices were destroyed". Those
            // produce an identical end state — no stuck desktop, port closed,
            // devices gone — so the observable outcome could not isolate the
            // property the test exists to prove.
            //
            // The mechanism is proven in the VM by
            // live_release_input_state_reaches_the_kernel, which reads the Up
            // off the kernel's own node. What was missing was an artifact from
            // the real end-to-end path, on a real seat, with a real phone.
            Ok(()) if keys == 0 && buttons == 0 => {
                eprintln!("[module10] released input state: nothing was held");
            }
            Ok(()) => {
                eprintln!("[module10] released input state: {keys} key(s), {buttons} button(s)");
            }
            Err(e) => eprintln!("[module10] could not release held input state: {e}"),
        }
    }
}

/// Release held input state and destroy the process-global uinput devices.
/// The next accepted input event creates a fresh set for a later host Start.
pub fn shutdown() {
    let mut guard = injector_slot().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(mut injector) = guard.injector.take() {
        // Count BEFORE releasing, and say it. THIS is the clean-shutdown path
        // P9 is about, and until 2026-09-05 it printed nothing on success.
        //
        // The hardware run that day held a mouse button through the window
        // close — the log shows a `button 0 Down` with no matching Up, so the
        // condition was genuinely met — and produced no release line at all,
        // because the instrumentation had been added to release_input_state().
        // That is the CLIENT-DISAPPEARED path; closing the window calls
        // shutdown() instead. Two paths, and the test took the other one.
        //
        // Without this line the outcome is unfalsifiable: release_all() emits
        // the Ups and then the devices are destroyed, and a destroyed uinput
        // device releases whatever it held anyway. "The host let go" and "the
        // kernel cleaned up after it" leave an identical desktop.
        let keys =
            injector.held.keys().len() + crate::inject::modifier_count(injector.held.modifiers());
        let buttons = injector.held.buttons().len();
        match injector.release_all() {
            Ok(()) if keys == 0 && buttons == 0 => {
                eprintln!("[module10] shutdown released input state: nothing was held");
            }
            Ok(()) => {
                eprintln!(
                    "[module10] shutdown released input state: {keys} key(s), {buttons} button(s)"
                );
            }
            Err(e) => {
                eprintln!("[module10] could not release all input state during shutdown: {e}")
            }
        }
    }
    guard.attempted = false;
}

/// True when real devices were created and events are reaching the kernel.
pub fn is_real() -> bool {
    let mut guard = injector_slot().lock().unwrap_or_else(|p| p.into_inner());
    initialize(&mut guard);
    guard.injector.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The operator-facing failure message is product behaviour, and for the
    /// whole life of this module it told people to run `usermod -aG input`.
    /// That grants a permanent read of every `/dev/input/event*` node — every
    /// physical keyboard on the machine — to move a cursor. Block 7 replaced
    /// it with the narrow opt-in, and this is what stops it coming back.
    #[test]
    fn the_failure_message_never_recommends_the_input_group() {
        // Naming the group in order to say we do NOT use it is fine and
        // useful. What must never return is the instruction to join it.
        for forbidden in ["usermod", "-aG input", "add this account", "must be in the"] {
            assert!(
                !UINPUT_GUIDANCE.contains(forbidden),
                "uinput guidance tells the operator to widen access: {UINPUT_GUIDANCE}"
            );
        }
        assert!(
            UINPUT_GUIDANCE.contains("does not add anyone to the 'input' group"),
            "the guidance should say what it deliberately does not do"
        );
        assert!(
            UINPUT_GUIDANCE.contains("Enable input"),
            "the guidance must name the action that actually fixes it"
        );
    }

    #[test]
    fn set1_identity_holds_over_the_documented_range() {
        // The claim the mapping rests on, spot-checked at both ends and at the
        // landmarks: Esc, A, Enter, LShift, Space, F1, F12.
        for (scan, key) in [
            (0x01u16, KeyCode::KEY_ESC),
            (0x1E, KeyCode::KEY_A),
            (0x1C, KeyCode::KEY_ENTER),
            (0x2A, KeyCode::KEY_LEFTSHIFT),
            (0x39, KeyCode::KEY_SPACE),
            (0x3B, KeyCode::KEY_F1),
            (0x58, KeyCode::KEY_F12),
        ] {
            assert_eq!(set1_to_evdev(scan), Some(key.0), "scan {scan:#x}");
        }
    }

    #[test]
    fn extended_codes_translate() {
        assert_eq!(set1_to_evdev(0xE04D), Some(KeyCode::KEY_RIGHT.0));
        assert_eq!(set1_to_evdev(0xE048), Some(KeyCode::KEY_UP.0));
        assert_eq!(set1_to_evdev(0xE05B), Some(KeyCode::KEY_LEFTMETA.0));
        assert_eq!(set1_to_evdev(0xE01D), Some(KeyCode::KEY_RIGHTCTRL.0));
    }

    #[test]
    fn unmapped_scan_codes_are_rejected_not_guessed() {
        assert_eq!(set1_to_evdev(0), None);
        assert_eq!(set1_to_evdev(0x59), None); // past the identity run
        assert_eq!(set1_to_evdev(0xE000), None); // no such extended key
    }

    #[test]
    fn absolute_normalization_spans_the_full_range() {
        set_virtual_screen(1920, 1080);
        assert_eq!(normalize_abs(0, 0), (0, 0));
        assert_eq!(normalize_abs(1919, 1079), (ABS_MAX, ABS_MAX));
        // Centre lands within a rounding step of half range.
        let (cx, cy) = normalize_abs(960, 540);
        assert!((cx - ABS_MAX / 2).abs() < 64, "cx={cx}");
        assert!((cy - ABS_MAX / 2).abs() < 64, "cy={cy}");
        // Out of range is clamped, never wrapped onto the opposite edge.
        assert_eq!(normalize_abs(99_999, 99_999), (ABS_MAX, ABS_MAX));
    }

    #[test]
    fn buttons_map_and_reject_unknown() {
        assert_eq!(button_key(0).unwrap(), KeyCode::BTN_LEFT.0);
        assert_eq!(button_key(1).unwrap(), KeyCode::BTN_RIGHT.0);
        assert_eq!(button_key(2).unwrap(), KeyCode::BTN_MIDDLE.0);
        assert!(button_key(7).is_err());
    }

    #[test]
    fn modifier_bits_expand_to_left_hand_keys() {
        assert!(modifier_keys(0).is_empty());
        assert_eq!(modifier_keys(MOD_SHIFT), vec![KeyCode::KEY_LEFTSHIFT.0]);
        assert_eq!(
            modifier_keys(MOD_SHIFT | MOD_CTRL | MOD_ALT),
            vec![
                KeyCode::KEY_LEFTSHIFT.0,
                KeyCode::KEY_LEFTCTRL.0,
                KeyCode::KEY_LEFTALT.0
            ]
        );
    }
}
