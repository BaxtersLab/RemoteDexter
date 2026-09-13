//! Hardware-gated live input-injection proof.
//!
//! Runs only when `RD_USE_HW=1` (interactive desktop). Windows injects a real
//! absolute mouse move via `SendInput` and confirms the OS cursor actually
//! moved there (`GetCursorPos`) — proof the injector drives real input, not a
//! stub. Moves the cursor twice and checks both landings so a coincidental
//! starting position can't pass it.
//!
//! Linux has no `GetCursorPos` to check against: Wayland deliberately provides
//! no protocol for asking the compositor where the pointer is. The Linux test
//! therefore proves the other end — it exclusively grabs the evdev nodes for
//! its own virtual devices, then reads the injected events back and asserts the
//! exact codes and values. The grab prevents the live compositor from receiving
//! those events while the proof runs.

#[cfg(all(target_os = "linux", feature = "linux-input"))]
static LIVE_UINPUT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(windows)]
#[test]
fn live_absolute_mouse_move_lands() {
    use module10::inject::{cursor_pos, inject};
    use module10::message::{InputControlMessage, MouseMoveMode};

    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping live_absolute_mouse_move_lands (set RD_USE_HW=1)");
        return;
    }

    let targets = [(200i32, 200i32), (600i32, 400i32)];
    for (tx, ty) in targets {
        let msg = InputControlMessage::MouseMove {
            mode: MouseMoveMode::Absolute,
            dx: 0,
            dy: 0,
            abs_x: tx as u32,
            abs_y: ty as u32,
        };
        let injected = inject(&msg).expect("inject");
        assert!(injected, "absolute move should report an injected event");

        // Give the input queue a moment to apply.
        std::thread::sleep(std::time::Duration::from_millis(60));
        let (cx, cy) = cursor_pos().expect("cursor pos");
        eprintln!("target=({tx},{ty}) landed=({cx},{cy})");
        // Absolute normalization rounds across the virtual desktop; allow a
        // few px of slop but require it actually moved to the target vicinity.
        assert!(
            (cx - tx).abs() <= 3 && (cy - ty).abs() <= 3,
            "cursor did not land near ({tx},{ty}); got ({cx},{cy})"
        );
    }
}

/// The Linux twin: real uinput devices, real kernel events, read back and
/// checked value by value.
///
/// **Why read-back rather than "type into a window and look".** There is no
/// window to look at that would not also be somebody's work. Each virtual evdev
/// node is exclusively grabbed before injection, so the test process receives
/// the events but the live compositor does not. The key chosen is also a bare
/// Right Ctrl as defense in depth. It exercises the `0xE0`-prefixed extended
/// scan-code path, which the plain-ASCII keys do not.
#[cfg(all(target_os = "linux", feature = "linux-input"))]
#[test]
fn live_uinput_publishes_real_kernel_events() {
    use module10::inject_linux::{set_virtual_screen, UinputInjector};
    use module10::message::{InputControlMessage, KeyAction, MouseMoveMode};

    // Lower right of a 1920x1080 desktop — well away from anything likely to be
    // in use, and only ever moved to, never clicked.
    const TARGET: (u32, u32) = (1500, 820);
    const SCREEN: (u32, u32) = (1920, 1080);

    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping live_uinput_publishes_real_kernel_events (set RD_USE_HW=1)");
        return;
    }

    // Not `.unwrap()`. When the first hardware test panics — which is exactly
    // what happens on a machine with no input grant — it poisons this lock, and
    // the second test then dies with `PoisonError` instead of the real reason.
    // Observed on 2026-08-23 in the Block 7 red run: one honest "Permission
    // denied" and one useless cascade. The lock guards ordering, not data.
    let _guard = LIVE_UINPUT_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    set_virtual_screen(SCREEN.0, SCREEN.1);
    let mut inj = match UinputInjector::new() {
        Ok(i) => i,
        Err(e) => panic!(
            "could not create uinput devices: {e}\n{}",
            module10::inject_linux::UINPUT_GUIDANCE
        ),
    };

    // Open the nodes BEFORE injecting. evdev delivers only what arrives after
    // the descriptor is open, so opening afterwards reads an empty queue and
    // the test would fail for a reason with nothing to do with injection.
    let nodes = inj.dev_nodes();
    assert!(
        !nodes.is_empty(),
        "kernel published no device nodes for the virtual devices"
    );

    let mut readers: Vec<(String, evdev::Device)> = Vec::new();
    for path in &nodes {
        let Ok(mut dev) = evdev::Device::open(path) else {
            continue;
        };
        let name = dev.name().unwrap_or("?").to_string();
        if !name.starts_with("RemoteDexter") {
            continue;
        }
        dev.grab()
            .unwrap_or_else(|e| panic!("could not exclusively grab {name} at {}: {e}", path.display()));
        dev.set_nonblocking(true).expect("set nonblocking");
        readers.push((name, dev));
    }
    for expected in [
        "RemoteDexter Keyboard",
        "RemoteDexter Mouse",
        "RemoteDexter Abs Pointer",
    ] {
        assert!(
            readers.iter().any(|(name, _)| name == expected),
            "{expected} was not opened and grabbed; refusing to inject"
        );
    }
    eprintln!(
        "exclusively grabbed and reading back from: {:?}",
        readers.iter().map(|r| &r.0).collect::<Vec<_>>()
    );

    // Keyboard: bare Right Ctrl down then up. Extended set-1 scan code 0xE01D,
    // which translates to KEY_RIGHTCTRL(97). The exclusive grab contains it;
    // the inert key choice is a second safety boundary.
    const RIGHT_CTRL_SCAN: u16 = 0xE01D;
    const KEY_RIGHTCTRL: u16 = 97;
    inj.inject(&InputControlMessage::KeyEvent {
        scan_code: RIGHT_CTRL_SCAN,
        action: KeyAction::Down,
        modifiers: 0,
    })
    .expect("inject key down");
    inj.inject(&InputControlMessage::KeyEvent {
        scan_code: RIGHT_CTRL_SCAN,
        action: KeyAction::Up,
        modifiers: 0,
    })
    .expect("inject key up");

    // Pointer: absolute move to a known coordinate.
    inj.inject(&InputControlMessage::MouseMove {
        mode: MouseMoveMode::Absolute,
        dx: 0,
        dy: 0,
        abs_x: TARGET.0,
        abs_y: TARGET.1,
    })
    .expect("inject absolute move");

    let events = drain(&mut readers);
    eprintln!("read back {} events", events.len());

    let key_seq: Vec<i32> = events
        .iter()
        .filter(|(t, c, _)| *t == 1 /* EV_KEY */ && *c == KEY_RIGHTCTRL)
        .map(|(_, _, v)| *v)
        .collect();
    assert_eq!(
        key_seq,
        vec![1, 0],
        "expected KEY_RIGHTCTRL down then up, got {key_seq:?}"
    );

    let expect_x = (TARGET.0 as i64 * 65535 / (SCREEN.0 - 1) as i64) as i32;
    let expect_y = (TARGET.1 as i64 * 65535 / (SCREEN.1 - 1) as i64) as i32;
    let abs_x: Vec<i32> = events
        .iter()
        .filter(|(t, c, _)| *t == 3 /* EV_ABS */ && *c == 0 /* ABS_X */)
        .map(|(_, _, v)| *v)
        .collect();
    let abs_y: Vec<i32> = events
        .iter()
        .filter(|(t, c, _)| *t == 3 && *c == 1 /* ABS_Y */)
        .map(|(_, _, v)| *v)
        .collect();
    eprintln!("ABS_X={abs_x:?} (expect {expect_x}), ABS_Y={abs_y:?} (expect {expect_y})");
    assert_eq!(abs_x, vec![expect_x], "ABS_X did not carry the exact target");
    assert_eq!(abs_y, vec![expect_y], "ABS_Y did not carry the exact target");
}

#[cfg(all(target_os = "linux", feature = "linux-input"))]
#[test]
fn live_uinput_shutdown_releases_devices_and_allows_restart() {
    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!(
            "skipping live_uinput_shutdown_releases_devices_and_allows_restart (set RD_USE_HW=1)"
        );
        return;
    }

    // Not `.unwrap()`. When the first hardware test panics — which is exactly
    // what happens on a machine with no input grant — it poisons this lock, and
    // the second test then dies with `PoisonError` instead of the real reason.
    // Observed on 2026-08-23 in the Block 7 red run: one honest "Permission
    // denied" and one useless cascade. The lock guards ordering, not data.
    let _guard = LIVE_UINPUT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    module10::inject::shutdown();

    assert!(
        module10::inject_linux::is_real(),
        "could not create real uinput devices"
    );
    assert_remote_devices(true);

    module10::inject::shutdown();
    assert_remote_devices(false);

    assert!(
        module10::inject_linux::is_real(),
        "uinput devices could not be recreated after shutdown"
    );
    assert_remote_devices(true);
    module10::inject::shutdown();
    assert_remote_devices(false);
}

#[cfg(all(target_os = "linux", feature = "linux-input"))]
fn assert_remote_devices(expected_present: bool) {
    use std::time::Duration;

    for _ in 0..40 {
        let names = std::fs::read_dir("/sys/class/input")
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_to_string(entry.path().join("name")).ok())
            .map(|name| name.trim().to_string())
            .filter(|name| name.starts_with("RemoteDexter"))
            .collect::<Vec<_>>();
        let all_present = [
            "RemoteDexter Keyboard",
            "RemoteDexter Mouse",
            "RemoteDexter Abs Pointer",
        ]
        .iter()
        .all(|expected| names.iter().any(|name| name == expected));
        if all_present == expected_present {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    panic!("RemoteDexter uinput device presence did not become {expected_present}");
}

/// Read everything queued on every reader. Non-blocking, so a device with
/// nothing to say returns immediately instead of hanging the test; the settle
/// loop covers the kernel not having flushed yet.
#[cfg(all(target_os = "linux", feature = "linux-input"))]
fn drain(readers: &mut [(String, evdev::Device)]) -> Vec<(u16, u16, i32)> {
    use std::time::Duration;
    let mut out = Vec::new();
    for round in 0..40 {
        for (_, dev) in readers.iter_mut() {
            if let Ok(iter) = dev.fetch_events() {
                for ev in iter {
                    out.push((ev.event_type().0, ev.code(), ev.value()));
                }
            }
        }
        // Once anything has arrived, take one more pass so a batch split across
        // reads is not truncated mid-way.
        if !out.is_empty() && round > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    out
}

/// A press whose Up never came must be releasable, and the release must reach
/// the kernel.
///
/// **This is the test for the defect that cost the operator a hard power-off.**
/// The host had no way to let go of anything except `shutdown`, which runs on
/// host Stop — so a button held by a client that vanished mid-drag held the
/// desktop down, hovering still highlighted, no click landed, and the only exit
/// was the button on the tower.
///
/// The unit tests prove the *record* of what is held. Only this proves the
/// **effect**: that the Up events actually arrive at the kernel, for the key,
/// for the chord's modifier, and for the button.
///
/// Exclusively grabbed like its neighbours, so nothing reaches the live
/// compositor, and the codes are inert ones — Ctrl+C is not sent anywhere it
/// could be received, and the button is the middle one.
#[cfg(all(target_os = "linux", feature = "linux-input"))]
#[test]
fn live_uinput_releases_a_press_whose_up_never_came() {
    use module10::inject_linux::{set_virtual_screen, UinputInjector};
    use module10::message::{ButtonAction, InputControlMessage, KeyAction, MOD_CTRL};

    const KEY_C: u16 = 46;
    const KEY_LEFTCTRL: u16 = 29;
    const BTN_MIDDLE: u16 = 0x112;

    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping live_uinput_releases_a_press_whose_up_never_came (set RD_USE_HW=1)");
        return;
    }

    // Not `.unwrap()`: a poisoned lock from an earlier hardware failure must not
    // replace the real reason with a PoisonError. See the note above.
    let _guard = LIVE_UINPUT_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    set_virtual_screen(1920, 1080);
    let mut inj = match UinputInjector::new() {
        Ok(i) => i,
        Err(e) => panic!(
            "could not create uinput devices: {e}\n{}",
            module10::inject_linux::UINPUT_GUIDANCE
        ),
    };

    // Open and grab BEFORE injecting: evdev delivers only what arrives after
    // the descriptor is open.
    let nodes = inj.dev_nodes();
    let mut readers: Vec<(String, evdev::Device)> = Vec::new();
    for path in &nodes {
        let Ok(mut dev) = evdev::Device::open(path) else {
            continue;
        };
        let name = dev.name().unwrap_or("?").to_string();
        if !name.starts_with("RemoteDexter") {
            continue;
        }
        dev.grab().unwrap_or_else(|e| {
            panic!(
                "could not exclusively grab {name} at {}: {e}",
                path.display()
            )
        });
        dev.set_nonblocking(true).expect("set nonblocking");
        readers.push((name, dev));
    }
    for expected in ["RemoteDexter Keyboard", "RemoteDexter Mouse"] {
        assert!(
            readers.iter().any(|(name, _)| name == expected),
            "{expected} was not opened and grabbed; refusing to inject"
        );
    }

    // Down, and deliberately no Up — the client vanishing mid-press.
    inj.inject(&InputControlMessage::KeyEvent {
        scan_code: 0x2E, // C
        action: KeyAction::Down,
        modifiers: MOD_CTRL,
    })
    .expect("inject chord down");
    inj.inject(&InputControlMessage::MouseButton {
        button: 2, // middle
        action: ButtonAction::Down,
    })
    .expect("inject button down");

    inj.release_held().expect("release held input");

    let events = drain(&mut readers);
    eprintln!("read back {} events", events.len());
    let seq = |code: u16| -> Vec<i32> {
        events
            .iter()
            .filter(|(t, c, _)| *t == 1 /* EV_KEY */ && *c == code)
            .map(|(_, _, v)| *v)
            .collect()
    };
    assert_eq!(
        seq(KEY_C),
        vec![1, 0],
        "KEY_C was pressed and never released"
    );
    assert_eq!(
        seq(KEY_LEFTCTRL),
        vec![1, 0],
        "the chord's Ctrl was pressed and never released — a stuck modifier is \
         the more damaging half, since window managers bind modifier-plus-click"
    );
    assert_eq!(
        seq(BTN_MIDDLE),
        vec![1, 0],
        "the mouse button was pressed and never released"
    );

    // Releasing twice must not invent a second Up. A release that fires on
    // every disconnect regardless would send Ups for keys the person at the
    // machine is holding on their own keyboard.
    inj.release_held().expect("second release is a no-op");
    let again = drain(&mut readers);
    let stray: Vec<_> = again.iter().filter(|(t, _, _)| *t == 1).collect();
    assert!(
        stray.is_empty(),
        "releasing with nothing held emitted key events: {stray:?}"
    );
}

/// The **public** release entry point must reach the kernel, not merely clear
/// the host's record of what it holds.
///
/// ## Why this exists, and who found the gap
///
/// The Windows box, 2026-08-31. It added a `GetAsyncKeyState` read-back and
/// then broke `release_input_state` so it cleared `held` **without** calling
/// `send` — the exact shape of "the host thinks it let go, the desktop is still
/// held". Two of the three host-path tests reported `ok` over a machine that
/// was genuinely held down.
///
/// The same hole was open here. `live_uinput_releases_a_press_whose_up_never_came`
/// calls `release_held` on its own injector, and the three host-path tests
/// assert on `is_holding_input()` — the record. Nothing joined the two: a
/// `release_input_state` that cleared the record and emitted nothing would have
/// passed every test on this platform too.
///
/// So this drives the process-global path the host actually calls, and reads
/// the Up back off the kernel's own node.
#[cfg(all(target_os = "linux", feature = "linux-input"))]
#[test]
fn live_release_input_state_reaches_the_kernel() {
    use module10::message::{ButtonAction, InputControlMessage};

    const BTN_MIDDLE: u16 = 0x112;

    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping live_release_input_state_reaches_the_kernel (set RD_USE_HW=1)");
        return;
    }
    let _guard = LIVE_UINPUT_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    // Start from nothing held, so a leftover press cannot supply the Up.
    module10::inject::release_input_state();

    // Press through the process-global injector — the one the host uses. This
    // also creates the devices, which is why the nodes are opened afterwards.
    module10::inject::inject(&InputControlMessage::MouseButton {
        button: 2,
        action: ButtonAction::Down,
    })
    .expect("inject button down");
    assert!(
        module10::inject::is_holding_input(),
        "the host does not believe it is holding a button it just pressed"
    );

    // Only the RELEASE has to be read back, so opening after the press is
    // correct — evdev delivers what arrives after the descriptor is open.
    let mut readers: Vec<(String, evdev::Device)> = Vec::new();
    for entry in std::fs::read_dir("/dev/input").expect("read /dev/input") {
        let path = entry.expect("dir entry").path();
        if !path.to_string_lossy().contains("event") {
            continue;
        }
        let Ok(mut dev) = evdev::Device::open(&path) else {
            continue;
        };
        let name = dev.name().unwrap_or("?").to_string();
        if name != "RemoteDexter Mouse" {
            continue;
        }
        dev.grab()
            .unwrap_or_else(|e| panic!("could not grab {name} at {}: {e}", path.display()));
        dev.set_nonblocking(true).expect("set nonblocking");
        readers.push((name, dev));
    }
    assert!(
        !readers.is_empty(),
        "the global injector published no 'RemoteDexter Mouse' node to read back from"
    );

    module10::inject::release_input_state();

    let events = drain(&mut readers);
    let ups: Vec<i32> = events
        .iter()
        .filter(|(t, c, _)| *t == 1 /* EV_KEY */ && *c == BTN_MIDDLE)
        .map(|(_, _, v)| *v)
        .collect();
    assert_eq!(
        ups,
        vec![0],
        "release_input_state cleared the host's record but the kernel never saw the Up — \
         this is the stuck desktop, and every other test on this platform would have passed"
    );
    assert!(
        !module10::inject::is_holding_input(),
        "the record still says a button is held after the release"
    );
}
