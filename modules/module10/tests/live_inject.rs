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

/// RD-TEXT-1: the batch size in `keymap::TEXT_BATCH_EVENTS` rests on the
/// kernel's per-reader evdev buffer. This measures that buffer on a real
/// kernel instead of trusting the arithmetic in a doc comment.
///
/// Everything runs against the RemoteDexter keyboard's own node, EXCLUSIVELY
/// GRABBED so no compositor receives a keystroke, read through a RAW stream so
/// a `SYN_DROPPED` is seen rather than quietly resynchronised away.
///
/// The assertions are DETERMINISTIC: the reader drains on a fixed schedule
/// counted in batches, never on a timer. A uinput write lands in the reader's
/// buffer before `write` returns, so "the reader skipped two pauses" can be
/// staged exactly instead of hoped for.
///
/// 1. **Buffer control.** Nine shifted keystrokes (72 events) into a reader
///    that is not draining MUST overflow; otherwise nothing below could tell a
///    batch that fits from a buffer that never fills.
/// 2. **A paragraph, reader draining after every THIRD batch** — a compositor
///    that missed two pauses in a row. Every key event in order, none dropped.
/// 3. **The same paragraph, draining after every FOURTH batch** must overflow:
///    the margin claimed in the doc comment is exactly the one the kernel has.
/// 4. **Timing, reported only.** The paragraph paced as the host paces it, and
///    in one burst, against a reader polling every 200 µs. Timing can flake,
///    and a flaky assertion is a defect of its own; the deterministic runs are
///    the proof, these are the illustration.
///
/// VM only (BaxtersVMHarness). Never on a seated workstation.
#[cfg(all(target_os = "linux", feature = "linux-input"))]
#[test]
fn live_text_batches_fit_the_readers_evdev_buffer() {
    use evdev::raw_stream::RawDevice;
    use module10::inject_linux::UinputInjector;
    use module10::keymap::{kernel_events, text_to_plan, TypedKey, MAX_TEXT_CHARS};
    use module10::message::{InputControlMessage, KeyAction, MOD_SHIFT};
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const EV_SYN: u16 = 0;
    const EV_KEY: u16 = 1;
    const SYN_DROPPED: u16 = 3;
    const KEY_LEFTSHIFT: u16 = 42;
    const O_NONBLOCK: i32 = 0o4000;
    // host_app's TEXT_BATCH_PAUSE. Mirrored, not imported: module10 cannot
    // depend on the binary.
    const BATCH_PAUSE: Duration = Duration::from_millis(2);

    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping live_text_batches_fit_the_readers_evdev_buffer (set RD_USE_HW=1)");
        return;
    }
    let _guard = LIVE_UINPUT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut inj = UinputInjector::new().unwrap_or_else(|e| {
        panic!(
            "could not create uinput devices: {e}\n{}",
            module10::inject_linux::UINPUT_GUIDANCE
        )
    });

    let mut kb: Option<RawDevice> = None;
    for path in inj.dev_nodes() {
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(&path)
        else {
            continue;
        };
        let Ok(mut dev) = RawDevice::try_from(file) else {
            continue;
        };
        if dev.name() == Some("RemoteDexter Keyboard") {
            dev.grab()
                .expect("could not exclusively grab the RemoteDexter keyboard");
            kb = Some(dev);
            break;
        }
    }
    let kb = kb.expect("RemoteDexter Keyboard was not opened and grabbed; refusing to inject");
    let kb = Arc::new(std::sync::Mutex::new(kb));

    fn read_now(kb: &std::sync::Mutex<RawDevice>, out: &mut Vec<(u16, u16, i32)>) {
        let mut dev = kb.lock().unwrap();
        loop {
            match dev.fetch_events() {
                Ok(it) => {
                    let before = out.len();
                    out.extend(it.map(|e| (e.event_type().0, e.code(), e.value())));
                    if out.len() == before {
                        return;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(e) => panic!("reading the keyboard node failed: {e}"),
            }
        }
    }
    let dropped =
        |ev: &[(u16, u16, i32)]| ev.iter().any(|&(t, c, _)| t == EV_SYN && c == SYN_DROPPED);
    let keys_only = |ev: &[(u16, u16, i32)]| -> Vec<(u16, i32)> {
        ev.iter()
            .filter(|e| e.0 == EV_KEY)
            .map(|&(_, c, v)| (c, v))
            .collect()
    };
    // What inject_linux writes for a keystroke: Shift around the key, each its
    // own frame. Scan codes in the keymap's range ARE evdev codes (identity
    // through 0x58, pinned by keymap's own test).
    let expected = |keys: &[TypedKey]| -> Vec<(u16, i32)> {
        let mut out = Vec::new();
        for k in keys {
            for (m, down) in [(&k.down, true), (&k.up, false)] {
                let InputControlMessage::KeyEvent {
                    scan_code,
                    action,
                    modifiers,
                } = m
                else {
                    panic!("a text plan holds only key events")
                };
                assert_eq!(matches!(action, KeyAction::Down), down);
                assert!((0x01..=0x58).contains(scan_code));
                let shift = modifiers & MOD_SHIFT != 0;
                let v = i32::from(down);
                if down && shift {
                    out.push((KEY_LEFTSHIFT, 1));
                }
                out.push((*scan_code, v));
                if !down && shift {
                    out.push((KEY_LEFTSHIFT, 0));
                }
            }
        }
        out
    };
    let inject_keys = |inj: &mut UinputInjector, keys: &[TypedKey]| {
        for k in keys {
            inj.inject(&k.down).expect("inject key down");
            inj.inject(&k.up).expect("inject key up");
        }
    };
    let settle = || std::thread::sleep(Duration::from_millis(50));

    // Start clean: nothing queued from device creation.
    settle();
    read_now(&kb, &mut Vec::new());

    // 1. The buffer control: 72 events into a reader that is not reading.
    let nine = text_to_plan("ABCDEFGHI").unwrap();
    inject_keys(&mut inj, &nine.keys);
    settle();
    let mut ev = Vec::new();
    read_now(&kb, &mut ev);
    assert!(
        dropped(&ev),
        "nine shifted keystrokes (72 events) did not overflow the reader's buffer; \
         read {} events. The batch arithmetic rests on a buffer this kernel does not have.",
        ev.len()
    );
    eprintln!("buffer control: 72 events into an idle reader -> SYN_DROPPED");

    let sentence = "Typed in paced batches, Shift and all: 2,000 characters (one paragraph). ";
    let para: String = sentence.chars().cycle().take(MAX_TEXT_CHARS).collect();
    let plan = text_to_plan(&para).unwrap();
    let batches = plan.batches();
    let want = expected(&plan.keys);
    let total_events: usize = plan.keys.iter().map(kernel_events).sum();

    // 2 and 3. The reader drains only after every `every`-th batch.
    let lockstep = |every: usize, inj: &mut UinputInjector| -> Vec<(u16, u16, i32)> {
        let mut got = Vec::new();
        for (i, batch) in batches.iter().enumerate() {
            inject_keys(inj, batch);
            if (i + 1) % every == 0 {
                read_now(&kb, &mut got);
            }
        }
        read_now(&kb, &mut got);
        got
    };
    let three = lockstep(3, &mut inj);
    assert!(
        !dropped(&three),
        "a reader that missed two pauses lost events: three batches did not fit"
    );
    assert_eq!(
        keys_only(&three),
        want,
        "the paragraph arrived short or out of order"
    );
    eprintln!(
        "lockstep: drained every 3rd of {} batches -> all {} key events in order, none dropped",
        batches.len(),
        want.len()
    );

    settle();
    read_now(&kb, &mut Vec::new());
    let four = lockstep(4, &mut inj);
    assert!(
        dropped(&four),
        "draining only every 4th batch did not overflow; the claimed margin is not the real one"
    );
    eprintln!("lockstep control: drained every 4th batch -> SYN_DROPPED, so the margin is exact");

    // 4. Timing, reported only.
    let run = |paced: bool, inj: &mut UinputInjector| {
        settle();
        read_now(&kb, &mut Vec::new());
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let kb = Arc::clone(&kb);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut got = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    read_now(&kb, &mut got);
                    std::thread::sleep(Duration::from_micros(200));
                }
                read_now(&kb, &mut got);
                got
            })
        };
        let started = Instant::now();
        for (i, batch) in batches.iter().enumerate() {
            if paced && i > 0 {
                std::thread::sleep(BATCH_PAUSE);
            }
            inject_keys(inj, batch);
        }
        let took = started.elapsed();
        std::thread::sleep(Duration::from_millis(100));
        stop.store(true, Ordering::SeqCst);
        let got = reader.join().expect("reader thread");
        eprintln!(
            "{} run: {} keystrokes / {total_events} kernel events in {took:?}; \
             {} of {} key events read; SYN_DROPPED={}",
            if paced { "paced" } else { "burst" },
            plan.keys.len(),
            got.iter().filter(|e| e.0 == EV_KEY).count(),
            want.len(),
            dropped(&got)
        );
    };
    run(true, &mut inj);
    run(false, &mut inj);
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
