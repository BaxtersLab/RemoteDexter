# RemoteDexter — Android input spec

**Written on the dev box, 2026-08-19**, against `module10`'s actual wire types
and the host's own tests. Supersedes the premise of the 2026-08-17 test-box
report.

---

## 0. Correction first: this is mostly built already

The 2026-08-17 streaming report concluded that the Android client has *"zero code
anywhere to send input"* after grepping for `input_event` / `grant_input` /
`OnTouchListener`. **That is no longer true of this tree**, and a spec written on
that premise would re-specify working code.

Verified present and wired in `apk/app/src/main/java/com/remotedexter/`:

| piece | where | state |
|---|---|---|
| `InputController` object | `InputController.kt` (171 lines) | grant/revoke handshake, relative move, left click |
| gesture source | `MainActivity.kt:38–70` — `GestureDetector` | `onScroll` → `onDrag`, `onSingleTapConfirmed` → `onTap` |
| touch plumbing | `MainActivity.kt:158–162` — `setOnTouchListener` | both detectors fed |
| ack / denial routing | `SessionOrchestrator.kt:150, 198` | `grant_input`/`revoke_input` → `InputController` |
| UI toggle + lifecycle | `MainActivity.kt:137, 167–188, 243–244` | truthful label, `reset()` on end |
| pinch-zoom / two-finger pan | `MainActivity.kt:83–99` | client-side view only, no protocol traffic |

So the remaining work is **not** "build touch control". It is the list in §5.

---

## 1. Licensing boundary — read this before opening any reference

Do not copy, translate, vendor, link or wrap any third-party implementation into
RemoteDexter. A thin shim does not launder a licence: wrapping creates a combined
work and the terms attach through it, and a copyleft network clause reaches users
who interact with the program **over a network** — exactly what this product is.

This costs nothing, because every fact needed below comes from primary sources:

- **Android touch**: `MotionEvent` (`getActionMasked`, `getX(int)`,
  `getPointerCount`, `getHistorySize`/`getHistoricalX`), `View.setOnTouchListener`,
  `GestureDetector`, `ScaleGestureDetector`, `ViewConfiguration`
  (`getScaledTouchSlop`, `getLongPressTimeout`) — Android developer docs.
- **Linux injection**: kernel `Documentation/input/uinput.rst`,
  `linux/input-event-codes.h`, the `evdev` crate this repo already depends on.
- **This repo's own** `module10` and `host_app`, which are the authority for
  everything on the wire.

Where a KDoc or comment justifies a choice by pointing at what some other product
does, **restate the justification from the reasoning, not the citation**, so no
file carries a provenance claim. Relative-first pointer motion, for example, is a
sound choice on its own merits (§4.6) and should be defended that way.

---

## 2. Transport — the JSON path, not the binary one

`module10` has **two** input paths. Using the wrong one is the single most
expensive mistake available here.

| path | what it is | use it? |
|---|---|---|
| `module10::encode` / `decode` + `InputControlStream` | binary frames over `multiplexer::FramedStream` | **No.** Not what the host's Android command handler reads. |
| `serde_json` of `InputControlMessage` inside an Agent2 command | JSON over the pinned Noise session, via `RDRust.sendCommand` | **Yes.** This is what `host_app` parses. |

Authority: `host_app/src/main.rs:825` — `serde_json::from_value(event)`. The
exact shape is fixed by the host's own passing tests
(`input_requires_permitted_window_and_explicit_control_grant`), quoted verbatim:

```json
{"type":"input_event","window":42,"event":{"MouseMove":{"mode":"Relative","dx":0,"dy":0,"abs_x":0,"abs_y":0}}}
```

`InputControlMessage` is an **externally tagged** serde enum: variant name as the
sole key, fields as its object. Unit variants (`FocusGained`, `InputPause`, …)
serialize as the bare **string** `"FocusGained"`, not an object — that asymmetry
is easy to get wrong.

Every `input_event` must carry `"window"`, and it must equal the surface actually
streaming (`SessionOrchestrator.currentWindowId()`).

---

## 3. Preconditions the host enforces — all three, or it is denied

From `input_gate()` (`host_app/src/main.rs:807–856`), in order:

1. **`RD_CAP_INPUT=1`** in the host's environment. Unset by default; armed by
   whoever runs `run.sh`. Denial: `json_cap_denied`.
2. **The window is in the permitted allow-list** — which starts empty.
3. **An explicit `grant_input`** — view-only is the default even for a permitted
   window. `revoke_input` re-denies immediately.

Plus, on the Linux host, membership of the **`input` group** — `/dev/uinput` is
`root:input 0660`. Without it, device creation fails and injection degrades to a
reporting no-op with one loud warning (`inject_linux.rs`). **This is invisible
from the client**: every command is still ACKed. If control appears dead with no
denials, check group membership first.

---

## 4. The message catalogue, as the host actually reads it

### 4.1 `MouseMove` — relative

```json
{"MouseMove":{"mode":"Relative","dx":<i32>,"dy":<i32>,"abs_x":0,"abs_y":0}}
```
`abs_x`/`abs_y` are ignored but **must be present** — serde requires every field.
Host emits `REL_X`/`REL_Y` on `RemoteDexter Mouse`; zero components are skipped.

### 4.2 `MouseMove` — absolute

```json
{"MouseMove":{"mode":"Absolute","dx":0,"dy":0,"abs_x":<u32>,"abs_y":<u32>}}
```

**`abs_x`/`abs_y` are host desktop pixels, NOT normalized 0..65535.** The
0..65535 range is the uinput axis range; the host normalizes internally
(`normalize_abs`: `x * 65535 / (w-1)`). Sending normalized values would put the
cursor in the top-left ~0.03% of the screen.

Valid range is the permitted window's rect, **half-open**: `l <= x < r`,
`t <= y < b`. `abs_x == width` is refused.

On Linux `share_source::rect` returns `Some((0,0,w,h))` **only** for the desktop
surface (`DESKTOP_ID == i64::MAX == 9223372036854775807`) and `None` for every
other id — and a `None` rect makes an absolute move **fail closed**. Since the
Linux host offers exactly one surface (the whole desktop), absolute mode is
usable today; it is unusable against any other window id.

### 4.3 `MouseButton`

```json
{"MouseButton":{"button":<0|1|2>,"action":"Down"|"Up"}}
```
**0 = left, 1 = right, 2 = middle** (`button_key`). Any other value is
`Malformed`. Buttons live on the *relative* mouse device, but the compositor
keeps one logical cursor, so an absolute move followed by a click clicks at the
new position.

### 4.4 `MouseScroll`

```json
{"MouseScroll":{"dx":<i32>,"dy":<i32>,"mode":"Lines"|"Pixels"}}
```
`Lines` = detents (host multiplies by 120 for the hi-res axis). `Pixels` = hi-res
units, **120 per detent**; the host divides by 120 for the coarse axis, so any
`|dy| < 120` in `Pixels` mode produces **no coarse event at all** and older
toolkits scroll nothing. Prefer `Lines` for discrete flicks; if using `Pixels`,
accumulate to at least 120.

### 4.5 `KeyEvent`

```json
{"KeyEvent":{"scan_code":<u16>,"action":"Down"|"Up","modifiers":<u8>}}
```
`scan_code` is a **PS/2 set-1** code, not an Android keycode and not an evdev
code. For `0x01..=0x58` set-1 and evdev coincide by design (`KEY_ESC=1`,
`KEY_1=2`, … `KEY_F12=0x58`); past that each is mapped by name. Extended keys are
`0xE0`-prefixed in the high byte (`0xE04D` = Right Arrow).

`modifiers` bitfield — **`SHIFT=0x01`, `CTRL=0x02`, `ALT=0x04`**. The host presses
modifiers before a key-down and releases them after the key-up, each in its own
batch. Do **not** also send separate modifier `KeyEvent`s; that double-presses.

### 4.6 Why relative stays the default

Not because another project does it. Because: it needs no resolution knowledge,
it degrades gracefully when the view is zoomed or panned (the client-side pinch
zoom in `MainActivity` changes the mapping continuously), and a finger is a poor
absolute pointing device on a 6" screen showing a 1920px desktop — one finger-
width is ~40 desktop pixels. Absolute is worth adding as an explicit *mode*
(§5.6), not as the default.

---

## 5. What remains to build

Ordered by value per unit of work.

### 5.1 Sub-pixel accumulation — a real bug, fix first — ✅ **DONE 2026-08-19**

`InputController.onDrag` does `(dxPixels * SENSITIVITY).toInt()` and returns
early when both are 0. `toInt()` truncates toward zero, so **every drag
component below `1/1.5 ≈ 0.67 px` is discarded entirely, not deferred.**
`onScroll` fires per touch sample (60–120 Hz), so slow, precise movement — the
kind used to hit a close button — decomposes into many sub-pixel deltas and the
cursor does not move at all, while fast movement works fine. It will read as
"the cursor is jumpy / won't do fine adjustments".

**Measured, not asserted** — simulating `onDrag` against the code as written:

| input | current | with carried remainder |
|---|---|---|
| 100 x 0.40 px (slow precise drag) | **0 px** | 60 px |
| 100 x 0.66 px (just under the floor) | **0 px** | 98 px |
| 100 x 0.67 px (just over) | 100 px | 100 px |
| 100 x 3.00 px (ordinary drag) | **400 px** | 450 px |

Two separate defects, and the second is the one that will be felt constantly:

1. **A dead zone.** Any component below `1/1.5 = 0.667 px` is discarded, so slow
   precise movement produces no cursor motion at all.
2. **Systematic under-travel on *every* drag.** `3.0 x 1.5 = 4.5` truncates to 4,
   losing 0.5 px per sample — **~11% short**, at every speed. Effective
   sensitivity is therefore not 1.5 but roughly 1.33, and it *varies with drag
   speed*, because faster drags mean larger per-sample deltas and proportionally
   less truncation loss. That is why it will read as "inconsistent" rather than
   simply "slow", and why re-tuning `SENSITIVITY` cannot fix it.

Fix: keep `Float` remainders across calls, send the integer part, carry the
fraction. Reset the accumulator on gesture end so a stale fraction cannot leak
into the next gesture. The table above doubles as the regression fixture — the
first, second and fourth rows all fail against today's code.

### 5.2 Coalescing and a send budget — ✅ **DONE 2026-08-19**

Every `onScroll` callback currently becomes one JSON command over Noise. At 120 Hz
that is 120 encrypted round-trips per second of dragging, each with a full JSON
object. The protocol already anticipates this — `Capabilities { flags,
max_coalesce }` exists and `module10::coalesce::MoveCoalescer` implements exactly
this accumulate-and-flush — and the client uses neither.

Build: accumulate deltas and flush on a fixed cadence (start at 60 Hz) **or** at
`max_coalesce` samples, whichever first; always flush on gesture end so the last
movement is never stranded. This composes with §5.1 — the same accumulator serves
both.

### 5.3 Click-and-drag on the host — ✅ **DONE 2026-08-19, proven on a real Android 34 runtime**

Today the cursor can move and it can click, but it cannot **click and drag** —
so no text selection, no window moving, no sliders. This is the largest
functional gap, and it is a gesture-design problem, not a protocol one:
`MouseButton{Down}` → moves → `MouseButton{Up}` is already fully supported.

Suggested: long-press to latch the left button down, then drag, release on
finger-up. Use `ViewConfiguration.getLongPressTimeout()` rather than a literal.
`GestureDetector.SimpleOnGestureListener.onLongPress` gives the trigger.
**Latch must be released on `ACTION_CANCEL` and on session end**, or the host is
left with a button held down — the worst failure mode in this document.

### 5.4 Right click and middle click

`button: 1` and `2` are supported host-side and unreachable from the UI. Right
click is the more valuable. Needs a gesture that does not collide with §5.3's
long-press — a two-finger tap is the conventional choice and is currently
consumed only by `ScaleGestureDetector`, which does not act on a tap.

### 5.5 Host scrolling

`MouseScroll` is entirely unused. Two-finger drag is currently taken by
client-side pan, so this needs a deliberate decision: either a modifier gesture,
or a mode toggle that switches two-finger drag between *view pan* and *host
scroll*. Send `Lines` (see §4.4's 120-unit trap).

### 5.6 Absolute mode as an explicit option

Feasible today for the desktop surface (§4.2). Do **not** parse the resolution
out of the title string `"Desktop (1920x1080)"` — that is the fragility the
current KDoc rightly objects to. Add the surface's pixel dimensions as explicit
fields in the host's `list_windows_response()` alongside the existing
`"desktop": true` flag, and have the client map through the *current* zoom/pan
transform in `SurfaceFramePipeline`. Until those fields exist, relative is the
honest default.

### 5.7 Keyboard

Nothing exists. Needs a soft-keyboard surface and an Android-keycode → set-1
table (§4.5). Largest item here; least coupled to the rest. Worth doing after
5.1–5.3 make the pointer trustworthy.

### 5.8 Unused protocol verbs

`FocusGained`/`FocusLost` and `InputPause`/`InputResume` are defined and never
sent. `InputPause` on app-background is a cheap safety win: it stops a
backgrounded phone from driving a desktop.

---

### Status after the 2026-08-19 implementation round

`PointerMotion.kt` (182 lines, new) holds the arithmetic — sub-pixel carry, the
two coalescing budgets, and `DragLatch`. Zero `android.*` and zero JNI, so it
runs as a plain JVM test. `InputController.kt` delegates to it; `MainActivity.kt`
supplies the gesture triggers.

**Gate: 17 tests, 0 failures, 0 errors, 0 skipped, plus `:app:assembleDebug`
green — counted from `build/test-results/`, not read off the exit status.**

Fail-before was established properly: the arithmetic was extracted **unchanged**
first, so the suite ran against the shipped truncating behaviour and **8 of 10
failed**. Worth recording that the 2 which "passed" at that point
(`carryDoesNotLeakAcrossReset`, `flushOnAnEmptyGestureSendsNothing`) passed
**vacuously** — both assert null, and the pre-fix stub returned null for
everything. They only became real guards once the fix landed.

Still outstanding for 5.3, and it is the part that matters: **no cursor has
moved.** Everything above is arithmetic and compilation. The latch must be
device-tested on the test box, and the case to press hardest is
`ACTION_CANCEL` mid-drag — a latch that outlives its gesture leaves the host's
left button held down, selecting everything the cursor crosses. `MainActivity`
now routes both `ACTION_UP` and `ACTION_CANCEL` to `onGestureEnd`, and
`requestDisable()` releases the latch *before* asking for the revoke (after it,
every `input_event` is denied and the Up could never land) — but neither path
has been exercised against a real host.

### Device verification — closed on the dev box, 2026-08-19

Done here, not on the test box. `sdkmanager` installed `emulator` +
`system-images;android-34;google_apis;x86_64`; `/dev/kvm` already carried an ACL
for this account so no group change or sudo was needed. The AVD runs
`-no-window`, so nothing is ever placed on the host compositor — Article XIV
holds by construction.

**`SurfaceTouchRouter.kt`** (140 lines, new) now owns the finger-count split and
the gesture-end routing, behind a `SurfaceGestures` interface. That interface is
a seam, not a stub: the shipped implementation is `MainActivity`'s, and it exists
so real `MotionEvent`s can drive the routing in a test without a session, a host,
or the JNI bridge.

**6 on-device tests, 0 failures, on Android 34 / x86_64:**

| test | what it proves is *Android's* behaviour, not ours |
|---|---|
| `actionCancelEndsTheGesture` | a cancel reaches `onGestureEnd` — the case that would otherwise strand a latched button |
| `actionUpEndsTheGesture` | the ordinary path |
| `aGestureEndsExactlyOnce` | no doubled Up, which would be a real second button release |
| `holdingStillFiresLongPressBeforeTheGestureEnds` | `GestureDetector` actually fires `onLongPress` on its own schedule, so a latch can form |
| `aDragProducesMovementInTheDirectionOfTheFinger` | the `onScroll` sign convention is not inverted |
| `aQuickTapIsReportedAsATap` | a tap is not swallowed by the long-press path |

Timeouts come from `ViewConfiguration.getLongPressTimeout()` /
`getDoubleTapTimeout()` rather than literals, so the tests track the platform.

**Falsified.** Deleting the `ACTION_CANCEL` branch from the router failed
**exactly one** test — `actionCancelEndsTheGesture` — with the other five still
green. Reverted and re-run green. A well-aimed test, not a blanket one.

**Whole-feature gate: 27 Kotlin tests (21 JVM + 6 on-device) + 3 Rust contract
tests, 0 failures, plus `assembleDebug`.** Counts read from result XML.

Still not done, and it is the honest remainder: **no test has driven a real
RemoteDexter host.** The emulator proves the client's gestures and the VM proves
the host's uinput injection, but the two have never been connected end to end.
That needs a phone, a host and a network in one place.

## 6. Test plan

Article IX: build **and** run, real counts, every fix carrying a regression test
proven to fail before and pass after.

**Pure-Kotlin unit tests, no device.** §5.1 and §5.2 are arithmetic and belong in
JVM tests: assert that 100 successive 0.4 px deltas produce a total of 60 px
(±1) rather than 0, and that a flush emits exactly one message per cadence tick.
Both must fail against today's code before the fix — §5.1's failure is the whole
point of the finding.

**JSON shape tests.** Assert the emitted string parses and matches the host's
tested literal byte-for-byte in structure — variant name as sole key, unit
variants as bare strings, `abs_x`/`abs_y` present even when unused. This suite
is what stops a silent divergence from `message.rs`.

**Host-side round trip, on the dev box.** `module10`'s live-inject tests already
read injected events back out of the evdev nodes. Feed them JSON produced by the
Kotlin encoder (checked in as fixtures) and assert the resulting evdev events.
That closes the loop across the language boundary without a phone.

**Device test — test box only.** Anything that actually moves a cursor. This box
is single-seat (Article XIV); a latched mouse button or a runaway cursor from
§5.3 is precisely the class of failure that cannot be recovered from here.

## 7. Do not build yet

Multi-touch passthrough (the host exposes one logical cursor, not a touchscreen),
gesture customisation UI, and any input path that bypasses `grant_input`. The
three-condition gate in §3 is the security boundary this host exists to hold.
