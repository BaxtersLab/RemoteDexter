package com.remotedexter

object ControlDenialPolicy {
    /**
     * Whether a refusal means this phone no longer holds input control.
     *
     * A refused `input_event` usually does — the host refuses input to a peer
     * without the grant. But a TEXT run is also refused for its CONTENT (a
     * character the host cannot type, a run over its ceiling), and the host
     * still holds the grant then. Reading those as a lost grant switched the
     * phone to Viewing Only after an accented letter, and the operator's next
     * tap went nowhere (RD-TEXT-1).
     */
    fun losesGrant(forCmd: String, reason: String = ""): Boolean =
        forCmd == "grant_input" ||
            (forCmd == "input_event" && reason !in TextReturn.ABOUT_THE_TEXT)
}

/** What became of a Type or Go press — what the compose field should do. */
sealed class TextSend {
    /** Queued for the host. The field clears; a refusal will put it back. */
    object Queued : TextSend()

    /** Not sent, by [action]'s rule. The field keeps the text. */
    data class Refused(val action: KeyboardInput.Action) : TextSend()

    /** Allowed, but the session would not take it. The field keeps the text. */
    object NotQueued : TextSend()

    /** Only a queued run may clear the field; anything else would lose text. */
    val clearsField: Boolean get() = this is Queued
}

/**
 * Which host refusals end the session, and which are just an answer.
 *
 * ## The defect this exists to prevent
 *
 * `SessionOrchestrator` treated every `denied`/`error` as fatal unless it was
 * one of three input commands, and called `fail()` on the rest — tearing down a
 * live stream. That was correct while those three were the only commands a
 * running session could send.
 *
 * Adding the clipboard broke it silently. Pressing "← Host" while the host had
 * an **image** copied would be answered `denied … not text`, which is a perfectly
 * ordinary answer to an ordinary question — and it would have killed the
 * session. So would a host running without `RD_CAP_CLIPBOARD`, which is the
 * default.
 *
 * The rule is written here, once, as a value a test can walk, rather than as a
 * condition inside a `when` branch nobody can reach from a unit test. A command
 * added to the session later gets this decision made deliberately, because the
 * safe answer is not the default — it is a list.
 */
object SessionDenialPolicy {

    /**
     * Commands whose refusal is an answer to the operator, not a broken
     * session.
     *
     * Everything here is something a person pressed a button for during a live
     * stream. A refusal means "not that, not now", and the remedy is a sentence
     * on screen — never the end of the session they were in the middle of.
     */
    private val ANSWERABLE = setOf(
        "grant_input",
        "revoke_input",
        "input_event",
        "clipboard_push",
        "clipboard_pull"
    )

    /**
     * True when a refusal should end the session.
     *
     * The default is FATAL, and deliberately so: the negotiation commands
     * (`list_windows`, `permit_window`, `stream_start`) are the ones a session
     * cannot continue without, and an unknown command being refused means the
     * two ends disagree about what this protocol is. Being wrong in that
     * direction costs a reconnect; being wrong the other way leaves a session
     * running on a host that has refused the thing it depends on.
     */
    fun isFatalToSession(forCmd: String): Boolean = forCmd !in ANSWERABLE

    /** True when the refusal belongs to the clipboard, so the UI can say so. */
    fun isClipboard(forCmd: String): Boolean =
        forCmd == "clipboard_push" || forCmd == "clipboard_pull"
}

object ControlRequestPolicy {
    fun canRequestEnable(controlEnabled: Boolean, pending: Boolean): Boolean =
        !controlEnabled && !pending

    fun canRequestDisable(controlEnabled: Boolean, pending: Boolean): Boolean =
        controlEnabled && !pending
}

object ControlDisableSequence {
    fun execute(releaseDragIfHeld: () -> Unit, sendRevoke: () -> Unit) {
        releaseDragIfHeld()
        sendRevoke()
    }
}

/**
 * Turns touch gestures on the video surface into real cursor control on the
 * host. Streaming (this app receiving and displaying frames) and control (this
 * app driving the host's mouse) are separate host-side capabilities gated
 * independently (`RD_CAP_SCREENSHOT` vs `RD_CAP_INPUT`); this class only ever
 * concerns itself with the second one.
 *
 * All arithmetic lives in [PointerMotion] and [DragLatch], which have no
 * Android or JNI dependency and are unit-tested on the JVM. What stays here is
 * only what genuinely needs the platform: composing JSON and handing it to
 * [RDRust.sendCommand].
 *
 * ### The shipping touch path is ABSOLUTE as of the cursor-offset feature
 *
 * One finger now names a desktop pixel rather than nudging the pointer. That
 * change was forced by the operator requirement that a slider lift the real host
 * cursor and click point above the fingertip: a constant offset subtracted from
 * successive touch positions cancels itself out of the deltas
 * (`(p2 - o) - (p1 - o) == p2 - p1`), so a relative path can express "move the
 * cursor" but cannot express "and put it *there*". `CursorOffsetNoOpControlTest`
 * runs that argument rather than asserting it.
 *
 * [PointerMotion] and [onDrag] are BOTH ON THE SHIPPING PATH AGAIN as of Block
 * 11, reached when the user selects Trackpad mode. They were retained through
 * the absolute-touch work on the argument that deleting them would throw away
 * coverage to make a diff look tidier; [PointerModeRouter] now chooses between
 * the two per touch sample.
 *
 * ### Why relative ("trackpad") movement is worth keeping as a mode
 *
 * `MouseMove` supports both `Relative` and `Absolute` on the wire
 * (`module10::message::InputControlMessage`). Relative earns its place for
 * three reasons:
 *
 * 1. **It needs no resolution knowledge.** Absolute requires mapping a touch
 *    point onto exact remote desktop pixels; this client can currently only
 *    infer that by parsing a title string ("Desktop (1920x1080)"), which is
 *    fragile.
 * 2. **It survives zoom and pan.** The surface has client-side pinch-zoom, so
 *    the view-to-desktop mapping changes continuously; a relative delta is
 *    unaffected by it.
 * 3. **A finger is a poor absolute pointer at this scale.** One finger-width
 *    covers roughly 40 desktop pixels on a 6" screen showing a 1920px desktop,
 *    which is wider than most click targets.
 *
 * Absolute won the default in Block 8, because a finger that points at a thing
 * and moves the cursor somewhere else is the more surprising behaviour of the
 * two. Reason 3 above is exactly why Trackpad still has to be reachable: a
 * fingertip cannot hit a close button, and in Trackpad mode the cursor is not
 * under the finger hiding the target. See `ANDROID_INPUT_SPEC_2026-08-19.md`
 * §5.6.
 *
 * ### Explicit, visible grant — mirrors RD_CAP_INPUT itself
 *
 * The host's own capability is opt-in (`RD_CAP_INPUT` is unset by default,
 * armed deliberately by whoever runs `run.sh`). This class mirrors that on
 * the client side: control is never active the moment a stream starts —
 * the operator has to tap "Enable Control" first, same philosophy, same
 * reasoning (handing over real input injection should never be a silent
 * side effect of something else).
 *
 * ### Wire sequence
 *
 * ```
 *   → {"type":"grant_input"}
 *   ← {"type":"ack","for":"grant_input"}                 (or "denied")
 *   → {"type":"input_event","window":N,"event":{"MouseMove":{...}}}
 *   → {"type":"input_event","window":N,"event":{"MouseButton":{...}}}
 *   → {"type":"revoke_input"}
 *   ← {"type":"ack","for":"revoke_input"}
 * ```
 *
 * All of it over the same pinned Noise session, via [RDRust.sendCommand] —
 * the identical call [SessionOrchestrator] already uses for its own
 * negotiation. No new native/JNI surface; this is pure Kotlin.
 */
object InputController {

    private const val TAG = "InputController"

    private val motion = PointerMotion()
    private val latch = DragLatch()

    /** Debug-only: at most one host key held down. See [HeldKeyLatch]. */
    private val keyLatch = HeldKeyLatch()

    /** True once `grant_input` has been acked — gates every subsequent send. */
    @Volatile private var controlEnabled = false

    /** True while a `grant_input`/`revoke_input` round-trip is in flight. */
    @Volatile private var pending = false

    /**
     * Notified whenever [controlEnabled] changes for any reason (granted,
     * revoked, or denied) — [MainActivity] observes this to keep the toggle
     * button's label truthful even when the change wasn't the result of the
     * button being tapped a moment ago (a denial arrives asynchronously).
     */
    var onControlStateChanged: ((enabled: Boolean) -> Unit)? = null

    /**
     * Notified when the host refuses a control command, with the host's own
     * reason.
     *
     * Separate from [onControlStateChanged] because a refusal usually changes
     * no state at all: control was already off, so the state callback does not
     * fire and the user is left tapping a button that appears to do nothing.
     * The host's reason names what is wrong — e.g. that input injection is not
     * enabled for this run — and that is the only place the user can learn it.
     */
    var onControlDenied: ((forCmd: String, reason: String) -> Unit)? = null

    /** Paragraphs sent and not yet answered for. See [PendingTexts]. */
    private val pendingTexts = PendingTexts()

    /**
     * Notified when the host refuses or stops a text run this phone sent,
     * with the part that did not reach the desktop — for the compose field to
     * take back. Called INSTEAD of [onControlDenied] for that refusal, so the
     * operator gets one message about their text rather than two.
     */
    var onTextReturned: ((reason: String, returned: PendingTexts.Returned, max: Int?) -> Unit)? = null

    fun isControlEnabled(): Boolean = controlEnabled

    /** True while a long-press has latched the left button down. */
    fun isDragging(): Boolean = latch.isLatched()

    /** Tap "Enable Control": ask the host for the grant. */
    fun requestEnable() {
        if (!ControlRequestPolicy.canRequestEnable(controlEnabled, pending)) return
        pending = true
        send(InputJson.grantInput(), "grant_input")
    }

    /**
     * Tap "Viewing Only": give the grant back up.
     *
     * Releases a latched drag **before** asking for the revoke, not after. Once
     * the host has revoked, every `input_event` is denied — so an Up sent after
     * the revoke would be refused and the host's left button would stay held
     * down with no way left to release it.
     */
    fun requestDisable() {
        if (!ControlRequestPolicy.canRequestDisable(controlEnabled, pending)) return
        ControlDisableSequence.execute(
            releaseDragIfHeld = ::releaseAllHeldInput,
            sendRevoke = {
                pending = true
                send(InputJson.revokeInput(), "revoke_input")
            }
        )
    }

    /** Called by [SessionOrchestrator.onAck] — not part of its own negotiation. */
    fun onAck(forCmd: String) {
        when (forCmd) {
            "grant_input" -> setEnabled(true)
            "revoke_input" -> setEnabled(false)
        }
    }

    /**
     * An `input_event` was acknowledged. Most are pointer moves and name no
     * text run; one that does was typed in full, and its copy can go.
     */
    fun onInputAck(ack: org.json.JSONObject) {
        InputJson.textReply(ack)?.let { pendingTexts.settle(it.id) }
    }

    /**
     * Called by [SessionOrchestrator.onHostMessage] on a denial/error for our
     * commands. [text] is set when the reply names a text run this phone sent.
     */
    fun onDenied(forCmd: String, reason: String, text: InputJson.TextReply? = null) {
        RdxLog.w(TAG, "$forCmd denied: $reason")
        pending = false
        // Told before the state is touched: a refusal most often changes no
        // state at all, so waiting for onControlStateChanged would swallow it.
        val returned = text?.let { pendingTexts.refused(it.id, it.typed, it.at) }
        if (returned != null) {
            onTextReturned?.invoke(reason, returned, text.max)
        } else {
            onControlDenied?.invoke(forCmd, reason)
        }
        if (ControlDenialPolicy.losesGrant(forCmd, reason)) {
            setEnabled(false)
        }
        // A denied revoke leaves the host grant's state uncertain, so retain
        // the local claim until a later acknowledgement or session reset.
    }

    private fun setEnabled(enabled: Boolean) {
        pending = false
        if (controlEnabled == enabled) return
        controlEnabled = enabled
        RdxLog.i(TAG, if (enabled) "control enabled" else "control disabled")
        onControlStateChanged?.invoke(enabled)
    }

    /**
     * Move the host pointer to the mapped position, preserving its coordinate space.
     *
     * [position] must already be inside the mapped bounds — its axes land in a `u32`
     * host-side, so a negative value does not merely misbehave, it fails to
     * parse and the event is dropped silently. `DesktopCoordinateMapper` is what
     * guarantees the clamp, and the caller is expected to have used it.
     *
     * Every one-finger move sends one of these. No coalescing: an absolute
     * position is naturally latest-wins, so a dropped intermediate costs
     * nothing, while a dropped *final* one would leave the pointer short of
     * where the finger stopped. Android already batches touch samples to the
     * display refresh, which bounds the rate.
     */
    fun onAbsoluteMove(position: PointerPosition) {
        val windowId = SessionOrchestrator.currentWindowId()
        if (!InputEmissionPolicy.mayEmit(controlEnabled, windowId)) return
        sendAbsoluteMove(windowId, position)
    }

    /**
     * A tap at an exact desktop pixel: move there first, then click.
     *
     * The ordering is the feature. With a cursor offset set, the pointer is not
     * under the fingertip, so clicking without moving first would click wherever
     * the pointer happened to be left — which is the bug this whole change
     * exists to avoid.
     */
    fun onTapAt(position: PointerPosition) {
        val windowId = SessionOrchestrator.currentWindowId()
        if (!InputEmissionPolicy.mayEmit(controlEnabled, windowId)) return
        AbsoluteInputSequence.tap(
            position.x, position.y,
            move = { _, _ -> sendAbsoluteMove(windowId, position) },
            button = { b, action -> sendButton(windowId, b, action) }
        )
    }

    /**
     * A two-finger tap at an exact desktop pixel: move there, then right click.
     *
     * Same ordering as [onTapAt] and for the same reason — a context menu opens
     * at the pointer, so clicking without moving first opens one where the
     * operator is not looking.
     */
    fun onSecondaryTapAt(position: PointerPosition) {
        val windowId = SessionOrchestrator.currentWindowId()
        if (!InputEmissionPolicy.mayEmit(controlEnabled, windowId)) return
        AbsoluteInputSequence.secondaryTap(
            position.x, position.y,
            move = { _, _ -> sendAbsoluteMove(windowId, position) },
            button = { b, action -> sendButton(windowId, b, action) }
        )
    }

    /**
     * Long-press at an exact desktop pixel: move there, then latch the left
     * button down. Movement while latched stays absolute, so the drag follows
     * the offset cursor rather than the fingertip.
     */
    fun onLongPressAt(position: PointerPosition) {
        val windowId = SessionOrchestrator.currentWindowId()
        if (!InputEmissionPolicy.mayEmit(controlEnabled, windowId)) return
        if (latch.press()) {
            AbsoluteInputSequence.longPress(
                position.x, position.y,
                move = { _, _ -> sendAbsoluteMove(windowId, position) },
                button = { b, action -> sendButton(windowId, b, action) }
            )
            RdxLog.i(TAG, "drag latched")
        }
    }

    /**
     * A touch-drag delta, in on-screen pixels, with the originating
     * `MotionEvent`'s own timestamp — call from the surface's gesture detector.
     *
     * The event time is passed in rather than read from the clock here so the
     * coalescing budget measures when the touch actually happened, not when it
     * happened to be dispatched. No-ops silently when control isn't enabled.
     */
    fun onDrag(dxPixels: Float, dyPixels: Float, eventTimeMs: Long) {
        if (!controlEnabled) return
        val windowId = SessionOrchestrator.currentWindowId()
        if (windowId < 0) return
        val d = motion.onDragSample(dxPixels, dyPixels, eventTimeMs) ?: return
        sendMove(windowId, d)
    }

    /**
     * The finger left the surface (or the gesture was cancelled). Flushes any
     * movement still inside the coalescing window and releases a latched drag.
     *
     * Must be called for **every** touch-up, including cancels — a latch that
     * outlives its gesture leaves the host's left button held down.
     */
    fun onGestureEnd(eventTimeMs: Long) {
        val windowId = SessionOrchestrator.currentWindowId()
        if (controlEnabled && windowId >= 0) {
            motion.flush(eventTimeMs)?.let { sendMove(windowId, it) }
        } else {
            motion.reset()
        }
        releaseDragIfHeld()
    }

    /** A tap — left click (down immediately followed by up). */
    fun onTap() {
        if (!controlEnabled) return
        val windowId = SessionOrchestrator.currentWindowId()
        if (windowId < 0) return
        sendButton(windowId, 0, "Down")
        sendButton(windowId, 0, "Up")
    }

    /**
     * Long-press: latch the left button down so the following drag is a real
     * click-and-drag on the host — text selection, window moving, sliders.
     * Released by [onGestureEnd], [reset], or [requestDisable].
     */
    fun onLongPress() {
        if (!controlEnabled) return
        val windowId = SessionOrchestrator.currentWindowId()
        if (windowId < 0) return
        if (latch.press()) {
            sendButton(windowId, 0, "Down")
            RdxLog.i(TAG, "drag latched")
        }
    }

    /**
     * Send the Up for a latched drag if one is held. Safe to call at any time:
     * [DragLatch.release] reports false when nothing is latched, so this can
     * never emit a stray button release.
     */
    private fun releaseDragIfHeld() {
        if (!latch.release()) return
        val windowId = SessionOrchestrator.currentWindowId()
        if (windowId >= 0) {
            sendButton(windowId, 0, "Up")
            RdxLog.i(TAG, "drag released")
        } else {
            // Nothing can be sent, but the latch is cleared regardless — the
            // alternative is believing a button is held forever.
            RdxLog.w(TAG, "drag released with no window — host may hold the button")
        }
    }

    /**
     * Release every kind of held input, drag and key, before a revoke or reset.
     *
     * Order does not matter between the two — they are different events for
     * different subsystems — but both must go BEFORE the revoke, for the reason
     * [requestDisable] gives: past a revoke every `input_event` is denied, so an
     * Up sent afterwards is refused and the host keeps holding whatever it held.
     */
    private fun releaseAllHeldInput() {
        releaseDragIfHeld()
        releaseHeldKeyIfHeld()
    }

    /**
     * Debug-only: hold one host key down and do not send its Up.
     *
     * # This is the one path in the client that deliberately breaks the rule
     *
     * [sendKeyStroke] sends Down and Up together and unconditionally, because a
     * key left down on the host repeats forever with nothing on the phone able
     * to stop it. That invariant is why Windows round 13 could not produce the
     * `N key(s)` half of the host's shutdown message from a phone at all. This
     * exists so that one measurement can be taken, and nothing else.
     *
     * It is unreachable in a release build twice over: [BuildProfile] compiles
     * `HELD_KEY_AFFORDANCE = false` there, so [HeldKeyPolicy.mayHold] inlines a
     * refusal; and the only caller, `HeldKeyDebugReceiver`, exists solely in the
     * debug source set and is declared solely in the debug manifest.
     *
     * The key is released by [releaseAllHeldInput] on every path that releases a
     * drag — revoke, session end, surface destroyed — so it cannot outlive the
     * session that authorised it any more than a latched drag can.
     *
     * @return the decision, so the caller can log why nothing happened. A
     *   refusal in silence is indistinguishable from a broken affordance, which
     *   is the failure mode this whole area has already produced twice.
     */
    fun holdKey(scanCode: Int): HeldKeyPolicy.Decision {
        val windowId = SessionOrchestrator.currentWindowId()
        val decision = HeldKeyPolicy.mayHold(
            affordanceCompiledIn = BuildProfile.HELD_KEY_AFFORDANCE,
            controlGranted = controlEnabled,
            windowId = windowId,
            alreadyHeld = keyLatch.isHeld(),
            scanCode = scanCode
        )
        when (decision) {
            is HeldKeyPolicy.Decision.Hold -> {
                // Latch FIRST. If the send fails the key may still be down on
                // the host, and a latch that never recorded it is a key nothing
                // will ever release.
                keyLatch.press(decision.scanCode)
                send(
                    InputJson.key(windowId, decision.scanCode, "Down", 0),
                    "input_event(key ${decision.scanCode} down, HELD)"
                )
                RdxLog.i(TAG, "debug affordance holding ${decision.keyName} down")
            }
            is HeldKeyPolicy.Decision.Refuse ->
                RdxLog.i(TAG, "not holding key $scanCode: ${decision.why}")
        }
        return decision
    }

    /** True while the debug affordance is holding a key. */
    fun isHoldingKey(): Boolean = keyLatch.isHeld()

    /**
     * Send the Up for a held key if one is held.
     *
     * Mirrors [releaseDragIfHeld] exactly, including the no-window case: the
     * latch is cleared regardless, because the alternative is believing a key is
     * held forever.
     */
    fun releaseHeldKeyIfHeld() {
        val owed = keyLatch.release() ?: return
        val windowId = SessionOrchestrator.currentWindowId()
        if (windowId >= 0) {
            send(InputJson.key(windowId, owed, "Up", 0), "input_event(key $owed up)")
            RdxLog.i(TAG, "held key $owed released")
        } else {
            RdxLog.w(TAG, "held key $owed released with no window — host may hold the key")
        }
    }

    private fun sendAbsoluteMove(windowId: Long, position: PointerPosition) {
        send(
            InputJson.moveAbsolute(windowId, position.x, position.y, position.space),
            "input_event(abs move)"
        )
    }

    private fun sendMove(windowId: Long, d: Delta) {
        send(InputJson.moveRelative(windowId, d.dx, d.dy), "input_event(move)")
    }

    private fun sendButton(windowId: Long, button: Int, action: String) {
        send(InputJson.button(windowId, button, action), "input_event(btn$button $action)")
    }

    /**
     * Type text on the host.
     *
     * Gated by [KeyboardInput], which routes the decision through the SAME
     * [InputEmissionPolicy.mayEmit] the pointer path uses — so a keyboard can
     * never emit in a state where a click could not.
     *
     * Text, not keystrokes: a scan code names a physical key position and only
     * the host knows which position produces which character. The host expands
     * it in `module10::keymap`.
     */
    fun commitText(buffer: String): TextSend {
        val windowId = SessionOrchestrator.currentWindowId()
        return sendComposed(windowId, buffer, KeyboardInput.onCommit(controlEnabled, windowId, buffer))
    }

    /**
     * Type the line into whatever has focus on the host, WITHOUT Enter.
     *
     * The other half of [commitText]. Filling a username box and running a
     * command are different acts, and a keyboard that could only do the second
     * could not fill in a form.
     */
    fun stageText(buffer: String): TextSend {
        val windowId = SessionOrchestrator.currentWindowId()
        return sendComposed(windowId, buffer, KeyboardInput.onStage(controlEnabled, windowId, buffer))
    }

    /**
     * Put a composed run on the wire, under an id the host will answer to.
     *
     * The result is what tells the compose field whether it may clear. It used
     * to clear on any decision to send, BEFORE knowing whether the session had
     * taken the command — so a send into a closing session lost the text with
     * nothing on the wire to show for it (RD-TEXT-1).
     */
    private fun sendComposed(windowId: Long, composed: String, action: KeyboardInput.Action): TextSend {
        if (action !is KeyboardInput.Action.SendText) {
            perform(windowId, action, "text")
            return TextSend.Refused(action)
        }
        val id = pendingTexts.register(composed)
        if (RDRust.sendCommand(InputJson.text(windowId, action.text, id))) {
            return TextSend.Queued
        }
        pendingTexts.forget(id)
        RdxLog.w(TAG, "could not send input_event(text) — session not accepting commands")
        return TextSend.NotQueued
    }

    /**
     * Backspace, given what is still in the compose field.
     *
     * Returns the decision so the caller knows whether the key was consumed:
     * a local edit must fall through to the field, and swallowing it would
     * make Backspace stop working while composing.
     */
    fun backspace(buffer: String): KeyboardInput.Action {
        val windowId = SessionOrchestrator.currentWindowId()
        val action = KeyboardInput.onBackspaceWithBuffer(controlEnabled, windowId, buffer)
        perform(windowId, action, "backspace")
        return action
    }

    private fun perform(windowId: Long, action: KeyboardInput.Action, what: String) {
        when (action) {
            // Text always goes under an id, so even a caller that reaches here
            // with text gets its refusal answered.
            is KeyboardInput.Action.SendText ->
                sendComposed(windowId, action.text, action)
            is KeyboardInput.Action.SendKey ->
                sendKeyStroke(windowId, action.scanCode)
            is KeyboardInput.Action.Drop ->
                RdxLog.i(TAG, "not sending $what: ${action.why}")
            is KeyboardInput.Action.TooLong ->
                RdxLog.i(TAG, "not sending $what: ${action.length} characters is over the ${action.max} limit")
            is KeyboardInput.Action.TooLargeToSend ->
                RdxLog.i(TAG, "not sending $what: ${action.bytes} bytes is over the ${action.max}-byte input envelope")
        }
    }

    /**
     * One key, down then up.
     *
     * Both halves are sent together and unconditionally: a down without its up
     * leaves the key held on the HOST, which for a repeating key means it types
     * forever with nothing on the phone to stop it.
     */
    private fun sendKeyStroke(windowId: Long, scanCode: Int, modifiers: Int = 0) {
        send(
            InputJson.key(windowId, scanCode, "Down", modifiers),
            "input_event(key $scanCode down)"
        )
        send(
            InputJson.key(windowId, scanCode, "Up", modifiers),
            "input_event(key $scanCode up)"
        )
    }

    /**
     * Press one of the chord buttons: Ctrl+C, Ctrl+V, Print Screen.
     *
     * The modifiers ride on BOTH halves because that is what the host's
     * injectors expect: each backend presses the modifiers before a key-down
     * and releases them after a key-up, so a Down carrying Ctrl and an Up
     * carrying nothing would press Control and never let go of it — on the
     * host, with nothing on the phone able to release it.
     *
     * Returns the decision so the caller can say why nothing happened. A button
     * that refuses in silence is indistinguishable from a broken one, which is
     * exactly what the operator hit with the dead `PrtScr` icon.
     */
    fun pressChord(chord: KeyChord.Chord): KeyChord.Action {
        val windowId = SessionOrchestrator.currentWindowId()
        val action = KeyChord.press(controlEnabled, windowId, chord)
        when (action) {
            is KeyChord.Action.Send ->
                sendKeyStroke(windowId, chord.scanCode, chord.modifiers)
            is KeyChord.Action.Drop ->
                RdxLog.i(TAG, "not sending ${chord.label}: ${action.why}")
        }
        return action
    }

    /**
     * Send wheel notches to the host.
     *
     * Gated by the same [InputEmissionPolicy.mayEmit] as everything else that
     * writes to the host. Scrolling a document is changing what someone is
     * looking at, and a viewer must not be able to do it.
     *
     * **The window under the CURSOR receives it**, because that is what a wheel
     * event means to any desktop. No targeting is attempted here: park the
     * pointer where you want it and scroll, exactly as with a mouse.
     */
    fun scroll(dx: Int, dy: Int): Boolean {
        val windowId = SessionOrchestrator.currentWindowId()
        if (!InputEmissionPolicy.mayEmit(controlEnabled, windowId)) return false
        send(InputJson.scroll(windowId, dx, dy), "input_event(scroll $dx,$dy)")
        return true
    }

    /**
     * Offer the phone's clipboard to the host.
     *
     * The caller reads the phone's clipboard — this object has no Context and
     * deliberately keeps none. Returns the decision so the caller can say what
     * happened; a transfer that silently does nothing is the defect this whole
     * area has produced twice.
     *
     * The text is NEVER logged, here or anywhere below.
     */
    fun pushClipboard(text: String?): ClipboardBridge.Action {
        val windowId = SessionOrchestrator.currentWindowId()
        val action = ClipboardBridge.push(controlEnabled, windowId, text)
        if (action is ClipboardBridge.Action.Push) {
            send(InputJson.clipboardPush(windowId, action.text), "clipboard_push")
            RdxLog.i(TAG, "sent ${action.text.toByteArray().size} bytes to the host clipboard")
        }
        return action
    }

    /**
     * Ask for the host's clipboard. The reply arrives asynchronously as a
     * `clipboard` message and is handled by [SessionOrchestrator].
     */
    fun pullClipboard(): ClipboardBridge.Action {
        val windowId = SessionOrchestrator.currentWindowId()
        val action = ClipboardBridge.pull(controlEnabled, windowId)
        if (action is ClipboardBridge.Action.Pull) {
            send(InputJson.clipboardPull(windowId), "clipboard_pull")
        }
        return action
    }

    /**
     * Send a command over the session. Unlike [SessionOrchestrator.send],
     * a failure here does not fail the whole session — losing one input
     * event is not the same as losing the stream negotiation, and treating
     * it that way would tear down a working session over a dropped click.
     */
    private fun send(json: String, label: String) {
        if (!RDRust.sendCommand(json)) {
            RdxLog.w(TAG, "could not send $label — session not accepting commands")
        }
    }

    /** Reset to the pre-session state — call when a session ends or fails. */
    fun reset() {
        releaseAllHeldInput()
        motion.reset()
        // No answer for any of these is coming from a session that has ended.
        pendingTexts.clear()
        setEnabled(false)
    }
}
