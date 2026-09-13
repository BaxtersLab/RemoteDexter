package com.remotedexter

/**
 * What to send when the user types, and — more importantly — when not to.
 *
 * # Why this is pure
 *
 * The Android half of typing is an invisible `EditText` and an IME, neither of
 * which can be reasoned about in a unit test. The half that MATTERS is the
 * decision: is control granted, is there a session, is this character worth
 * sending. Keeping that decision here, free of Android types, is what lets the
 * gating be proven on the JVM instead of eyeballed on a device.
 *
 * # Composed, not live
 *
 * Text is held in a visible field and sent when the user commits it, rather
 * than forwarded keystroke by keystroke. The operator's words: *"its a blind
 * send"* — the field was 1dp and cleared itself after every character, so there
 * was nothing to read and no chance to correct a typo before it landed in a
 * remote shell.
 *
 * Live per-keystroke typing is what a desktop client normally does, and it is
 * the right model on a low-latency link. Over a phone on a congested Wi-Fi it
 * means committing each character to a machine you cannot see clearly, with no
 * way to review. Composing first trades immediacy for the ability to check what
 * you are about to run.
 *
 * # The gate
 *
 * The plan is explicit: *"Keyboard text is sent only while control is
 * granted."* That is not a convenience check. Viewing and control are separate
 * grants precisely so that watching a screen cannot become typing on it, and a
 * keyboard that emitted while control was off would quietly erase the
 * distinction — the one the whole consent model rests on.
 *
 * The host would refuse it anyway. Checking here as well is deliberate
 * belt-and-braces: the refusal would arrive as a `denied` the user cannot act
 * on, having already typed a password into a field that was never going to
 * receive it.
 *
 * # One gate, not two
 *
 * The decision itself is [InputEmissionPolicy.mayEmit] — the SAME rule the
 * mouse path uses — rather than a second condition written out here. A keyboard
 * with its own copy of "when may input be emitted" is a copy that eventually
 * disagrees with the mouse's, and the direction it would disagree in is
 * permissive. The reason strings below are derived only AFTER that gate has
 * refused, and exist for the log; they are not the decision.
 */
object KeyboardInput {

    /** Set 1 scan code for Backspace. */
    const val SCAN_BACKSPACE = 14

    /** What the caller should put on the wire. */
    sealed class Action {
        /** Send this text. */
        data class SendText(val text: String) : Action()

        /** Press and release one key by position. */
        data class SendKey(val scanCode: Int) : Action()

        /** Send nothing. [why] is for the log, never the user's own text. */
        data class Drop(val why: String) : Action()
    }

    /**
     * Decide what a run of newly typed text should produce.
     *
     * @param controlGranted whether the host has granted input control.
     * @param windowId the permitted surface, or negative when there is none.
     * @param added the characters the IME just committed.
     */
    fun onTextTyped(controlGranted: Boolean, windowId: Long, added: String): Action {
        if (!InputEmissionPolicy.mayEmit(controlGranted, windowId)) {
            return Action.Drop(refusalReason(controlGranted, windowId))
        }
        if (added.isEmpty()) return Action.Drop("nothing typed")
        return Action.SendText(added)
    }

    /**
     * Why the gate said no — for the log only.
     *
     * The two cases need different remedies: one wants a connection, the other
     * wants the user to press Enable Control. A single "refused" would send
     * them looking in the wrong place.
     */
    private fun refusalReason(controlGranted: Boolean, windowId: Long): String =
        if (windowId < 0) "no session" else if (!controlGranted) "control not granted" else "refused"

    /**
     * Type the line and press Enter — submit it.
     *
     * The trailing newline is added HERE rather than by the caller so that
     * "commit" has one meaning: the line, and the Enter that runs it. A caller
     * that appended its own newline somewhere else would eventually forget to,
     * and the difference — text that arrives but never executes — looks exactly
     * like a dropped connection.
     *
     * Paired with [onStage]; see it for why both exist.
     */
    fun onCommit(controlGranted: Boolean, windowId: Long, buffer: String): Action {
        if (!InputEmissionPolicy.mayEmit(controlGranted, windowId)) {
            return Action.Drop(refusalReason(controlGranted, windowId))
        }
        // An empty field still commits: pressing Enter on nothing is a
        // deliberate blank line, which at a shell prompt is how you get a fresh
        // prompt back. Swallowing it would make the key feel broken.
        return Action.SendText(buffer + "\n")
    }

    /**
     * Type the line and stop — no Enter.
     *
     * # Why this had to be separate
     *
     * The first version sent the line AND the Enter whichever control was used,
     * so the Send button and the keyboard's Enter did the same thing. The
     * operator's words: *"enter is send and send is enter"*. There was no way
     * to put text into a field on the host without submitting it — no filling
     * in a username, no typing a search term you then want to edit, no
     * answering half a form.
     *
     * Two actions, two meanings: **Type** puts the text there, **Enter** puts
     * it there and runs it.
     *
     * An empty field stages nothing, unlike [onCommit], where an empty commit
     * is a deliberate bare Enter. "Type nothing" has no such reading — it is a
     * button press that should do nothing rather than send an empty message.
     */
    fun onStage(controlGranted: Boolean, windowId: Long, buffer: String): Action {
        if (!InputEmissionPolicy.mayEmit(controlGranted, windowId)) {
            return Action.Drop(refusalReason(controlGranted, windowId))
        }
        if (buffer.isEmpty()) return Action.Drop("nothing typed")
        return Action.SendText(buffer)
    }

    /**
     * Decide what Backspace should do, given what is in the compose field.
     *
     * While there is text to delete it is a LOCAL edit — the point of composing
     * is to fix mistakes before they land. Once the field is empty there is
     * nothing local left to delete, so it becomes a remote Backspace, which is
     * the only way to remove text on the host that was never typed here.
     */
    fun onBackspaceWithBuffer(
        controlGranted: Boolean,
        windowId: Long,
        buffer: String
    ): Action =
        if (buffer.isNotEmpty()) {
            Action.Drop("editing locally")
        } else {
            onBackspace(controlGranted, windowId)
        }

    /**
     * Decide what a Backspace should produce.
     *
     * Backspace needs its own path because **deleting produces no text**: an
     * IME reports a shorter buffer, not a character, so a text-only route can
     * never express it. Without this, the remote field could only ever grow.
     */
    fun onBackspace(controlGranted: Boolean, windowId: Long): Action {
        if (!InputEmissionPolicy.mayEmit(controlGranted, windowId)) {
            return Action.Drop(refusalReason(controlGranted, windowId))
        }
        return Action.SendKey(SCAN_BACKSPACE)
    }

    /**
     * The text the IME added, given the previous and current buffer contents.
     *
     * A `TextWatcher` reports the whole field, not a delta, so the delta has to
     * be derived. Only a pure **append** counts: anything else — a deletion, a
     * mid-string edit, an autocorrect replacing a word — is not "the user typed
     * these characters next" and must not be replayed as if it were. Returning
     * null for those cases is what stops autocorrect from retyping a whole
     * word into a remote shell.
     */
    fun appendedText(before: String, after: String): String? {
        if (after.length <= before.length) return null
        if (!after.startsWith(before)) return null
        return after.substring(before.length)
    }
}
