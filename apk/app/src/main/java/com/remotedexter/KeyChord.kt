package com.remotedexter

/**
 * The key combinations that have a button of their own.
 *
 * ## What these replace, and why the originals could not work
 *
 * The app used to carry buttons labelled `Ctrl+C` and `Ctrl+V`. **Neither ever
 * pressed Ctrl+C on the host.** `btnCopy` read the PHONE's clipboard and pushed
 * it across; `btnPaste` sent an empty payload with the comment "empty triggers
 * host fetch"; and the host's handler logged the bytes beside a note reading
 * "For now log/store it; real platform clipboard comes [later]". Block 10 found
 * that handler acking without ever touching a clipboard, recorded it as an
 * undeclared stub, and deleted the whole path — buttons included — without
 * asking the operator, who used those buttons and wanted them.
 *
 * These are the same buttons doing what their labels always claimed. A chord is
 * an ordinary [InputControlMessage.KeyEvent] carrying a scan code and modifier
 * bits, so Ctrl+C **presses Ctrl and C on the host** and the host's own
 * clipboard receives the copy. It rides the injection path that is already
 * proven on hardware rather than adding a second one, and it needs no new wire
 * message: `android_input_wire_v1` already carries `scan_code` and `modifiers`.
 *
 * ## Scope, stated honestly
 *
 * This is cut and paste WITHIN the remote desktop — copy in one host window,
 * paste in another. It is not a clipboard shared between the phone and the
 * host; text copied on the phone is still not reachable from the host, and that
 * needs a wire message and real platform clipboard access on both sides.
 */
object KeyChord {

    /**
     * Modifier bits, matching `module10::message`.
     *
     * Named rather than written as `2` at the call sites. The Rust definition
     * is the authority and its own doc records that these once lived in three
     * places, each with a comment saying it must match the others — which is
     * the arrangement in which they eventually do not.
     */
    const val MOD_NONE = 0x00
    const val MOD_CTRL = 0x02

    /**
     * A chord, as the host's key positions.
     *
     * Set 1 scan codes, which is what the wire carries and what
     * `module10::inject_linux::set1_to_evdev` translates. C and V are `0x2E`
     * and `0x2F` and map one-to-one into evdev. Print Screen is the **extended**
     * code `0xE037`, already mapped to `KEY_SYSRQ`.
     */
    enum class Chord(val scanCode: Int, val modifiers: Int, val label: String) {
        /** Ctrl+C — copy, into the HOST's clipboard. */
        Copy(0x2E, MOD_CTRL, "Ctrl+C"),

        /** Ctrl+V — paste, from the HOST's clipboard. */
        Paste(0x2F, MOD_CTRL, "Ctrl+V"),

        /**
         * Print Screen.
         *
         * The host's own screenshot key, so the capture is taken and saved by
         * the host exactly as if someone had pressed it at the machine. That is
         * the difference between this and the button it replaces: the old
         * `PrtScr` icon called `rd_request_screenshot`, whose engine transport
         * is never established — its only writer has no callers anywhere in the
         * tree — so the call fell through an `if let Some(...)` and sent
         * nothing at all. Silent, and silent since it was written.
         */
        PrintScreen(0xE037, MOD_NONE, "PrtScn")
    }

    sealed class Action {
        /** Send the chord: modifier down, key down, key up, modifier up. */
        data class Send(val chord: Chord) : Action()

        /** Refused, with a reason worth telling the user. */
        data class Drop(val why: String) : Action()
    }

    /**
     * Whether a chord may be sent.
     *
     * **The gate is [InputEmissionPolicy.mayEmit]** — the same rule the pointer
     * and the keyboard go through, not a third copy of "when may input be
     * emitted". These keys are input like any other: Ctrl+V pastes into a
     * machine, and a phone that could send it while control was off would erase
     * the distinction between watching a screen and typing on it.
     */
    fun press(controlEnabled: Boolean, windowId: Long, chord: Chord): Action {
        if (!InputEmissionPolicy.mayEmit(controlEnabled, windowId)) {
            return Drop.reasonFor(controlEnabled)
        }
        return Action.Send(chord)
    }

    private object Drop {
        /**
         * Two refusals, told apart.
         *
         * "Turn on control" and "there is no session" need different things
         * from the user, and one message covering both would send them looking
         * for the wrong remedy.
         */
        fun reasonFor(controlEnabled: Boolean): Action.Drop =
            if (!controlEnabled) Action.Drop("control is not enabled")
            else Action.Drop("no window to send to")
    }
}
