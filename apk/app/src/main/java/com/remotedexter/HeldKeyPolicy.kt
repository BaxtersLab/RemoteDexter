package com.remotedexter

/**
 * When the debug-only held-key affordance may put a lone `Down` on the wire.
 *
 * # Why the flag is a parameter
 *
 * [BuildProfile.HELD_KEY_AFFORDANCE] is a `const val` compiled per variant —
 * true in the debug source set, false in the release one — so a release build
 * inlines `false` here and the affordance is dead code in it. That is the
 * structural guarantee, but a constant cannot be varied by a test, and a branch
 * no test can execute is a branch nobody has checked.
 *
 * So the decision takes the flag as an argument. Both answers are then
 * executable on the JVM in the ordinary debug unit-test run — including the one
 * that matters, the refusal a release build would give. The variant constants
 * themselves are asserted separately, one test per variant source set, because
 * that is the only claim a shared test cannot make.
 *
 * # One gate, not two
 *
 * The control/session half of the decision is [InputEmissionPolicy.mayEmit] —
 * the SAME rule the pointer and keyboard paths use — not a second condition
 * written out here. A held key is still input, and it must be impossible to
 * hold one in a state where an ordinary click could not be sent. A copy of that
 * rule is a copy that eventually disagrees, and the direction it would disagree
 * in is permissive.
 *
 * The affordance flag is checked FIRST and separately, so a refusal in a release
 * build says so plainly rather than being reported as a session problem.
 */
object HeldKeyPolicy {

    /** What the caller should do. [Refuse.why] is for the log. */
    sealed class Decision {
        /** Send `KeyEvent{scan_code, action:"Down"}` and latch it. */
        data class Hold(val scanCode: Int, val keyName: String) : Decision()

        /** Send nothing. */
        data class Refuse(val why: String) : Decision()
    }

    /**
     * Scan codes this affordance will hold.
     *
     * Deliberately not "any key the caller names". A held key repeats on the
     * host, so the set is restricted to keys whose auto-repeat is inert on a
     * desktop. Holding Shift for thirty seconds changes nothing about the
     * host's state; holding `A` fills whatever has focus, and whatever has
     * focus may be a shell.
     *
     * # F13 is here to answer a question, and it is the odd one out
     *
     * The first three are all **modifier** keys, and that was invisible until
     * Windows round 15 measured a revoke leaving LeftShift down for at least 90
     * seconds. With only modifiers holdable, there is no way to ask whether the
     * defect belongs to modifier scan codes or to the release path as a whole —
     * every experiment available used the same kind of key.
     *
     * F13 (scan `0x64`) is an ordinary key that does nothing on a desktop, and
     * it is **already this project's vetted safe held key on Windows**:
     * `host_app`'s `press_and_hold_chord` holds Ctrl+F13 and reads it back, so
     * it is not a new risk being introduced for one round's convenience.
     *
     * That makes round 16's comparison a clean A/B — hold 42, hold 100, read
     * both back — instead of a guess.
     *
     * Set 1 scan codes, matching [KeyboardInput.SCAN_BACKSPACE]'s numbering and
     * what `module10::keymap` expects on the wire.
     */
    val HOLDABLE: Map<Int, String> = mapOf(
        42 to "LeftShift",
        54 to "RightShift",
        29 to "LeftCtrl",
        100 to "F13"
    )

    /**
     * May a lone `Down` be sent for [scanCode]?
     *
     * @param affordanceCompiledIn [BuildProfile.HELD_KEY_AFFORDANCE].
     * @param controlGranted whether the host has acked `grant_input`.
     * @param windowId the permitted surface, or negative when there is none.
     * @param alreadyHeld whether the latch already owes an Up.
     */
    fun mayHold(
        affordanceCompiledIn: Boolean,
        controlGranted: Boolean,
        windowId: Long,
        alreadyHeld: Boolean,
        scanCode: Int
    ): Decision {
        if (!affordanceCompiledIn) {
            return Decision.Refuse("held-key affordance is not compiled into this build")
        }
        if (!InputEmissionPolicy.mayEmit(controlGranted, windowId)) {
            return Decision.Refuse(
                if (!controlGranted) "control is not granted" else "no session window"
            )
        }
        if (alreadyHeld) {
            return Decision.Refuse("a key is already held; release it first")
        }
        val name = HOLDABLE[scanCode]
            ?: return Decision.Refuse("scan code $scanCode is not holdable")
        return Decision.Hold(scanCode, name)
    }
}
