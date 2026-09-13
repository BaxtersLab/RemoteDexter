package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The decision that authorises a lone key `Down`.
 *
 * The branch that matters most here is the FIRST one — the refusal a release
 * build gives. [BuildProfile.HELD_KEY_AFFORDANCE] is a `const val` compiled per
 * variant, so in a release build the compiler inlines `false` and this
 * affordance is dead code. A constant cannot be varied by a test, so the flag is
 * a parameter and both answers are executed here, in the ordinary debug run.
 * The constants themselves are asserted one per variant in `testDebug` and
 * `testRelease`, which is the only claim a shared test cannot make.
 */
class HeldKeyPolicyTest {

    private fun decide(
        compiledIn: Boolean = true,
        granted: Boolean = true,
        windowId: Long = 7,
        alreadyHeld: Boolean = false,
        scanCode: Int = 42
    ) = HeldKeyPolicy.mayHold(compiledIn, granted, windowId, alreadyHeld, scanCode)

    @Test
    fun aReleaseBuildRefuses() {
        // THE RELEASE BEHAVIOUR, executed. Everything else about this affordance
        // being absent from a shipping build is structural — a source set not
        // compiled, a manifest not merged. This is the runtime half, and it is
        // the reason the flag is a parameter rather than read directly.
        val d = decide(compiledIn = false)
        assertTrue(d is HeldKeyPolicy.Decision.Refuse)
        assertEquals(
            "held-key affordance is not compiled into this build",
            (d as HeldKeyPolicy.Decision.Refuse).why
        )
    }

    @Test
    fun aReleaseBuildRefusesEvenWhenEverythingElseIsPerfect() {
        // The flag is checked FIRST and independently: a release build must
        // refuse for the reason that is actually true, not report a session
        // problem it does not have.
        val d = decide(compiledIn = false, granted = true, windowId = 1, alreadyHeld = false)
        assertTrue("the compiled-out check must not be reachable past", d is HeldKeyPolicy.Decision.Refuse)
    }

    @Test
    fun holdingRequiresControl() {
        // A held key is input. Viewing and control are separate grants precisely
        // so that watching a screen cannot become typing on it, and this path
        // must not be the one place that forgets it.
        val d = decide(granted = false)
        assertEquals(
            "control is not granted",
            (d as HeldKeyPolicy.Decision.Refuse).why
        )
    }

    @Test
    fun holdingRequiresASessionWindow() {
        val d = decide(windowId = -1)
        assertEquals("no session window", (d as HeldKeyPolicy.Decision.Refuse).why)
    }

    @Test
    fun aSecondHoldIsRefusedWhileOneIsAlreadyHeld() {
        // The latch is single-slot, so a second Down would owe an Up nothing
        // records. Refusing here is what keeps the two in step.
        val d = decide(alreadyHeld = true)
        assertEquals(
            "a key is already held; release it first",
            (d as HeldKeyPolicy.Decision.Refuse).why
        )
    }

    @Test
    fun onlyTheInertKeysMayBeHeld() {
        // A held key REPEATS on the host. Shift, Ctrl and F13 held for a minute
        // change nothing; `A` fills whatever has focus, and focus may be a
        // shell. The set is the guard, and a caller naming anything else is
        // refused rather than clamped to a default.
        for (bad in listOf(30, 14, 57, 0, -1, 999)) {
            val d = decide(scanCode = bad)
            assertTrue("scan code $bad must not be holdable, got $d", d is HeldKeyPolicy.Decision.Refuse)
            assertEquals(
                "scan code $bad is not holdable",
                (d as HeldKeyPolicy.Decision.Refuse).why
            )
        }
    }

    @Test
    fun theInertKeysAreHeldAndNamed() {
        // F13 is the odd one out and it is there on purpose: the other three are
        // all MODIFIERS, which left Windows round 15 unable to ask whether the
        // stuck key belonged to modifier scan codes or to the release path
        // itself. 0x64 is already this project's vetted safe held key on
        // Windows — press_and_hold_chord holds Ctrl+F13 and reads it back.
        assertEquals(
            "the holdable set changed — say so in the round TODO before it travels",
            mapOf(42 to "LeftShift", 54 to "RightShift", 29 to "LeftCtrl", 100 to "F13"),
            HeldKeyPolicy.HOLDABLE
        )
        for ((code, name) in HeldKeyPolicy.HOLDABLE) {
            val d = decide(scanCode = code)
            assertTrue("$name must be holdable", d is HeldKeyPolicy.Decision.Hold)
            d as HeldKeyPolicy.Decision.Hold
            assertEquals(code, d.scanCode)
            assertEquals("the log names the key, not just the number", name, d.keyName)
        }
    }
}
