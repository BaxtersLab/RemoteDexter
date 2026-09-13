package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The RELEASE variant's copy of [BuildProfile]. Twin of
 * `testDebug/BuildProfileDebugTest`.
 *
 * **This is the test that says the affordance does not ship.** It runs in
 * `:app:testReleaseUnitTest`, against the release source set, so what it reads
 * is the constant a released APK would actually be compiled with — not a
 * runtime flag that something could set, and not a grep over a file.
 *
 * The gate runs this task as its own row for that reason. A debug-only
 * capability whose absence from release is checked only by the debug build is
 * not checked at all.
 */
class BuildProfileReleaseTest {

    @Test
    fun theReleaseBuildCompilesTheHeldKeyAffordanceOut() {
        assertFalse(
            "the release build must NOT carry the held-key affordance: it is a " +
                "test instrument that deliberately strands a key on the host",
            BuildProfile.HELD_KEY_AFFORDANCE
        )
    }

    @Test
    fun aReleaseBuildRefusesToHoldAnyKey() {
        // The policy, driven with the constant this variant really compiles,
        // rather than with a literal a test chose. Every holdable scan code is
        // refused, and so is the state where everything else would allow it.
        for (code in HeldKeyPolicy.HOLDABLE.keys) {
            val d = HeldKeyPolicy.mayHold(
                affordanceCompiledIn = BuildProfile.HELD_KEY_AFFORDANCE,
                controlGranted = true,
                windowId = 7,
                alreadyHeld = false,
                scanCode = code
            )
            assertTrue(
                "a release build authorised holding scan code $code: $d",
                d is HeldKeyPolicy.Decision.Refuse
            )
            assertEquals(
                "held-key affordance is not compiled into this build",
                (d as HeldKeyPolicy.Decision.Refuse).why
            )
        }
    }

    @Test
    fun theReleaseBuildNamesItself() {
        assertEquals("release", BuildProfile.NAME)
    }
}
