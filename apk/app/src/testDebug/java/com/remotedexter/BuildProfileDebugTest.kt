package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The DEBUG variant's copy of [BuildProfile]. Its twin is
 * `testRelease/BuildProfileReleaseTest`, and the pair is the whole proof.
 *
 * A shared test in `src/test` cannot make this claim: it compiles against
 * whichever variant is running and would simply assert whatever it was handed.
 * These two run in different unit-test tasks against different source sets, so
 * between them they state that the debug build has the affordance and the
 * release build does not.
 *
 * If this test is ever seen to fail, the two files have been merged into one and
 * the release guarantee has been lost.
 */
class BuildProfileDebugTest {

    @Test
    fun theDebugBuildCompilesTheHeldKeyAffordanceIn() {
        assertTrue(
            "the debug build must carry the affordance — Windows cannot prove " +
                "the N key(s) half of the shutdown message without it",
            BuildProfile.HELD_KEY_AFFORDANCE
        )
    }

    @Test
    fun theDebugBuildNamesItself() {
        assertEquals("debug", BuildProfile.NAME)
    }
}
