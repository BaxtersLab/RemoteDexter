package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The cursor-lift bound.
 *
 * An unbounded lift puts the cursor off-screen, where the user cannot see it
 * and every tap lands somewhere they did not look.
 */
class CursorLiftTest {

    @Test
    fun valuesInRangeArePreserved() {
        assertEquals(0, CursorLift.clamp(0))
        assertEquals(48, CursorLift.clamp(48))
        assertEquals(CursorLift.MAX_DP, CursorLift.clamp(CursorLift.MAX_DP))
    }

    @Test
    fun anAbsurdLiftIsClampedRatherThanAccepted() {
        assertEquals(CursorLift.MAX_DP, CursorLift.clamp(99999))
    }

    /** A negative lift would push the cursor under the finger, hiding it. */
    @Test
    fun aNegativeLiftIsClampedToZero() {
        assertEquals(0, CursorLift.clamp(-40))
        assertEquals(0, CursorLift.clamp(Int.MIN_VALUE))
    }

    /**
     * Clamping is applied on load as well as save. A preference file survives
     * upgrades and restores from backup, so a value this code never wrote can
     * still turn up in it.
     */
    @Test
    fun clampingIsIdempotentSoLoadCanApplyItToo() {
        assertEquals(CursorLift.MAX_DP, CursorLift.clamp(CursorLift.clamp(99999)))
    }
}
