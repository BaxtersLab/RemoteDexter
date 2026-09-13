package com.remotedexter

import com.remotedexter.mobile.render.Scaling
import com.remotedexter.mobile.render.ScalingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Fit versus original: the arithmetic that decides how far to zoom. */
class ScalingModeTest {

    private val max = 4f

    /**
     * The headline case: a 1920px desktop letterboxed into a 1080px-wide view
     * is drawn at 0.5625, so 1:1 needs its inverse.
     */
    @Test
    fun originalIsTheInverseOfTheFitScale() {
        val z = Scaling.originalZoom(1080, 2280, 1920, 1080, max)!!
        assertEquals(1920f / 1080f, z, 0.001f)
    }

    /** The axis that runs out first decides the letterbox, and so the inverse. */
    @Test
    fun theLimitingAxisDecides() {
        // Very wide viewport: height is the constraint.
        val z = Scaling.originalZoom(4000, 500, 1920, 1080, max)!!
        assertEquals(1080f / 500f, z, 0.001f)
    }

    /**
     * A desktop far larger than the phone cannot reach true 1:1 within the
     * renderer's ceiling. Zooming as far as it allows is honest; asking for a
     * scale that will be silently refused leaves the control looking broken.
     */
    @Test
    fun anEnormousDesktopIsClampedToTheCeiling() {
        val z = Scaling.originalZoom(1080, 2280, 7680, 4320, max)!!
        assertEquals(max, z, 0.001f)
    }

    /**
     * A desktop smaller than the viewport is already at or above 1:1 when
     * fitted, so "original" must not mean zooming OUT — the pipeline's floor is
     * fit and would refuse it.
     */
    @Test
    fun aSmallDesktopNeverZoomsBelowFit() {
        val z = Scaling.originalZoom(3000, 3000, 640, 480, max)!!
        assertEquals(1f, z, 0.001f)
    }

    /**
     * Fails closed. 1f is a legitimate answer, so it cannot double as "I don't
     * know" — a caller could not tell the two apart.
     */
    @Test
    fun unusableGeometryYieldsNullNotAGuess() {
        assertNull(Scaling.originalZoom(0, 2280, 1920, 1080, max))
        assertNull(Scaling.originalZoom(1080, 0, 1920, 1080, max))
        assertNull(Scaling.originalZoom(1080, 2280, 0, 1080, max))
        assertNull(Scaling.originalZoom(1080, 2280, 1920, 0, max))
        assertNull(Scaling.originalZoom(-1, 2280, 1920, 1080, max))
    }

    @Test
    fun theFactorReachesTheTargetFromWhereverWeAre() {
        val f = Scaling.factorToReach(target = 2f, current = 0.5f)!!
        assertEquals(4f, f, 0.001f)
        assertEquals(2f, 0.5f * f, 0.001f)
    }

    @Test
    fun theFactorRefusesNonsenseRatherThanProducingInfinity() {
        assertNull(Scaling.factorToReach(target = 2f, current = 0f))
        assertNull(Scaling.factorToReach(target = 0f, current = 1f))
        assertNull(Scaling.factorToReach(target = Float.NaN, current = 1f))
    }

    @Test
    fun theModeTogglesBetweenExactlyTwoValues() {
        assertEquals(ScalingMode.Original, ScalingMode.Fit.next())
        assertEquals(ScalingMode.Fit, ScalingMode.Original.next())
    }
}
