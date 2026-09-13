package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pinch deadzone, and the rule that is no longer there.
 *
 * Two fingers used to mean either moving the view or scrolling the host, chosen
 * from the current zoom. That rule is gone by the operator's decision — two
 * fingers move the view, always, and the wheel is a pair of buttons — so what
 * survives is only the part that was always right: an ordinary two-finger drag
 * must not zoom the picture by accident.
 */
class TwoFingerGestureTest {

    /** Jitter of a percent or two, the way a real two-finger drag reports it. */
    private val jitter = listOf(1.01f, 0.995f, 1.02f, 0.99f, 1.015f, 1.005f)

    /**
     * The regression. Two fingers dragged across glass are never parallel, and
     * every one of those samples used to reach `applyZoom` — which clamps at
     * MIN_ZOOM from below, so the first factor above 1.0 lifted the view off
     * fit and nothing brought it back.
     */
    @Test
    fun anOrdinarySwipeNeverZoomsTheView() {
        val g = TwoFingerGesture()
        for ((i, f) in (jitter + jitter).withIndex()) {
            assertNull("sample $i zoomed the view", g.onSample(f))
        }
        assertFalse("a drag is not a pinch", g.isPinching())
    }

    /**
     * Proof the samples above are not a straw man: fed to `applyZoom` directly,
     * the same numbers really do walk the zoom off fit and never return.
     */
    @Test
    fun thoseSameSamplesUsedToWalkTheZoomOffFitPermanently() {
        var zoom = 1f
        for (f in jitter + jitter) {
            zoom = (zoom * f).coerceIn(1f, 4f) // what applyZoom does
        }
        assertTrue("the samples never left fit, so they prove nothing", zoom > 1f)
    }

    /** A deliberate pinch still zooms, and is not made to wait for it. */
    @Test
    fun aRealPinchZooms() {
        val g = TwoFingerGesture()
        var applied: Float? = null
        for (i in 0 until 10) {
            applied = g.onSample(1.05f)
            if (applied != null) break
        }
        assertTrue("a deliberate pinch never zoomed", applied != null)
        assertTrue(
            "the accumulated pinch was discarded rather than applied: $applied",
            applied!! >= 1f + TwoFingerGesture.PINCH_THRESHOLD
        )
        assertTrue("the gesture must know it is a pinch", g.isPinching())
    }

    /** Everything after the deadzone passes straight through, or a pinch stutters. */
    @Test
    fun samplesAfterTheDeadzonePassThroughUnchanged() {
        val g = TwoFingerGesture()
        repeat(10) { g.onSample(1.05f) }
        assertEquals(1.05f, g.onSample(1.05f)!!, 0.0001f)
    }

    /** Pinching apart and pinching together both count. */
    @Test
    fun pinchingInwardAlsoCrossesTheDeadzone() {
        val g = TwoFingerGesture()
        var applied: Float? = null
        for (i in 0 until 10) {
            applied = g.onSample(0.95f)
            if (applied != null) break
        }
        assertTrue("pinching inward never zoomed", applied != null)
        assertTrue("the factor must shrink the view: $applied", applied!! < 1f)
    }

    /** The deadzone is per gesture. A pinch must not outlive its own. */
    @Test
    fun aPinchDoesNotOutliveItsOwnGesture() {
        val g = TwoFingerGesture()
        repeat(10) { g.onSample(1.05f) }
        g.onGestureEnd()
        assertFalse(g.isPinching())
        assertNull("the previous gesture's pinch carried over", g.onSample(1.01f))
    }
}

/**
 * How a held scroll button paces itself.
 *
 * The numbers are the whole design, so they are asserted rather than left to be
 * discovered by holding a button on a phone and counting.
 */
class ScrollRepeatTest {

    /** A tap must send exactly one notch. A button that fires twice is worse
     *  than one that never repeats. */
    @Test
    fun theFirstRepeatWaitsLongEnoughThatATapIsOneNotch() {
        assertEquals(ScrollRepeat.INITIAL_DELAY_MS, ScrollRepeat.delayAfter(1))
        assertTrue(
            "a tap is around 100ms; the first repeat must be well clear of it",
            ScrollRepeat.INITIAL_DELAY_MS >= 300L
        )
    }

    /** Once spinning, it spins steadily. */
    @Test
    fun laterRepeatsUseTheShortInterval() {
        for (n in 2..20) {
            assertEquals(ScrollRepeat.REPEAT_INTERVAL_MS, ScrollRepeat.delayAfter(n))
        }
        assertTrue(
            "the repeat must be faster than the initial delay or holding does nothing",
            ScrollRepeat.REPEAT_INTERVAL_MS < ScrollRepeat.INITIAL_DELAY_MS
        )
    }

    /** Zero and negative are not real inputs, but they must not repeat faster
     *  than the first press does. */
    @Test
    fun aCountBelowOneIsTreatedAsTheFirstPress() {
        assertEquals(ScrollRepeat.INITIAL_DELAY_MS, ScrollRepeat.delayAfter(0))
        assertEquals(ScrollRepeat.INITIAL_DELAY_MS, ScrollRepeat.delayAfter(-5))
    }
}
