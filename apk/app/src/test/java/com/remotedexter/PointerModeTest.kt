package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Touch and trackpad routing.
 *
 * Block 11 asks for both modes. The rules that matter are the ones about state:
 * trackpad has to remember where the finger was, and forgetting to forget is
 * what throws the cursor across the desktop.
 */
class PointerModeTest {

    @Test
    fun touchModeAlwaysPutsTheCursorWhereTheFingerIs() {
        val r = PointerModeRouter()
        assertEquals(
            PointerMove.Absolute(10f, 20f),
            r.onMove(PointerMode.Touch, 10f, 20f)
        )
        assertEquals(
            PointerMove.Absolute(300f, 400f),
            r.onMove(PointerMode.Touch, 300f, 400f)
        )
    }

    /**
     * **The classic trackpad bug.** Without this rule the first sample of a
     * gesture is measured against wherever the LAST gesture ended, so lifting
     * a finger and putting it down elsewhere hurls the cursor by that distance.
     * It only appears from the second gesture onwards, which is why it survives
     * casual testing.
     */
    @Test
    fun theFirstTouchOfAGestureProducesNoMove() {
        val r = PointerModeRouter()
        assertNull(r.onMove(PointerMode.Trackpad, 100f, 100f))
    }

    @Test
    fun trackpadModeSendsTheDistanceTravelled() {
        val r = PointerModeRouter()
        r.onMove(PointerMode.Trackpad, 100f, 100f)
        assertEquals(
            PointerMove.Relative(5f, -3f),
            r.onMove(PointerMode.Trackpad, 105f, 97f)
        )
    }

    /** The reference must advance, or deltas accumulate from the origin. */
    @Test
    fun deltasAreMeasuredFromThePreviousSampleNotTheFirst() {
        val r = PointerModeRouter()
        r.onMove(PointerMode.Trackpad, 0f, 0f)
        assertEquals(PointerMove.Relative(10f, 0f), r.onMove(PointerMode.Trackpad, 10f, 0f))
        assertEquals(PointerMove.Relative(10f, 0f), r.onMove(PointerMode.Trackpad, 20f, 0f))
    }

    /**
     * The bug the first-touch rule prevents, stated as a sequence: end a
     * gesture, start another far away, and nothing may be sent for the new
     * first touch.
     */
    @Test
    fun anewGestureAfterALiftDoesNotJumpTheCursor() {
        val r = PointerModeRouter()
        r.onMove(PointerMode.Trackpad, 100f, 100f)
        r.onMove(PointerMode.Trackpad, 110f, 100f)
        r.onGestureEnd()
        assertNull(
            "a finger put down elsewhere must not move the cursor by the gap",
            r.onMove(PointerMode.Trackpad, 900f, 700f)
        )
        // And the new gesture then tracks normally.
        assertEquals(PointerMove.Relative(1f, 1f), r.onMove(PointerMode.Trackpad, 901f, 701f))
    }

    /** A sample that did not move is not worth a wire round trip. */
    @Test
    fun aStationaryFingerSendsNothing() {
        val r = PointerModeRouter()
        r.onMove(PointerMode.Trackpad, 50f, 50f)
        assertNull(r.onMove(PointerMode.Trackpad, 50f, 50f))
    }

    /**
     * Touch mode still records the point, so switching to trackpad mid-gesture
     * does not treat the next sample as a first touch and silently drop it.
     */
    @Test
    fun switchingFromTouchToTrackpadMidGestureKeepsTracking() {
        val r = PointerModeRouter()
        r.onMove(PointerMode.Touch, 200f, 200f)
        assertEquals(
            PointerMove.Relative(4f, 4f),
            r.onMove(PointerMode.Trackpad, 204f, 204f)
        )
    }

    @Test
    fun theModeTogglesBetweenExactlyTwoValues() {
        assertEquals(PointerMode.Trackpad, PointerMode.Touch.next())
        assertEquals(PointerMode.Touch, PointerMode.Trackpad.next())
    }
}
