package com.remotedexter

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The latch exists to make one specific failure impossible: a `MouseButton`
 * Down with no matching Up, which leaves the host's left button held and turns
 * every subsequent cursor movement into a drag-select. Each test names the
 * concrete way that could happen.
 */
class DragLatchTest {

    @Test
    fun pressingOnceSendsExactlyOneDown() {
        val l = DragLatch()
        assertTrue("first press must send a Down", l.press())
        assertTrue(l.isLatched())
    }

    @Test
    fun pressingTwiceDoesNotSendASecondDown() {
        // A long-press callback firing twice, or a second finger landing, must
        // not double-press: the host would see Down,Down,Up and stay held.
        val l = DragLatch()
        l.press()
        assertFalse("second press must not send another Down", l.press())
    }

    @Test
    fun releasingWhenNotLatchedSendsNothing() {
        // Every finger-up calls release(). Only the ones that follow a latch
        // may send an Up — otherwise an ordinary tap emits a stray Up that the
        // host injects as a real button release.
        assertFalse("stray Up sent with nothing latched", DragLatch().release())
    }

    @Test
    fun releaseIsIdempotent() {
        val l = DragLatch()
        l.press()
        assertTrue("first release must send the Up", l.release())
        assertFalse("second release must send nothing", l.release())
        assertFalse(l.isLatched())
    }

    @Test
    fun resetWhileLatchedStillOwesAnUp() {
        // Session end / ACTION_CANCEL / control revoked mid-drag. The host has
        // a button held down; the client MUST still send the Up.
        val l = DragLatch()
        l.press()
        assertTrue("reset must report the owed Up", l.reset())
        assertFalse(l.isLatched())
    }

    @Test
    fun resetWhenIdleOwesNothing() {
        assertFalse("reset invented an Up", DragLatch().reset())
    }

    @Test
    fun aFullDragCycleLeavesNothingHeld() {
        val l = DragLatch()
        repeat(3) {
            assertTrue(l.press())
            assertTrue(l.release())
        }
        assertFalse("latch left held after balanced cycles", l.isLatched())
        assertFalse(l.reset())
    }
}
