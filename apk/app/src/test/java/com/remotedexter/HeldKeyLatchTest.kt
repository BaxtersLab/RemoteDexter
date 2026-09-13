package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The latch behind the debug-only held-key affordance.
 *
 * The affordance exists to send a `KeyEvent` Down with no Up on purpose, which
 * is the exact thing the rest of the client is built to make impossible. What
 * keeps it safe is that the owed Up is always known and always recoverable, so
 * every test here names the concrete way a key could be stranded on the host.
 */
class HeldKeyLatchTest {

    @Test
    fun pressingOnceOwesExactlyOneDown() {
        val l = HeldKeyLatch()
        assertTrue("first press must send a Down", l.press(42))
        assertTrue(l.isHeld())
        assertEquals(42, l.held())
    }

    @Test
    fun pressingASecondKeyDoesNotSendASecondDown() {
        // Two broadcasts in a row. A second Down would owe a second Up that a
        // single-slot latch cannot record, so the first key would be stranded.
        val l = HeldKeyLatch()
        l.press(42)
        assertFalse("second press must not send another Down", l.press(29))
        assertEquals("the first key must remain the held one", 42, l.held())
    }

    @Test
    fun pressingTheSameKeyTwiceDoesNotSendASecondDown() {
        val l = HeldKeyLatch()
        l.press(42)
        assertFalse("repeat press must not send another Down", l.press(42))
    }

    @Test
    fun releasingWhenNothingIsHeldSendsNothing() {
        // reset() runs on every session end, whether or not the affordance was
        // ever used. A stray Up would be injected on the host as a real release.
        assertNull("stray Up sent with nothing held", HeldKeyLatch().release())
    }

    @Test
    fun releaseReportsTheOwedScanCodeThenIsIdempotent() {
        val l = HeldKeyLatch()
        l.press(54)
        assertEquals("release must name the key owed an Up", 54, l.release())
        assertNull("second release must send nothing", l.release())
        assertFalse(l.isHeld())
    }

    @Test
    fun resetWhileHeldStillOwesAnUp() {
        // Control revoked, surface destroyed or session ended while a key is
        // down. The host is holding it; the client MUST still send the Up.
        val l = HeldKeyLatch()
        l.press(29)
        assertEquals("reset must report the owed Up", 29, l.reset())
        assertFalse(l.isHeld())
    }

    @Test
    fun resetWhenIdleOwesNothing() {
        assertNull("reset invented an Up", HeldKeyLatch().reset())
    }

    @Test
    fun balancedCyclesLeaveNothingHeld() {
        val l = HeldKeyLatch()
        repeat(3) {
            assertTrue(l.press(42))
            assertEquals(42, l.release())
        }
        assertFalse("latch left held after balanced cycles", l.isHeld())
        assertNull(l.reset())
    }
}
