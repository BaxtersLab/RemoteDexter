package com.remotedexter

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class InputControllerLifecycleTest {

    @Before
    fun resetState() {
        InputController.onControlStateChanged = null
        InputController.reset()
    }

    @After
    fun cleanup() {
        InputController.onControlStateChanged = null
        InputController.onControlDenied = null
        InputController.reset()
    }

    /**
     * A refusal the user cannot see is a button that does nothing.
     *
     * On 2026-08-25 the host acknowledged `grant_input` and then denied every
     * `input_event` on `RD_CAP_INPUT`, and the only trace was a log line. The
     * host now refuses the grant up front — which changes no client state,
     * because control was already off — so the reason has to reach the UI or
     * the operator is back to guessing.
     */
    @Test
    fun aRefusedGrantReportsTheHostsReason() {
        var seenCmd: String? = null
        var seenReason: String? = null
        InputController.onControlDenied = { cmd, reason ->
            seenCmd = cmd
            seenReason = reason
        }

        InputController.onDenied(
            "grant_input",
            "capability not authorized (set RD_CAP_INPUT=1)"
        )

        assertEquals("grant_input", seenCmd)
        assertTrue(
            "the reason must survive intact so the operator can act on it, got: $seenReason",
            seenReason?.contains("RD_CAP_INPUT") == true
        )
        assertFalse("a refused grant must not leave control on", InputController.isControlEnabled())
    }

    /** The Activity has to actually subscribe, and let go on the way out. */
    @Test
    fun mainActivitySubscribesToDenialsAndReleasesThemOnDestroy() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity {
                assertNotNull(
                    "MainActivity must listen for denials or they reach no one",
                    InputController.onControlDenied
                )
            }
        }
        assertNull(
            "a destroyed Activity must not stay subscribed",
            InputController.onControlDenied
        )
    }

    @Test
    fun sessionResetClearsTheGrantAndNotifiesTheUi() {
        val observed = mutableListOf<Boolean>()
        InputController.onControlStateChanged = { observed.add(it) }

        InputController.onAck("grant_input")
        InputController.reset()

        assertFalse(InputController.isControlEnabled())
        assertEquals(listOf(true, false), observed)
    }

    /**
     * The debug-only held-key affordance refuses without a granted session.
     *
     * This is the half of the affordance that IS reachable from a test with no
     * host: [HeldKeyPolicy] applies the same [InputEmissionPolicy] gate every
     * other input path applies, so a broadcast arriving before pairing, before a
     * session, or before Enable Control can hold nothing.
     *
     * The other half — hold a key, revoke control, and watch the host report the
     * release — needs a real host and is deliberately NOT asserted here. It is
     * the `held-key-loop` row in scripts/gate.manifest, UNVERIFIED, and it is a
     * round 14 acceptance criterion. `SessionOrchestrator.currentWindowId()` is
     * read-only by design — "only this class's own negotiation should ever
     * change it" — and a test seam that set it would weaken the thing being
     * relied on here to make the refusal true.
     */
    @Test
    fun aHeldKeyIsRefusedWithNoSession() {
        assertFalse("state leaked from another test", InputController.isHoldingKey())

        val refused = InputController.holdKey(42)

        assertTrue(
            "an ungranted hold must be refused, got $refused",
            refused is HeldKeyPolicy.Decision.Refuse
        )
        assertFalse(
            "a refused hold must not latch — a latch with no Down owes an Up " +
                "that would be injected on the host as a real key release",
            InputController.isHoldingKey()
        )
    }

    /**
     * Control alone is not enough: there must be a surface too.
     *
     * `onAck("grant_input")` turns control on without a session, which is the
     * state a stale ack or a replayed message produces. The window id is still
     * -1, so the emission gate must still refuse.
     */
    @Test
    fun aHeldKeyIsRefusedWhenControlIsOnButNoWindowIsPermitted() {
        InputController.onAck("grant_input")
        assertTrue("precondition: control is on", InputController.isControlEnabled())

        val refused = InputController.holdKey(42)

        assertTrue(
            "a hold with no permitted surface must be refused, got $refused",
            refused is HeldKeyPolicy.Decision.Refuse
        )
        assertEquals(
            "no session window",
            (refused as HeldKeyPolicy.Decision.Refuse).why
        )
        assertFalse(InputController.isHoldingKey())
    }

    /**
     * Releasing when nothing is held sends nothing and cannot throw.
     *
     * [InputController.reset] runs on every session end, every surface
     * destruction and every revoke, whether or not the affordance was ever used
     * — so the empty case is the common one, and a stray `KeyEvent` Up from it
     * would be injected on the host as a real key release.
     */
    @Test
    fun releasingAnEmptyHeldKeyLatchIsANoOp() {
        InputController.releaseHeldKeyIfHeld()
        InputController.reset()
        assertFalse(InputController.isHoldingKey())
    }
}
