package com.remotedexter

import com.remotedexter.ToolbarAction.Diagnostics
import com.remotedexter.ToolbarAction.Keyboard
import com.remotedexter.ToolbarAction.Pair
import com.remotedexter.ToolbarAction.PointerMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which toolbar icons are live, in every session state.
 *
 * These rules were single lines inside `MainActivity` and were untestable
 * there. They are pinned here because **the icon toolbar deleted the labels**:
 * a control's availability is now carried entirely by whether it looks dim, so
 * a wrong rule no longer looks like a wrong rule — it looks like a rendering
 * bug, which is the one kind of defect this project keeps paying for twice.
 */
class ToolbarAvailabilityTest {

    private val idle = SessionState.Idle
    private val connecting = SessionState.Connecting("desk")
    private val streaming = SessionState.Streaming("desk")
    private val failed = SessionState.Failed(FailureReason.Network, "no route")
    private val mismatch = SessionState.IdentityMismatch("aa11", "bb22")

    /** Every state the UI can be in, so a sweep really is a sweep. */
    private val allStates = listOf(idle, connecting, streaming, failed, mismatch)

    private fun enabledIn(action: ToolbarAction): List<SessionState> =
        allStates.filter { ToolbarAvailability.isEnabled(action, it) }

    @Test
    fun typingIsOfferedOnlyWhereTextCanLand() {
        assertEquals(listOf(streaming), enabledIn(Keyboard))
    }

    /**
     * Connecting is not streaming. Written out because `SessionState.isActive`
     * covers both, and reaching for it here is the natural mistake: it would
     * open the compose bar over a picture that does not exist yet, and the
     * first line typed would be sent into a transport still shaking hands.
     */
    @Test
    fun aHalfEstablishedSessionOffersNoTyping() {
        assertTrue(connecting.isActive)
        assertFalse(ToolbarAvailability.isEnabled(Keyboard, connecting))
    }

    /**
     * An identity mismatch is the state where re-pairing is most likely to be
     * what the user wants, and it is terminal — so if Pair were gated on "not
     * active" or "not failed" this screen would be a dead end with no way out
     * but a force-stop.
     */
    @Test
    fun pairingIsReachableFromAnIdentityMismatch() {
        assertTrue(ToolbarAvailability.isEnabled(Pair, mismatch))
    }

    @Test
    fun pairingAndDiagnosticsAreNeverGatedOnASession() {
        assertEquals(allStates, enabledIn(Pair))
        assertEquals(allStates, enabledIn(Diagnostics))
    }

    /**
     * The pointer mode is a preference about how a finger is interpreted, not
     * an action against a host. Setting it before connecting is legitimate and
     * has to stay possible.
     */
    @Test
    fun thePointerPreferenceIsAvailableWithNoSessionAtAll() {
        assertEquals(allStates, enabledIn(PointerMode))
    }

    /**
     * No state may leave the whole row dim. A toolbar of five grey icons with
     * no words on it says nothing about why, and the user's only remaining
     * move is to guess — the failure mode that made every refusal in Block 5
     * visible in the first place.
     */
    @Test
    fun noStateLeavesTheEntireToolbarDead() {
        for (state in allStates) {
            val live = ToolbarAction.values().filter { ToolbarAvailability.isEnabled(it, state) }
            assertTrue("$state left every toolbar control disabled", live.isNotEmpty())
        }
    }

    /**
     * Streaming is the state everything is for; nothing may be withheld in it.
     * This is the complement of the test above and catches the opposite slip —
     * a rule written as a refusal that accidentally refuses the good case too.
     */
    @Test
    fun everyControlIsLiveWhileStreaming() {
        for (action in ToolbarAction.values()) {
            assertTrue(
                "$action was disabled during a live session",
                ToolbarAvailability.isEnabled(action, streaming)
            )
        }
    }

    /**
     * A failure is not a reason to take away the controls that diagnose it.
     * Only the one that needs somewhere for text to land goes away.
     */
    @Test
    fun afterAFailureOnlyTheStreamBoundControlsGoAway() {
        val dead = ToolbarAction.values()
            .filterNot { ToolbarAvailability.isEnabled(it, failed) }
            .toSet()
        assertEquals(setOf(Keyboard), dead)
    }
}
