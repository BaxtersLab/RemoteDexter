package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Carrying text between the phone's clipboard and the host's.
 *
 * Plan §4.2 cut clipboard sync from v1 as a convenience that adds risk "before
 * view/control works end to end". It now does, and is proven on hardware, so
 * the stated precondition is met — the cut was sequencing, not a prohibition.
 * What was deleted was also not this: `clipboard_sync` ACKNOWLEDGED transfers it
 * never performed, and the host's own handler carried a note saying real
 * clipboard support came later.
 *
 * These tests hold the two things that make this safe to have: it never moves
 * without a press, and it moves under the same grant as every other way of
 * writing to the host.
 */
class ClipboardBridgeTest {

    private val streaming = 7L
    private val noWindow = -1L

    @Test
    fun textIsSentWhileControlIsGrantedAndThereIsAWindow() {
        assertEquals(
            ClipboardBridge.Action.Push("hello"),
            ClipboardBridge.push(true, streaming, "hello")
        )
    }

    /**
     * **Writing the host's clipboard is writing to the host.** A phone that
     * could do it while control was off would be putting text into a machine it
     * was only supposed to be watching.
     */
    @Test
    fun nothingIsSentWhileControlIsOff() {
        assertEquals(
            ClipboardBridge.Action.Drop(ClipboardBridge.Reason.NoControl),
            ClipboardBridge.push(false, streaming, "hello")
        )
    }

    /**
     * **Reading the host's clipboard is not viewing.** The clipboard holds what
     * was copied, which is very often something that was never on the screen —
     * so a peer with only a view would be taking data the view never showed
     * them. Same grant as the write, and for a reason, not for symmetry.
     */
    @Test
    fun theHostClipboardCannotBeReadWhileControlIsOff() {
        assertEquals(
            ClipboardBridge.Action.Drop(ClipboardBridge.Reason.NoControl),
            ClipboardBridge.pull(false, streaming)
        )
        assertEquals(ClipboardBridge.Action.Pull, ClipboardBridge.pull(true, streaming))
    }

    @Test
    fun nothingCrossesWithoutASession() {
        assertEquals(
            ClipboardBridge.Action.Drop(ClipboardBridge.Reason.NoSession),
            ClipboardBridge.push(true, noWindow, "hello")
        )
        assertEquals(
            ClipboardBridge.Action.Drop(ClipboardBridge.Reason.NoSession),
            ClipboardBridge.pull(true, noWindow)
        )
    }

    /**
     * ONE GATE. The pointer, the keyboard, the chords and this all decide
     * through `InputEmissionPolicy.mayEmit`; a fourth copy of "when may we
     * write to the host" is a copy that eventually disagrees, permissively.
     */
    @Test
    fun theClipboardGateAgreesWithTheMouseGateEverywhere() {
        for (control in listOf(true, false)) {
            for (window in listOf(-1L, 0L, 7L)) {
                val mouse = InputEmissionPolicy.mayEmit(control, window)
                assertEquals(
                    "push disagrees with the pointer at control=$control window=$window",
                    mouse,
                    ClipboardBridge.push(control, window, "x") is ClipboardBridge.Action.Push
                )
                assertEquals(
                    "pull disagrees with the pointer at control=$control window=$window",
                    mouse,
                    ClipboardBridge.pull(control, window) is ClipboardBridge.Action.Pull
                )
            }
        }
    }

    /**
     * An empty phone clipboard is its own refusal, not a silent no-op and not
     * an empty message. The user pressed a button; they are owed an answer, and
     * "you have not copied anything" is a different problem from "control is
     * off".
     */
    @Test
    fun anEmptyPhoneClipboardIsItsOwnRefusal() {
        assertEquals(
            ClipboardBridge.Action.Drop(ClipboardBridge.Reason.NothingToSend),
            ClipboardBridge.push(true, streaming, "")
        )
        assertEquals(
            ClipboardBridge.Action.Drop(ClipboardBridge.Reason.NothingToSend),
            ClipboardBridge.push(true, streaming, null)
        )
    }

    /**
     * Refused, not truncated. Half a password is not a password and half a
     * command is a different command — and the operator is told, on the phone,
     * rather than after a round trip ending in a denial they cannot act on.
     */
    @Test
    fun anOversizedSelectionIsRefusedWholeOnThePhone() {
        val huge = "a".repeat(ClipboardBridge.MAX_TEXT_BYTES + 1)
        assertEquals(
            ClipboardBridge.Action.Drop(ClipboardBridge.Reason.TooLarge),
            ClipboardBridge.push(true, streaming, huge)
        )
        assertTrue(
            ClipboardBridge.push(true, streaming, "a".repeat(ClipboardBridge.MAX_TEXT_BYTES))
                is ClipboardBridge.Action.Push
        )
    }

    /**
     * The limit counts BYTES, not characters. A cap read as characters lets
     * four times the bytes through on text that is not ASCII, and the host —
     * which counts bytes — would then refuse what the phone said was fine.
     */
    @Test
    fun theLimitIsMeasuredInBytes() {
        val wide = "é".repeat(ClipboardBridge.MAX_TEXT_BYTES) // two bytes each
        assertEquals(
            ClipboardBridge.Action.Drop(ClipboardBridge.Reason.TooLarge),
            ClipboardBridge.push(true, streaming, wide)
        )
    }

    /**
     * An empty reply clears the phone's clipboard, matching the host's.
     *
     * The first version refused to, because **empty was not trustworthy**:
     * `read_host_clipboard` returned `Ok("")` for every non-zero exit of
     * `wl-paste`, so nothing-copied, a clipboard holding an image, and a real
     * tool failure were one value — and overwriting on that would have let a
     * failure destroy what the operator had copied on their phone.
     *
     * The host now tells the three apart, so an empty reply means empty. The
     * operator asked for the overwrite; what made it safe was fixing the layer
     * underneath, not relaxing the check here.
     */
    @Test
    fun anEmptyReplyClearsThePhoneToMatchTheHost() {
        assertEquals(ClipboardBridge.Incoming.Clear, ClipboardBridge.receive(""))
        assertEquals(
            ClipboardBridge.Incoming.Replace("something"),
            ClipboardBridge.receive("something")
        )
    }

    /**
     * A message with no `text` field at all is NOT an empty clipboard. It is a
     * message that did not say, and only a host actually reporting an empty
     * clipboard may clear the phone's.
     */
    @Test
    fun anAbsentTextFieldIsNotAnEmptyClipboard() {
        assertEquals(ClipboardBridge.Incoming.Malformed, ClipboardBridge.receive(null))
    }

    /**
     * Every refusal is distinct, because each wants a different thing from the
     * user: grant control, connect, copy something, or select less.
     */
    @Test
    fun theRefusalsAreAllDistinguishable() {
        val seen = setOf(
            ClipboardBridge.push(false, streaming, "x"),
            ClipboardBridge.push(true, noWindow, "x"),
            ClipboardBridge.push(true, streaming, ""),
            ClipboardBridge.push(true, streaming, "a".repeat(ClipboardBridge.MAX_TEXT_BYTES + 1))
        )
        assertEquals("two refusals are the same value", 4, seen.size)
    }
}
