package com.remotedexter

import com.remotedexter.KeyboardInput.Action
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The keyboard gate. Block 11 requires that text is sent **only while control
 * is granted** — the rule that keeps viewing from becoming typing.
 */
class KeyboardInputTest {

    @Test
    fun textIsSentWhenStreamingAndControlIsGranted() {
        assertEquals(
            Action.SendText("hello"),
            KeyboardInput.onTextTyped(controlGranted = true, windowId = 0L, added = "hello")
        )
    }

    /** The rule the consent model rests on: viewing must never become typing. */
    @Test
    fun textIsNeverSentWhileControlIsOff() {
        assertEquals(
            Action.Drop("control not granted"),
            KeyboardInput.onTextTyped(controlGranted = false, windowId = 0L, added = "secret")
        )
    }

    @Test
    fun nothingIsSentWithoutASession() {
        assertEquals(
            Action.Drop("no session"),
            KeyboardInput.onTextTyped(controlGranted = true, windowId = -1L, added = "x")
        )
    }

    /** The two refusals need different remedies, so they must not read alike. */
    @Test
    fun theTwoRefusalsAreDistinguishable() {
        val noSession = KeyboardInput.onTextTyped(true, -1L, "x") as Action.Drop
        val noControl = KeyboardInput.onTextTyped(false, 0L, "x") as Action.Drop
        assertNotEquals(noSession.why, noControl.why)
    }

    @Test
    fun anEmptyRunSendsNothing() {
        assertEquals(Action.Drop("nothing typed"), KeyboardInput.onTextTyped(true, 0L, ""))
    }

    @Test
    fun backspaceIsSentAsAKeyNotAsText() {
        assertEquals(
            Action.SendKey(KeyboardInput.SCAN_BACKSPACE),
            KeyboardInput.onBackspace(controlGranted = true, windowId = 0L)
        )
    }

    /** Backspace obeys exactly the same gate as text. */
    @Test
    fun backspaceIsAlsoRefusedWhileControlIsOff() {
        assertEquals(
            Action.Drop("control not granted"),
            KeyboardInput.onBackspace(controlGranted = false, windowId = 0L)
        )
    }

    @Test
    fun aPlainAppendIsTheDelta() {
        assertEquals("lo", KeyboardInput.appendedText("hel", "hello"))
        assertEquals("h", KeyboardInput.appendedText("", "h"))
    }

    /**
     * **The autocorrect case.** An IME replacing "teh" with "the" reports a
     * whole new buffer. Treating that as typing would retype the word into a
     * remote shell, so anything that is not a pure append is refused.
     */
    @Test
    fun aReplacementIsNotAnAppendAndIsRefused() {
        assertNull(
            "autocorrect must not be replayed as typing",
            KeyboardInput.appendedText("teh", "the")
        )
        assertNull("a mid-string edit is not typing", KeyboardInput.appendedText("cat", "cart"))
    }

    /** A deletion produces no characters and must not look like one. */
    @Test
    fun aDeletionIsNotAnAppend() {
        assertNull(KeyboardInput.appendedText("hello", "hell"))
        assertNull(KeyboardInput.appendedText("x", ""))
    }

    @Test
    fun anUnchangedBufferYieldsNoDelta() {
        assertNull(KeyboardInput.appendedText("same", "same"))
    }

    /**
     * The keyboard uses the SAME gate as the mouse, not a copy of it.
     *
     * Asserted by agreement across the whole truth table: a second condition
     * written out in KeyboardInput would eventually disagree with the mouse's,
     * and the direction it would disagree in is permissive.
     */
    @Test
    fun theKeyboardGateAgreesWithTheMouseGateEverywhere() {
        for (control in listOf(true, false)) {
            for (window in listOf(-1L, 0L, 42L)) {
                val mouseMay = InputEmissionPolicy.mayEmit(control, window)
                val keyboardSent =
                    KeyboardInput.onTextTyped(control, window, "x") is Action.SendText
                assertEquals(
                    "control=$control window=$window: keyboard and mouse gates disagree",
                    mouseMay,
                    keyboardSent
                )
                val backspaceSent =
                    KeyboardInput.onBackspace(control, window) is Action.SendKey
                assertEquals(
                    "control=$control window=$window: backspace and mouse gates disagree",
                    mouseMay,
                    backspaceSent
                )
            }
        }
    }

    // ── composing ────────────────────────────────────────────────────

    /** Committing sends the line and the Enter that runs it, in one message. */
    @Test
    fun committingSendsTheLineWithATrailingNewline() {
        assertEquals(
            Action.SendText("ls -la\n"),
            KeyboardInput.onCommit(controlGranted = true, windowId = 0L, buffer = "ls -la")
        )
    }

    /**
     * Enter on an empty field is a deliberate blank line — at a shell prompt
     * that is how you get a fresh prompt back. Swallowing it would make the key
     * feel broken.
     */
    @Test
    fun committingAnEmptyFieldStillSendsANewline() {
        assertEquals(
            Action.SendText("\n"),
            KeyboardInput.onCommit(true, 0L, "")
        )
    }

    /** Committing obeys the same gate as everything else. */
    @Test
    fun committingIsRefusedWhileControlIsOff() {
        assertEquals(
            Action.Drop("control not granted"),
            KeyboardInput.onCommit(controlGranted = false, windowId = 0L, buffer = "rm -rf /")
        )
    }

    /**
     * **Type and Enter must not be the same act.**
     *
     * They were, and it made the keyboard unable to fill in a field: both sent
     * the line with a trailing Enter, so there was no way to put text
     * somewhere on the host without submitting it. The operator's words:
     * "enter is send and send is enter".
     */
    @Test
    fun stagingTypesTheLineWithoutSubmittingIt() {
        assertEquals(
            Action.SendText("username"),
            KeyboardInput.onStage(controlGranted = true, windowId = 0L, buffer = "username")
        )
    }

    /** The pair, asserted together, so they cannot quietly converge again. */
    @Test
    fun onlyCommitAppendsTheEnter() {
        val staged = KeyboardInput.onStage(true, 0L, "ls -la") as Action.SendText
        val committed = KeyboardInput.onCommit(true, 0L, "ls -la") as Action.SendText
        assertEquals("ls -la", staged.text)
        assertEquals("ls -la\n", committed.text)
        assertEquals(
            "commit must be exactly the staged text plus the Enter",
            staged.text + "\n",
            committed.text
        )
    }

    /**
     * "Type nothing" has no useful reading, unlike an empty COMMIT — which is a
     * deliberate bare Enter, and how you get a fresh shell prompt.
     */
    @Test
    fun stagingAnEmptyFieldSendsNothingWhileCommittingItSendsAnEnter() {
        assertEquals(Action.Drop("nothing typed"), KeyboardInput.onStage(true, 0L, ""))
        assertEquals(Action.SendText("\n"), KeyboardInput.onCommit(true, 0L, ""))
    }

    /** Staging obeys the same gate as everything else. */
    @Test
    fun stagingIsRefusedWhileControlIsOff() {
        assertEquals(
            Action.Drop("control not granted"),
            KeyboardInput.onStage(controlGranted = false, windowId = 0L, buffer = "secret")
        )
    }

    /**
     * The whole point of composing: a typo is fixed locally, before it reaches
     * a shell. Backspace with text in the field must NOT reach the host.
     */
    @Test
    fun backspaceEditsLocallyWhileThereIsTextToEdit() {
        assertEquals(
            Action.Drop("editing locally"),
            KeyboardInput.onBackspaceWithBuffer(true, 0L, "abc")
        )
    }

    /**
     * Once the field is empty there is nothing local left to delete, so
     * Backspace becomes remote — the only way to remove text on the host that
     * was never typed here.
     */
    @Test
    fun backspaceOnAnEmptyFieldReachesTheHost() {
        assertEquals(
            Action.SendKey(KeyboardInput.SCAN_BACKSPACE),
            KeyboardInput.onBackspaceWithBuffer(true, 0L, "")
        )
    }

    /** And a remote backspace is still gated. */
    @Test
    fun aRemoteBackspaceIsStillRefusedWhileControlIsOff() {
        assertEquals(
            Action.Drop("control not granted"),
            KeyboardInput.onBackspaceWithBuffer(false, 0L, "")
        )
    }

    /** Newline and tab are ordinary characters here; the host maps them. */
    @Test
    fun newlineAndTabAreCarriedAsText() {
        assertEquals(Action.SendText("\n"), KeyboardInput.onTextTyped(true, 0L, "\n"))
        assertEquals("\t", KeyboardInput.appendedText("a", "a\t"))
    }
}
