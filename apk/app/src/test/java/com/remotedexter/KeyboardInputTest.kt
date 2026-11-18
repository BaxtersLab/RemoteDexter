package com.remotedexter

import com.remotedexter.KeyboardInput.Action
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    // ── RD-TEXT-1: a paragraph, bounded by the host's own ceiling ─────────────

    /**
     * The host refuses more than 2,000 characters. Sending such a run anyway
     * cleared the field and lost the text to a refusal the phone could have
     * predicted, so it must not leave the phone.
     */
    @Test
    fun aRunOverTheCeilingIsNotSent() {
        val staged = KeyboardInput.onStage(true, 0L, "a".repeat(2001))
        assertFalse("2,001 characters were sent", staged is Action.SendText)
        assertEquals(Action.TooLong(2001, 2000), staged)
        // The ceiling itself is accepted, so the bound is the stated one.
        assertEquals(Action.SendText("a".repeat(2000)), KeyboardInput.onStage(true, 0L, "a".repeat(2000)))
    }

    /** Go's Enter is a character the host types, so it counts. */
    @Test
    fun goCountsItsEnterAgainstTheCeiling() {
        val submitted = KeyboardInput.onCommit(true, 0L, "a".repeat(2000))
        assertFalse("2,000 characters plus Enter were sent", submitted is Action.SendText)
        assertEquals(Action.TooLong(2001, 2000), submitted)
        assertEquals(
            Action.SendText("a".repeat(1999) + "\n"),
            KeyboardInput.onCommit(true, 0L, "a".repeat(1999))
        )
    }

    /**
     * Counted as the host counts: code points. An emoji is two UTF-16 units
     * and one character; counting units would refuse 1,001 emoji the host
     * would have measured as 1,001.
     */
    @Test
    fun theCeilingCountsCharactersNotUtf16Units() {
        val emoji = "😀"
        assertEquals(1, KeyboardInput.characterCount(emoji))
        // 2,000 emoji are 2,000 characters — not over the CHARACTER limit,
        // whatever else is wrong with them (see the byte tests below)...
        assertFalse(KeyboardInput.onStage(true, 0L, emoji.repeat(2000)) is Action.TooLong)
        // ...and 2,001 are over it, counted as characters, not 4,002 units.
        assertEquals(Action.TooLong(2001, 2000), KeyboardInput.onStage(true, 0L, emoji.repeat(2001)))
    }

    // ── The input envelope: what one command can carry ──────────────────────

    /** The desktop surface's id, the longest a window id gets. */
    private val desktop = Long.MAX_VALUE

    /** Ordinary prose at the character ceiling fits with plenty of room. */
    @Test
    fun proseAtTheCharacterCeilingFitsTheInputEnvelope() {
        val prose = "Plain sentences, with commas; and a full stop. ".repeat(50).take(2000)
        assertEquals(Action.SendText(prose), KeyboardInput.onStage(true, desktop, prose))
        assertTrue(KeyboardInput.encodedCommandBytes(desktop, prose) < 3000)
    }

    /**
     * Under 2,000 characters and still too big: quotes escape to two bytes.
     * Sending it anyway is the case the native loop drops after saying yes.
     */
    @Test
    fun textUnderTheCharacterCeilingCanStillBeTooLargeToSend() {
        val quoted = "\"".repeat(2000)
        val action = KeyboardInput.onStage(true, desktop, quoted)
        assertTrue("$action", action is Action.TooLargeToSend)
        assertTrue((action as Action.TooLargeToSend).bytes > 4096)
        assertEquals(4096, action.max)
    }

    /** Emoji are one character each but four bytes. */
    @Test
    fun emojiCountOnceForTheCeilingButFourTimesForTheEnvelope() {
        val action = KeyboardInput.onStage(true, desktop, "😀".repeat(1100))
        assertTrue("$action", action is Action.TooLargeToSend)
    }

    /** The byte bound is exactly the envelope: 4,096 goes, 4,097 does not. */
    @Test
    fun theByteCeilingIsExact() {
        val base = KeyboardInput.encodedCommandBytes(desktop, "")
        val need = KeyboardInput.MAX_INPUT_COMMAND_BYTES - base
        val atMax = "\"".repeat(need / 2) + "a".repeat(need % 2)
        assertTrue(KeyboardInput.characterCount(atMax) <= KeyboardInput.MAX_TEXT_CHARS)
        assertEquals(4096, KeyboardInput.encodedCommandBytes(desktop, atMax))
        assertEquals(Action.SendText(atMax), KeyboardInput.onStage(true, desktop, atMax))
        assertEquals(
            Action.TooLargeToSend(4097, 4096),
            KeyboardInput.onStage(true, desktop, atMax + "a")
        )
    }

    /** Go's Enter is in the command too, and is measured with it. */
    @Test
    fun goIsMeasuredWithItsEnter() {
        val base = KeyboardInput.encodedCommandBytes(desktop, "")
        val need = KeyboardInput.MAX_INPUT_COMMAND_BYTES - base
        val fitsOnlyWithoutEnter = "\"".repeat(need / 2) + "a".repeat(need % 2)
        assertTrue(KeyboardInput.onStage(true, desktop, fitsOnlyWithoutEnter) is Action.SendText)
        assertTrue(KeyboardInput.onCommit(true, desktop, fitsOnlyWithoutEnter) is Action.TooLargeToSend)
    }

    /** The control gate still comes first: no control, no length verdict. */
    @Test
    fun anOverLongRunWithoutControlIsRefusedForControl() {
        assertEquals(
            Action.Drop("control not granted"),
            KeyboardInput.onStage(false, 0L, "a".repeat(5000))
        )
    }

    /** A real paragraph — past the old 256 — goes through untouched. */
    @Test
    fun aParagraphIsSentWhole() {
        val para = "Several sentences, well past the old limit. ".repeat(20).trim()
        assertTrue(para.length > 256)
        assertEquals(Action.SendText(para), KeyboardInput.onStage(true, 0L, para))
        assertEquals(Action.SendText(para + "\n"), KeyboardInput.onCommit(true, 0L, para))
    }
}
