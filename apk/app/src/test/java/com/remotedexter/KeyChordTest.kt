package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Ctrl+C, Ctrl+V and Print Screen.
 *
 * These buttons existed, did not work, and were deleted by an agent that never
 * asked the operator who used them. Two separate failures, worth keeping
 * straight:
 *
 * - **They never did what they said.** `btnCopy` sent the PHONE's clipboard to
 *   the host; `btnPaste` sent an empty payload commented "empty triggers host
 *   fetch"; the host handler logged the bytes beside a note saying real
 *   clipboard support "comes later". Neither ever pressed a key.
 * - **`PrtScr` was worse.** It called `rd_request_screenshot`, whose engine
 *   transport has one writer with no callers anywhere in the tree, so the call
 *   fell through `if let Some(transport)` and sent nothing at all.
 *
 * They are now ordinary key events on the injection path proven on hardware,
 * so the labels are the truth: Ctrl+C presses Ctrl and C **on the host**.
 */
class KeyChordTest {

    private val streaming = 7L
    private val noWindow = -1L

    private fun sent(controlEnabled: Boolean, windowId: Long, chord: KeyChord.Chord) =
        KeyChord.press(controlEnabled, windowId, chord)

    /**
     * Set 1 scan codes, checked against the map that will receive them.
     * `inject_linux::set1_to_evdev` passes `0x01..=0x58` through one-to-one, so
     * C and V land on evdev's `KEY_C` and `KEY_V`; a wrong code here would type
     * a different letter into whatever has focus on the host.
     */
    @Test
    fun theChordsCarryTheKeysTheirLabelsName() {
        assertEquals(0x2E, KeyChord.Chord.Copy.scanCode)
        assertEquals(0x2F, KeyChord.Chord.Paste.scanCode)
        assertEquals(0xE037, KeyChord.Chord.PrintScreen.scanCode)
    }

    /**
     * Copy and paste are Control chords; Print Screen is a key on its own.
     * Sending Print Screen with Control held would be a different keystroke,
     * and on many desktops a different feature.
     */
    @Test
    fun onlyTheClipboardChordsHoldControl() {
        assertEquals(KeyChord.MOD_CTRL, KeyChord.Chord.Copy.modifiers)
        assertEquals(KeyChord.MOD_CTRL, KeyChord.Chord.Paste.modifiers)
        assertEquals(KeyChord.MOD_NONE, KeyChord.Chord.PrintScreen.modifiers)
    }

    /**
     * The modifier bit has to be the one the host reads. `module10::message`
     * defines `MOD_CTRL = 0x02` and its own doc records that these constants
     * once lived in three places, each with a comment saying it must match the
     * others — the arrangement in which they eventually do not.
     */
    @Test
    fun theControlBitMatchesTheHostsDefinition() {
        assertEquals(0x02, KeyChord.MOD_CTRL)
        assertEquals(0x00, KeyChord.MOD_NONE)
    }

    @Test
    fun aChordIsSentWhileControlIsGrantedAndThereIsAWindow() {
        for (chord in KeyChord.Chord.values()) {
            assertEquals(
                KeyChord.Action.Send(chord),
                sent(controlEnabled = true, windowId = streaming, chord = chord)
            )
        }
    }

    /**
     * **Ctrl+V pastes into a machine.** A phone that could send it while
     * control was off would erase the distinction between watching a screen and
     * typing on it, which is the distinction the whole consent model rests on.
     */
    @Test
    fun noChordIsSentWhileControlIsOff() {
        for (chord in KeyChord.Chord.values()) {
            assertTrue(
                "$chord was emitted with control off",
                sent(controlEnabled = false, windowId = streaming, chord = chord)
                    is KeyChord.Action.Drop
            )
        }
    }

    @Test
    fun noChordIsSentWithoutAWindow() {
        for (chord in KeyChord.Chord.values()) {
            assertTrue(
                "$chord was emitted with no window",
                sent(controlEnabled = true, windowId = noWindow, chord = chord)
                    is KeyChord.Action.Drop
            )
        }
    }

    /**
     * ONE GATE, NOT A THIRD COPY. The keyboard and the pointer both decide
     * through `InputEmissionPolicy.mayEmit`, and a chord button carrying its
     * own idea of "when may input be emitted" is a copy that eventually
     * disagrees — permissively, since that is the direction such copies drift.
     */
    @Test
    fun theChordGateAgreesWithTheMouseGateEverywhere() {
        for (control in listOf(true, false)) {
            for (window in listOf(-1L, 0L, 7L)) {
                val mouse = InputEmissionPolicy.mayEmit(control, window)
                val chord = sent(control, window, KeyChord.Chord.Copy) is KeyChord.Action.Send
                assertEquals(
                    "chord and pointer disagree at control=$control window=$window",
                    mouse,
                    chord
                )
            }
        }
    }

    /**
     * The two refusals are told apart, because they need different things from
     * the user: one wants Enable pressed, the other wants a connection. A
     * single message covering both sends them looking for the wrong remedy —
     * and the operator has already lost time to a button that refused in total
     * silence.
     */
    @Test
    fun theTwoRefusalsAreDistinguishable() {
        val noControl = sent(false, streaming, KeyChord.Chord.Copy) as KeyChord.Action.Drop
        val noSession = sent(true, noWindow, KeyChord.Chord.Copy) as KeyChord.Action.Drop
        assertTrue(noControl.why != noSession.why)
        assertTrue(noControl.why.isNotBlank())
        assertTrue(noSession.why.isNotBlank())
    }

    /**
     * Every chord has a label, and no two share one. Three unlabelled or
     * identically labelled buttons in a row would be three buttons the operator
     * has to press to find out what they do — and one of them presses Ctrl+V.
     */
    @Test
    fun everyChordIsLabelledAndNoTwoAlike() {
        val labels = KeyChord.Chord.values().map { it.label }
        assertEquals(labels.size, labels.toSet().size)
        for (label in labels) assertTrue(label.isNotBlank())
    }
}
