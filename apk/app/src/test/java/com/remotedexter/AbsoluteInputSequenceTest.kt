package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wire ordering of an absolute click, and the gate in front of it.
 *
 * With a cursor lift set the host pointer is deliberately not under the
 * fingertip, so "click" and "click *there*" stop being the same instruction.
 * These assert the difference.
 */
class AbsoluteInputSequenceTest {

    private class Wire {
        val events = mutableListOf<String>()
        val move: (Int, Int) -> Unit = { x, y -> events += "move($x,$y)" }
        val button: (Int, String) -> Unit = { b, a -> events += "button($b,$a)" }
    }

    @Test
    fun a_tap_moves_to_the_target_before_it_presses_anything() {
        val w = Wire()
        AbsoluteInputSequence.tap(400, 250, w.move, w.button)
        assertEquals(
            listOf("move(400,250)", "button(0,Down)", "button(0,Up)"),
            w.events
        )
    }

    /**
     * A two-finger tap is a right click, and it moves first for a sharper
     * reason than a left click does: a context menu opens AT the pointer. A
     * right click that has not moved opens a menu somewhere the operator is not
     * looking, and the menu then eats their next tap as well.
     */
    @Test
    fun a_secondary_tap_moves_first_and_uses_the_right_button() {
        val w = Wire()
        AbsoluteInputSequence.secondaryTap(400, 250, w.move, w.button)
        assertEquals(
            listOf("move(400,250)", "button(1,Down)", "button(1,Up)"),
            w.events
        )
    }

    /** Left and right must not be the same button, however obvious that looks. */
    @Test
    fun the_two_buttons_are_different() {
        assertEquals(0, AbsoluteInputSequence.LEFT_BUTTON)
        assertEquals(1, AbsoluteInputSequence.RIGHT_BUTTON)
    }

    /**
     * The regression that matters. If the move ever moves after the press, the
     * host presses at the old pointer position and drags to the new one — which
     * is a selection, not a click, and it happens at every nonzero offset.
     */
    @Test
    fun a_tap_never_presses_before_it_has_moved() {
        val w = Wire()
        AbsoluteInputSequence.tap(1, 2, w.move, w.button)
        val firstMove = w.events.indexOfFirst { it.startsWith("move(") }
        val firstButton = w.events.indexOfFirst { it.startsWith("button(") }
        assertTrue("no move was emitted at all", firstMove >= 0)
        assertTrue("the button was pressed before the pointer moved", firstMove < firstButton)
    }

    @Test
    fun a_long_press_moves_then_holds_and_does_not_release() {
        val w = Wire()
        AbsoluteInputSequence.longPress(90, 80, w.move, w.button)
        assertEquals(listOf("move(90,80)", "button(0,Down)"), w.events)
        assertFalse(
            "a long press that releases its own button cannot click-and-drag",
            w.events.any { it.contains("Up") }
        )
    }

    @Test
    fun both_sequences_use_the_left_button_the_host_expects() {
        assertEquals(0, AbsoluteInputSequence.LEFT_BUTTON)
        val w = Wire()
        AbsoluteInputSequence.tap(0, 0, w.move, w.button)
        AbsoluteInputSequence.longPress(0, 0, w.move, w.button)
        assertTrue(
            "every button event must name button 0",
            w.events.filter { it.startsWith("button(") }.all { it.startsWith("button(0,") }
        )
    }

    // ── the gate ────────────────────────────────────────────────────────

    @Test
    fun viewing_only_emits_nothing_however_valid_the_session_is() {
        assertFalse(
            "viewing mode must be genuinely silent, not merely visually inert",
            InputEmissionPolicy.mayEmit(controlEnabled = false, windowId = 42L)
        )
        assertFalse(InputEmissionPolicy.mayEmit(controlEnabled = false, windowId = Long.MAX_VALUE))
    }

    @Test
    fun control_without_a_session_emits_nothing_either() {
        assertFalse(InputEmissionPolicy.mayEmit(controlEnabled = true, windowId = -1L))
    }

    @Test
    fun only_an_enabled_control_with_a_real_window_may_emit() {
        assertTrue(InputEmissionPolicy.mayEmit(controlEnabled = true, windowId = 0L))
        assertTrue(
            "the desktop sentinel is the id every real session uses",
            InputEmissionPolicy.mayEmit(controlEnabled = true, windowId = Long.MAX_VALUE)
        )
    }
}
