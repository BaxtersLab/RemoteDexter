package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The control that justifies the whole design.
 *
 * The obvious way to build "move the cursor above my fingertip" is to subtract a
 * constant from the touch position and keep sending relative deltas. It cannot
 * work, and this test is the proof executed rather than asserted in a comment:
 * a constant vanishes under subtraction.
 *
 *     (p2 - o) - (p1 - o) = p2 - p1
 *
 * The user would drag a slider, watch it move, and the host cursor would behave
 * exactly as before. That is a worse outcome than the feature not existing,
 * because it looks like it works.
 *
 * This test passes today and must keep passing: it does not describe a bug to
 * fix, it describes why the shipping path had to become absolute. If it ever
 * fails, someone has made relative deltas offset-sensitive, and that is a much
 * stranger thing to have done.
 */
class CursorOffsetNoOpControlTest {

    private fun relativeDeltas(touches: List<Pair<Float, Float>>, offsetPx: Float): List<Pair<Float, Float>> {
        val out = mutableListOf<Pair<Float, Float>>()
        for (i in 1 until touches.size) {
            val (x1, y1) = touches[i - 1]
            val (x2, y2) = touches[i]
            // Each sample has the offset applied before differencing — the
            // naive implementation.
            out += Pair(x2 - x1, (y2 - offsetPx) - (y1 - offsetPx))
        }
        return out
    }

    @Test
    fun a_constant_offset_cancels_out_of_relative_deltas_and_changes_nothing() {
        val path = listOf(10f to 200f, 12f to 190f, 40f to 120f, 41f to 121f)
        val withoutOffset = relativeDeltas(path, 0f)
        for (offset in listOf(1f, 25f, 120f, 400f)) {
            assertEquals(
                "an offset of $offset px changed the relative deltas; " +
                    "if this ever fails the no-op argument no longer holds",
                withoutOffset,
                relativeDeltas(path, offset)
            )
        }
    }

    @Test
    fun the_same_is_true_however_large_the_offset_or_the_movement() {
        val path = listOf(0f to 0f, 1000f to 1000f)
        assertEquals(relativeDeltas(path, 0f), relativeDeltas(path, 5000f))
    }
}
