package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The numbers in [slowPreciseDragIsNotDiscarded], [justUnderTheFloorStillMoves]
 * and [ordinaryDragDoesNotUnderTravel] are the measured behaviour of the
 * shipped `InputController.onDrag` as of 2026-08-19, recorded in
 * ANDROID_INPUT_SPEC_2026-08-19.md §5.1. All three fail against the truncating
 * arithmetic and pass once the remainder is carried.
 */
class PointerMotionTest {

    /** Drive a whole gesture and total everything actually sent. */
    private fun totalTravel(
        motion: PointerMotion,
        samples: List<Float>,
        stepMs: Long = 100L,
    ): Int {
        var total = 0
        var now = 0L
        for (s in samples) {
            motion.onDragSample(s, 0f, now)?.let { total += it.dx }
            now += stepMs
        }
        motion.flush(now)?.let { total += it.dx }
        return total
    }

    // ── sub-pixel accumulation ──────────────────────────────────────────────

    @Test
    fun slowPreciseDragIsNotDiscarded() {
        // 100 samples of 0.40px at 1.5x == 60px of real travel.
        // Truncating per sample yields 0: every sample rounds to zero and is
        // dropped, so slow precise movement produces no cursor motion at all.
        val travel = totalTravel(PointerMotion(), List(100) { 0.40f })
        assertTrue("expected ~60px of travel, got $travel", travel in 59..61)
    }

    @Test
    fun justUnderTheFloorStillMoves() {
        // 0.66px * 1.5 == 0.99 -> truncates to 0. Just under the dead zone.
        val travel = totalTravel(PointerMotion(), List(100) { 0.66f })
        assertTrue("expected ~99px of travel, got $travel", travel in 97..100)
    }

    @Test
    fun ordinaryDragDoesNotUnderTravel() {
        // 3.0px * 1.5 == 4.5 -> truncates to 4, losing 0.5 per sample: ~11%
        // short at EVERY speed, not just slow ones. This is the defect that
        // makes sensitivity feel inconsistent, and retuning cannot fix it.
        val travel = totalTravel(PointerMotion(), List(100) { 3.0f })
        assertTrue("expected ~450px of travel, got $travel", travel in 449..451)
    }

    @Test
    fun negativeTravelAccumulatesSymmetrically() {
        // Truncation toward zero is symmetric, so the bug must not be fixed in
        // a way that biases one direction (e.g. floor() instead of a carry).
        val travel = totalTravel(PointerMotion(), List(100) { -0.40f })
        assertTrue("expected ~-60px of travel, got $travel", travel in -61..-59)
    }

    @Test
    fun carryDoesNotLeakAcrossReset() {
        val m = PointerMotion()
        m.onDragSample(0.4f, 0.4f, 0L)   // leaves a sub-pixel remainder
        m.reset()
        // After a reset the stale fraction must not push the next gesture over
        // the line early — a fresh single small sample still sends nothing.
        assertNull("stale carry leaked past reset", m.onDragSample(0.1f, 0.1f, 100L))
    }

    // ── coalescing ──────────────────────────────────────────────────────────

    @Test
    fun rapidSamplesAreCoalescedNotSentIndividually() {
        // 100 samples arriving 1ms apart is ~1000Hz — far above any real touch
        // rate, chosen so the interval is unambiguously the binding constraint.
        val m = PointerMotion()
        var sends = 0
        for (i in 0 until 100) {
            if (m.onDragSample(3.0f, 0f, i.toLong()) != null) sends++
        }
        assertTrue("expected far fewer than 100 sends, got $sends", sends <= 20)
        assertTrue("expected at least one send, got $sends", sends >= 1)
    }

    @Test
    fun coalescingPreservesTotalTravel() {
        // Fewer sends must not mean less movement: the whole point is that
        // deltas are folded together, not dropped.
        val travel = totalTravel(PointerMotion(), List(100) { 3.0f }, stepMs = 1L)
        assertTrue("coalescing lost travel: got $travel, expected ~450", travel in 449..451)
    }

    @Test
    fun flushAtGestureEndDoesNotStrandMovement() {
        val m = PointerMotion()
        // One sample, well inside the send interval, so it is still pending.
        m.onDragSample(10.0f, 0f, 0L)
        val flushed = m.flush(1L)
        assertNotNull("gesture end stranded the pending movement", flushed)
        assertEquals(15, flushed!!.dx)
    }

    @Test
    fun flushOnAnEmptyGestureSendsNothing() {
        assertNull("flush invented a message from nothing", PointerMotion().flush(0L))
    }

    @Test
    fun maxCoalesceBoundsLatencyWhenSamplesOutrunTheInterval() {
        // Every sample at the same instant: the time budget can never fire, so
        // only the sample cap can. Without it, movement would be held forever.
        val m = PointerMotion(maxCoalesce = 4)
        var sends = 0
        repeat(12) { if (m.onDragSample(3.0f, 0f, 0L) != null) sends++ }
        assertEquals("expected exactly 12/4 == 3 sends", 3, sends)
    }
}
