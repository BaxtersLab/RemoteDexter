package com.remotedexter

import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The diagnostic that separates "the new geometry never arrived" from "it
 * arrived and was not rendered" — the exact ambiguity that stopped Windows
 * Round 2 from closing check 2.
 */
class FrameGeometryChangeTest {

    @Test
    fun theFirstFrameIsNotAChange() {
        assertNull(
            "arriving at a size is not a change; logging it every reconnect trains the reader to ignore the line",
            FrameGeometryChange.message(null, 1440 to 900, 1)
        )
    }

    @Test
    fun aSteadyStreamSaysNothing() {
        assertNull(FrameGeometryChange.message(1440 to 900, 1440 to 900, 7))
    }

    @Test
    fun aRotationIsReportedWithBothGeometries() {
        val m = FrameGeometryChange.message(1440 to 900, 900 to 1440, 42)
        assertTrue("expected both geometries, got: $m", m!!.contains("1440x900"))
        assertTrue("expected both geometries, got: $m", m.contains("900x1440"))
        assertTrue("the sequence locates it in the log, got: $m", m.contains("42"))
    }

    @Test
    fun theRevertIsReportedToo() {
        // F2 is the revert failing, so it must be as visible as the turn.
        val m = FrameGeometryChange.message(900 to 1440, 1440 to 900, 99)
        assertTrue("expected the revert to be reported, got: $m", m!!.contains("900x1440"))
        assertTrue(m.contains("1440x900"))
    }

    /**
     * The three lines answer three different questions, and conflating them is
     * what misdirected the 2026-08-26 Windows trip: arrival is not decode, and
     * decode is not render.
     */
    @Test
    fun arrivalStatesTheFrameSFateNotJustItsSize() {
        val queued = FrameGeometryChange.message(
            1440 to 900, 900 to 1440, 5, viewerAttached = true
        )
        assertTrue("must say the frame went on to decode: $queued", queued!!.contains("queued"))

        val discarded = FrameGeometryChange.message(
            1440 to 900, 900 to 1440, 5, viewerAttached = false
        )
        assertTrue(
            "a frame with nowhere to go must say so, or it reads as delivered: $discarded",
            discarded!!.contains("DISCARDED")
        )
    }

    @Test
    fun theDecodedSizeIsReportedSeparatelyFromTheDeclaredOne() {
        val m = FrameGeometryChange.decodedMessage(1440 to 900, 900 to 1440, 7)
        assertTrue("must be distinguishable from the arrival line: $m", m!!.contains("DECODED"))
        assertTrue(m.contains("900x1440"))
        assertNull(FrameGeometryChange.decodedMessage(900 to 1440, 900 to 1440, 8))
    }

    /** The only line that proves pixels changed. */
    @Test
    fun theRenderedSizeIsReportedOnlyWhenItActuallyChanges() {
        val m = FrameGeometryChange.renderedMessage(1440 to 900, 900 to 1440)
        assertTrue("must be distinguishable from arrival and decode: $m", m!!.contains("RENDERED"))
        assertNull("no change, no line", FrameGeometryChange.renderedMessage(900 to 1440, 900 to 1440))
        assertNull("the first draw is not a change", FrameGeometryChange.renderedMessage(null, 1440 to 900))
    }

    @Test
    fun aResolutionChangeAtTheSameOrientationIsAlsoAChange() {
        assertTrue(
            "not every geometry change is a rotation",
            FrameGeometryChange.message(1920 to 1080, 1280 to 720, 5) != null
        )
    }
}
