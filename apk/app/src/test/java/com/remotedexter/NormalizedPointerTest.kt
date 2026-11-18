package com.remotedexter

import com.remotedexter.mobile.render.DesktopCoordinateMapper
import com.remotedexter.mobile.render.DesktopCoordinateMapper.RenderGeometry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NormalizedPointerTest {
    @Test
    fun video_resolution_never_changes_the_pointer_target() {
        for (size in listOf(1920 to 1080, 1440 to 810, 1286 to 722, 960 to 540, 768 to 432, 632 to 356)) {
            val g = RenderGeometry(1080, 2280, size.first, size.second, 1f, 0f, 0f)
            val r = DesktopCoordinateMapper.destinationRect(g)!!
            val p = DesktopCoordinateMapper.mapTouchToNormalized(
                g, r.left + r.width * 0.75f, r.top + r.height * 0.75f, 0f
            )!!
            assertEquals("x for $size", 49151, p.x)
            assertEquals("y for $size", 49151, p.y)
        }
    }

    @Test
    fun zoom_pan_and_cursor_lift_use_the_drawn_rectangle_not_video_pixels() {
        for (size in listOf(1920 to 1080, 960 to 540, 632 to 356)) {
            val g = RenderGeometry(2280, 1080, size.first, size.second, 2.5f, 37f, -82f)
            val r = DesktopCoordinateMapper.destinationRect(g)!!
            val p = DesktopCoordinateMapper.mapTouchToNormalized(
                g, r.left + r.width * 0.25f, r.top + r.height * 0.5f + 48f, 48f
            )!!
            assertEquals(16384, p.x)
            assertEquals(32768, p.y)
        }
    }

    @Test
    fun corners_and_letterboxes_clamp_to_the_normalized_axis() {
        val g = RenderGeometry(1080, 2280, 960, 540, 1f, 0f, 0f)
        val r = DesktopCoordinateMapper.destinationRect(g)!!
        assertEquals(
            DesktopCoordinateMapper.DesktopPoint(0, 0),
            DesktopCoordinateMapper.mapTouchToNormalized(g, r.left - 100f, r.top - 100f, 0f)
        )
        assertEquals(
            DesktopCoordinateMapper.DesktopPoint(65535, 65535),
            DesktopCoordinateMapper.mapTouchToNormalized(g, r.right + 100f, r.bottom + 100f, 0f)
        )
    }

    @Test
    fun unavailable_geometry_and_invalid_touch_still_refuse_input() {
        val g = RenderGeometry(1080, 2280, 960, 540, 1f, 0f, 0f)
        assertNull(DesktopCoordinateMapper.mapTouchToNormalized(g.copy(frameWidth = 0), 0f, 0f, 0f))
        assertNull(DesktopCoordinateMapper.mapTouchToNormalized(g, Float.NaN, 0f, 0f))
        assertNull(DesktopCoordinateMapper.mapTouchToNormalized(g, 0f, 0f, -1f))
    }
}
