package com.remotedexter

import com.remotedexter.mobile.render.DesktopCoordinateMapper
import com.remotedexter.mobile.render.DesktopCoordinateMapper.RenderGeometry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The arithmetic behind "click where the cursor is shown, not where the finger
 * is". All of it runs on the JVM: no device, no host, no mocks.
 */
class DesktopCoordinateMapperTest {

    /** A 1920x1080 desktop on a 1080x2280 phone held upright: heavy letterboxing. */
    private fun portraitPhone(zoom: Float = 1f, panX: Float = 0f, panY: Float = 0f) =
        RenderGeometry(1080, 2280, 1920, 1080, zoom, panX, panY)

    /** The same desktop on the same phone turned sideways: a near-perfect fit. */
    private fun landscapePhone(zoom: Float = 1f, panX: Float = 0f, panY: Float = 0f) =
        RenderGeometry(2280, 1080, 1920, 1080, zoom, panX, panY)

    private fun map(g: RenderGeometry, x: Float, y: Float, offset: Float = 0f) =
        DesktopCoordinateMapper.mapTouchToDesktop(g, x, y, offset)

    // ── fit-center, both orientations ────────────────────────────────────

    @Test
    fun the_centre_of_the_drawn_frame_is_the_centre_of_the_desktop() {
        for (g in listOf(portraitPhone(), landscapePhone())) {
            val r = DesktopCoordinateMapper.destinationRect(g)!!
            val p = map(g, (r.left + r.right) / 2f, (r.top + r.bottom) / 2f)!!
            assertEquals("x centre for $g", 960, p.x)
            assertEquals("y centre for $g", 540, p.y)
        }
    }

    @Test
    fun the_corners_of_the_drawn_frame_are_the_corners_of_the_desktop() {
        for (g in listOf(portraitPhone(), landscapePhone())) {
            val r = DesktopCoordinateMapper.destinationRect(g)!!
            assertEquals(DesktopCoordinateMapper.DesktopPoint(0, 0), map(g, r.left, r.top))
            // Bottom-right maps to the last real pixel, not one past it.
            val br = map(g, r.right, r.bottom)!!
            assertEquals(1919, br.x)
            assertEquals(1079, br.y)
        }
    }

    /** A 16:9 desktop in a tall viewport must be pillar/letterboxed, not stretched. */
    @Test
    fun fit_center_letterboxes_rather_than_stretching() {
        val g = portraitPhone()
        val r = DesktopCoordinateMapper.destinationRect(g)!!
        assertEquals("width should fill the viewport", 1080f, r.width, 0.01f)
        assertEquals("height is 1080 * (1080/1920)", 607.5f, r.height, 0.01f)
        assertTrue("there must be letterbox above the frame", r.top > 1f)
        assertEquals("letterbox is symmetric", r.top, g.viewportHeight - r.bottom, 0.01f)
    }

    // ── the offset itself ───────────────────────────────────────────────

    @Test
    fun the_offset_is_applied_in_view_space_before_the_inverse_scale() {
        val g = landscapePhone()
        val r = DesktopCoordinateMapper.destinationRect(g)!!
        val cx = (r.left + r.right) / 2f
        val cy = (r.top + r.bottom) / 2f

        val noOffset = map(g, cx, cy, 0f)!!
        val lifted = map(g, cx, cy, 100f)!!

        assertEquals("x must not move", noOffset.x, lifted.x)
        assertTrue("the cursor must be ABOVE the finger", lifted.y < noOffset.y)

        // 100 view px at this scale is 100 / (r.height/1080) desktop px.
        val expected = noOffset.y - (100f / (r.height / 1080f)).toInt()
        assertTrue(
            "expected roughly $expected, got ${lifted.y}",
            kotlin.math.abs(lifted.y - expected) <= 1
        )
    }

    /**
     * The ordering that makes the feature usable. If the offset were applied in
     * desktop pixels after the inverse scale, zooming in would drag the cursor
     * away from the fingertip; the physical gap the user chose must survive zoom.
     */
    @Test
    fun the_finger_to_cursor_gap_stays_constant_on_screen_as_zoom_changes() {
        val offset = 90f
        val gaps = listOf(1f, 2f, 4f).map { zoom ->
            val g = landscapePhone(zoom = zoom)
            val r = DesktopCoordinateMapper.destinationRect(g)!!
            val cx = (r.left + r.right) / 2f
            val cy = (r.top + r.bottom) / 2f
            val plain = map(g, cx, cy, 0f)!!
            val lifted = map(g, cx, cy, offset)!!
            // Convert the desktop-pixel difference back to view pixels.
            (plain.y - lifted.y) * (r.height / 1080f)
        }
        for (gap in gaps) {
            assertEquals("the on-screen gap must stay ~${offset}px at every zoom", offset, gap, 2f)
        }
    }

    @Test
    fun a_large_offset_clamps_at_the_top_desktop_edge_and_never_goes_negative() {
        val g = landscapePhone()
        val r = DesktopCoordinateMapper.destinationRect(g)!!
        val p = map(g, (r.left + r.right) / 2f, r.top + 5f, 5000f)!!
        assertEquals("must clamp to the top row, not go negative", 0, p.y)
        assertTrue("x is untouched by a vertical offset", p.x in 0..1919)
    }

    @Test
    fun a_touch_in_the_letterbox_clamps_to_the_nearest_desktop_edge() {
        val g = portraitPhone()
        val r = DesktopCoordinateMapper.destinationRect(g)!!
        // Well above the drawn frame — in the black bar.
        val above = map(g, (r.left + r.right) / 2f, r.top - 200f)!!
        assertEquals(0, above.y)
        val below = map(g, (r.left + r.right) / 2f, r.bottom + 200f)!!
        assertEquals(1079, below.y)
    }

    @Test
    fun every_result_is_inside_the_frame_for_any_touch_anywhere() {
        val g = portraitPhone()
        for (x in -500..1500 step 97) {
            for (y in -500..2500 step 197) {
                for (off in listOf(0f, 60f, 500f)) {
                    val p = map(g, x.toFloat(), y.toFloat(), off)!!
                    assertTrue("x out of range: ${p.x}", p.x in 0..1919)
                    assertTrue("y out of range: ${p.y}", p.y in 0..1079)
                }
            }
        }
    }

    // ── zoom and pan invert the rectangle that was drawn ─────────────────

    @Test
    fun zoom_and_pan_invert_the_same_rectangle_the_renderer_draws() {
        val g = landscapePhone(zoom = 2.5f, panX = -140f, panY = 60f)
        val r = DesktopCoordinateMapper.destinationRect(g)!!
        // Round-trip: pick desktop points, compute where the renderer puts them,
        // map back, and require the original.
        for ((dx, dy) in listOf(0 to 0, 960 to 540, 1919 to 1079, 100 to 900)) {
            val viewX = r.left + (dx + 0.5f) / 1920f * r.width
            val viewY = r.top + (dy + 0.5f) / 1080f * r.height
            val back = map(g, viewX, viewY)!!
            assertTrue("x round-trip $dx -> ${back.x}", kotlin.math.abs(back.x - dx) <= 1)
            assertTrue("y round-trip $dy -> ${back.y}", kotlin.math.abs(back.y - dy) <= 1)
        }
    }

    @Test
    fun panning_moves_the_mapped_point_in_the_opposite_direction() {
        val base = landscapePhone(zoom = 2f)
        val r = DesktopCoordinateMapper.destinationRect(base)!!
        val probeX = (r.left + r.right) / 2f
        val probeY = (r.top + r.bottom) / 2f
        val centre = map(base, probeX, probeY)!!
        // Pan the image right; the same screen point now sits over a point
        // further LEFT in the desktop.
        val panned = map(landscapePhone(zoom = 2f, panX = 200f), probeX, probeY)!!
        assertTrue("panning right must move the mapped x left", panned.x < centre.x)
    }

    // ── orientation changes must not leave stale geometry ────────────────

    @Test
    fun a_landscape_portrait_landscape_cycle_maps_against_the_current_geometry_each_time() {
        val land = landscapePhone()
        val port = RenderGeometry(1080, 2280, 1080, 1920, 1f, 0f, 0f) // host rotated too
        val landCentre = DesktopCoordinateMapper.destinationRect(land)!!
        val portCentre = DesktopCoordinateMapper.destinationRect(port)!!

        val a = map(land, (landCentre.left + landCentre.right) / 2f, (landCentre.top + landCentre.bottom) / 2f)!!
        assertEquals(960, a.x); assertEquals(540, a.y)

        val b = map(port, (portCentre.left + portCentre.right) / 2f, (portCentre.top + portCentre.bottom) / 2f)!!
        assertEquals("portrait desktop centre x", 540, b.x)
        assertEquals("portrait desktop centre y", 960, b.y)

        val c = map(land, (landCentre.left + landCentre.right) / 2f, (landCentre.top + landCentre.bottom) / 2f)!!
        assertEquals("returning to landscape must not inherit portrait geometry", a, c)
    }

    // ── fail closed ──────────────────────────────────────────────────────

    @Test
    fun unusable_geometry_produces_no_coordinate_at_all() {
        val bad = listOf(
            RenderGeometry(0, 2280, 1920, 1080, 1f, 0f, 0f),
            RenderGeometry(1080, 0, 1920, 1080, 1f, 0f, 0f),
            RenderGeometry(1080, 2280, 0, 1080, 1f, 0f, 0f),
            RenderGeometry(1080, 2280, 1920, 0, 1f, 0f, 0f),
            RenderGeometry(1080, 2280, 1920, 1080, 0f, 0f, 0f),
            RenderGeometry(1080, 2280, 1920, 1080, Float.NaN, 0f, 0f),
            RenderGeometry(1080, 2280, 1920, 1080, 1f, Float.NaN, 0f),
            RenderGeometry(-1, -1, -1, -1, 1f, 0f, 0f)
        )
        for (g in bad) {
            assertNull("destinationRect must refuse $g", DesktopCoordinateMapper.destinationRect(g))
            assertNull("mapping must refuse $g", map(g, 100f, 100f))
        }
    }

    @Test
    fun a_nonsense_touch_or_offset_produces_no_coordinate() {
        val g = landscapePhone()
        assertNull(map(g, Float.NaN, 100f))
        assertNull(map(g, 100f, Float.NaN))
        assertNull(map(g, 100f, 100f, Float.NaN))
        assertNull("a negative offset is not a thing the slider can mean", map(g, 100f, 100f, -5f))
        assertNotNull("but zero offset is perfectly valid", map(g, 100f, 100f, 0f))
    }

    // ── dp conversion ────────────────────────────────────────────────────

    @Test
    fun the_offset_is_a_physical_distance_not_a_pixel_count() {
        // Same dp, different densities -> different pixel counts, same physical gap.
        assertEquals(0f, DesktopCoordinateMapper.dpToPx(0, 3f), 0.001f)
        assertEquals(120f, DesktopCoordinateMapper.dpToPx(60, 2f), 0.001f)
        assertEquals(240f, DesktopCoordinateMapper.dpToPx(60, 4f), 0.001f)
        assertEquals("a negative dp is clamped away", 0f, DesktopCoordinateMapper.dpToPx(-10, 3f), 0.001f)
        assertEquals("a nonsense density yields no offset", 0f, DesktopCoordinateMapper.dpToPx(60, 0f), 0.001f)
    }
}
