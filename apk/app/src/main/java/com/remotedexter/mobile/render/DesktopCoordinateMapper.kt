package com.remotedexter.mobile.render

import kotlin.math.min
import kotlin.math.roundToInt

/**
 * The one description of where the desktop is drawn, and the only way back.
 *
 * ## Why this file exists
 *
 * Two pieces of code have to agree about the destination rectangle: the
 * renderer, which draws the frame into it, and the touch mapper, which converts
 * a fingertip back into a desktop pixel. If they each compute it, they will
 * eventually disagree — and the symptom is not a crash, it is clicks landing
 * near but not on the thing the user touched, which is exactly the class of bug
 * nobody can reproduce on demand.
 *
 * So the arithmetic lives here once. [SurfaceFramePipeline] calls
 * [destinationRect] to draw, and records the geometry it drew with;
 * [mapTouchToDesktop] inverts that same rectangle. Neither has its own copy.
 *
 * ## No Android in here
 *
 * Deliberately. This is plain Kotlin over plain numbers, so every case that
 * actually goes wrong — letterboxing, a pinch mid-gesture, a device rotation
 * that changes both the viewport and the frame, a touch in the black bar — is
 * provable on the JVM in milliseconds, with no device, no emulator, no host and
 * no mocks. `RectF` would have dragged in `android.graphics` and cost all of
 * that for a struct with four floats in it.
 *
 * ## Fail closed
 *
 * Every entry point returns `null` rather than a guess when the geometry is not
 * usable. A remote-control client that invents a coordinate when it does not
 * know where the frame is will click something. Clicking nothing is the correct
 * behaviour; clicking *somewhere* is not.
 */
object DesktopCoordinateMapper {

    /** A rectangle in view pixels. Right and bottom are exclusive-ish edges, as in the renderer. */
    data class DestRect(val left: Float, val top: Float, val right: Float, val bottom: Float) {
        val width: Float get() = right - left
        val height: Float get() = bottom - top
        fun isUsable(): Boolean =
            width > 0f && height > 0f &&
                left.isFinite() && top.isFinite() && right.isFinite() && bottom.isFinite()
    }

    /**
     * Everything needed to place a frame on screen, captured together.
     *
     * Captured *together* is the point. Viewport and frame dimensions change
     * independently — a device rotation changes the viewport immediately and the
     * frame only when the next frame arrives from a host that has itself
     * rotated. Reading them from two places at two moments is how a mapper ends
     * up inverting a rectangle that was never drawn.
     */
    data class RenderGeometry(
        val viewportWidth: Int,
        val viewportHeight: Int,
        val frameWidth: Int,
        val frameHeight: Int,
        val zoom: Float,
        val panX: Float,
        val panY: Float
    ) {
        fun isUsable(): Boolean =
            viewportWidth > 0 && viewportHeight > 0 &&
                frameWidth > 0 && frameHeight > 0 &&
                zoom > 0f && zoom.isFinite() &&
                panX.isFinite() && panY.isFinite()
    }

    /** A point in the coordinate space requested by the mapping function. */
    data class DesktopPoint(val x: Int, val y: Int)

    /**
     * Where the frame is drawn: fit-center, then zoom about that rectangle's own
     * centre, then pan.
     *
     * This is the renderer's behaviour, moved rather than reimplemented. At
     * `zoom == 1` and `pan == (0,0)` it is plain fit-center, byte for byte the
     * same rectangle as before this feature existed.
     */
    fun destinationRect(g: RenderGeometry): DestRect? {
        if (!g.isUsable()) return null

        val scale = min(
            g.viewportWidth.toFloat() / g.frameWidth.toFloat(),
            g.viewportHeight.toFloat() / g.frameHeight.toFloat()
        )
        if (!scale.isFinite() || scale <= 0f) return null

        val scaledW = g.frameWidth * scale
        val scaledH = g.frameHeight * scale
        val left = (g.viewportWidth - scaledW) / 2f
        val top = (g.viewportHeight - scaledH) / 2f

        // Zoom about the fit-center rectangle's own centre, then translate.
        val cx = left + scaledW / 2f
        val cy = top + scaledH / 2f
        val halfW = scaledW / 2f * g.zoom
        val halfH = scaledH / 2f * g.zoom

        val rect = DestRect(
            left = cx - halfW + g.panX,
            top = cy - halfH + g.panY,
            right = cx + halfW + g.panX,
            bottom = cy + halfH + g.panY
        )
        return if (rect.isUsable()) rect else null
    }

    /**
     * Turn a fingertip into a host desktop pixel, with the cursor lifted
     * [offsetPx] view-pixels above it.
     *
     * The offset is applied **in view space, before the inverse scale**, and
     * that ordering is the feature. Applying it afterwards, in desktop pixels,
     * would make the gap between finger and cursor grow and shrink with zoom —
     * the cursor would drift away from the fingertip as the user zoomed in,
     * which is precisely the opposite of a control the user set to a comfortable
     * distance.
     *
     * Returns `null` when the geometry cannot be trusted. Otherwise the result
     * is always inside the frame: a touch in the letterbox, or lifted off the
     * top of the desktop by a large offset, **clamps to the nearest edge**. That
     * is deliberate. The alternative — refusing to move — makes the top row of
     * the desktop unreachable at exactly the offsets the feature exists to
     * provide, and a title bar is at the top of the screen.
     */
    fun mapTouchToDesktop(
        g: RenderGeometry,
        touchX: Float,
        touchY: Float,
        offsetPx: Float
    ): DesktopPoint? {
        val (u, v) = touchFractions(g, touchX, touchY, offsetPx) ?: return null
        return DesktopPoint(
            x = (u * g.frameWidth).roundToInt().coerceIn(0, g.frameWidth - 1),
            y = (v * g.frameHeight).roundToInt().coerceIn(0, g.frameHeight - 1)
        )
    }

    /** Resolution-independent coordinates, sent only after the host acknowledges normalized_v1. */
    fun mapTouchToNormalized(
        g: RenderGeometry,
        touchX: Float,
        touchY: Float,
        offsetPx: Float
    ): DesktopPoint? {
        val (u, v) = touchFractions(g, touchX, touchY, offsetPx) ?: return null
        return DesktopPoint(
            x = (u * 65535).roundToInt(),
            y = (v * 65535).roundToInt()
        )
    }

    private fun touchFractions(
        g: RenderGeometry,
        touchX: Float,
        touchY: Float,
        offsetPx: Float
    ): Pair<Float, Float>? {
        if (!touchX.isFinite() || !touchY.isFinite()) return null
        if (!offsetPx.isFinite() || offsetPx < 0f) return null
        val rect = destinationRect(g) ?: return null

        val targetY = touchY - offsetPx
        val u = (touchX - rect.left) / rect.width
        val v = (targetY - rect.top) / rect.height
        if (!u.isFinite() || !v.isFinite()) return null
        return u.coerceIn(0f, 1f) to v.coerceIn(0f, 1f)
    }

    /**
     * Convert a slider position in density-independent pixels to view pixels.
     *
     * The slider is specified in `dp` so the cursor sits the same *physical*
     * distance above the fingertip on every device. A value in raw pixels would
     * mean something different on a 480dpi phone than on a 160dpi tablet, and
     * the user would have to re-tune it per device.
     */
    fun dpToPx(dp: Int, density: Float): Float {
        if (dp <= 0 || !density.isFinite() || density <= 0f) return 0f
        return dp * density
    }
}
