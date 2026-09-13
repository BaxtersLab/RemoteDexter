package com.remotedexter.mobile.render

/**
 * Fit versus original, the two scalings Block 11 asks for.
 *
 * **Fit** is the whole desktop, letterboxed to the phone. Nothing is hidden and
 * nothing needs panning, which is what you want to see where something is.
 *
 * **Original** is one host pixel per device pixel. Text becomes readable
 * instead of a grey smear, at the cost of seeing a window into the desktop
 * rather than the desktop — which is what you want to read or click something.
 *
 * # Why this is a computation, not a constant
 *
 * "Original" is not a fixed zoom. The pipeline's zoom is a multiplier on top of
 * the fit scale, and the fit scale depends on both the viewport and the frame:
 * a 1920px desktop letterboxed into a 1080px-wide view is already scaled to
 * 0.5625, so 1:1 needs 1.78x — while a 3840px desktop in the same view needs
 * 3.56x. Hard-coding a number would be right for exactly one pair of sizes and
 * silently wrong for every other, including after the host changes resolution.
 */
enum class ScalingMode {
    /** The whole desktop, letterboxed. */
    Fit,

    /** One host pixel per device pixel. */
    Original;

    fun next(): ScalingMode = if (this == Fit) Original else Fit
}

object Scaling {

    /**
     * The zoom multiplier that makes one host pixel one device pixel.
     *
     * Returns null when the geometry cannot support the question — a viewport
     * or frame with no area. Failing closed rather than returning 1f, because
     * 1f is a legitimate answer (a desktop already displayed 1:1) and a caller
     * could not tell it apart from "I don't know".
     *
     * The result is CLAMPED to the pipeline's ceiling. A desktop far larger
     * than the phone cannot reach true 1:1 within that ceiling, and the honest
     * behaviour is to zoom as far as the renderer allows rather than to ask for
     * a scale it will silently refuse — which would leave the button looking
     * broken.
     */
    fun originalZoom(
        viewportWidth: Int,
        viewportHeight: Int,
        frameWidth: Int,
        frameHeight: Int,
        maxZoom: Float
    ): Float? {
        if (viewportWidth <= 0 || viewportHeight <= 0) return null
        if (frameWidth <= 0 || frameHeight <= 0) return null
        // The fit scale is the smaller ratio: whichever axis runs out first is
        // the one that decides the letterbox.
        val fit = minOf(
            viewportWidth.toFloat() / frameWidth.toFloat(),
            viewportHeight.toFloat() / frameHeight.toFloat()
        )
        if (fit <= 0f || !fit.isFinite()) return null
        // Zoom is a multiplier on top of the fit scale, so 1:1 is its inverse.
        val oneToOne = 1f / fit
        if (!oneToOne.isFinite()) return null
        // A desktop SMALLER than the viewport is already displayed at or above
        // 1:1 when fitted, so "original" cannot mean zooming out — the
        // pipeline's floor is fit, and asking for less would be refused.
        return oneToOne.coerceIn(1f, maxZoom)
    }

    /**
     * The multiplier to pass to a zoom call that multiplies rather than sets.
     *
     * `applyZoom` takes a factor, not a target, so a caller that wants to LAND
     * on a zoom has to divide. Doing that here keeps the arithmetic in one
     * tested place instead of in an Activity.
     */
    fun factorToReach(target: Float, current: Float): Float? {
        if (current <= 0f || !current.isFinite()) return null
        if (target <= 0f || !target.isFinite()) return null
        return target / current
    }
}
