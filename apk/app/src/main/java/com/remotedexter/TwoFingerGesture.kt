package com.remotedexter

import kotlin.math.abs

/**
 * One two-finger gesture, from the first sample to the lift.
 *
 * ## What this used to decide, and why it no longer does
 *
 * Two fingers used to mean *either* moving the view *or* scrolling the host,
 * chosen from the current zoom: at fit there is nothing to pan to, so the
 * gesture was given to the wheel. The rule was tidy and it was wrong in use.
 *
 * `applyZoom` clamps at `MIN_ZOOM` from **below**, so the first scale factor
 * above 1.0 lifted the view off fit and nothing brought it back — and since the
 * zoom is never reset, every later gesture panned too. Worse, the operator had
 * every reason to be zoomed in: the landscape layout gave the desktop a quarter
 * of the screen, so the picture was unreadable at fit. Scrolling was therefore
 * unreachable almost all the time, with nothing on screen to say why. Their
 * report: *"it's not scrolling in the web browser either. it's overall not just
 * the VS Code app."*
 *
 * **The operator's decision, 2026-08-30:** two fingers move the view, in all
 * directions, always. Scrolling the host moves to explicit buttons —
 * *"a scroll up arrow and a scroll down arrow button but it scrolls the field
 * that the cursor is over, that's the same way the scroller on the mouse works.
 * cursor over scroll target then scroll up or down gives the desired result."*
 *
 * So no gesture changes meaning any more, and this class keeps only the part
 * that was always right: a deadzone, so the finger-span jitter of an ordinary
 * two-finger drag cannot zoom the view by accident.
 */
class TwoFingerGesture(private val pinchThreshold: Float = PINCH_THRESHOLD) {

    companion object {
        /**
         * How far the finger span must change before it counts as a pinch.
         *
         * 12%: comfortably above the one-to-two percent an ordinary drag
         * produces, and far below what anyone pinching deliberately does in the
         * first fraction of a second.
         */
        const val PINCH_THRESHOLD = 0.12f
    }

    private var pinchAccum = 1f
    private var pinching = false

    /**
     * Offer one sample's scale factor.
     *
     * @return the factor to multiply the view zoom by, or null while the
     *   gesture is still inside the deadzone and the view must not move.
     *
     * Once the deadzone is crossed the whole accumulated factor is returned at
     * once — not discarded — so a deliberate pinch does not visibly lag behind
     * the fingers, and everything after it passes straight through.
     */
    fun onSample(scaleFactor: Float): Float? {
        if (pinching) return scaleFactor
        pinchAccum *= scaleFactor
        if (abs(pinchAccum - 1f) < pinchThreshold) return null
        pinching = true
        val pending = pinchAccum
        pinchAccum = 1f
        return pending
    }

    /** True once this gesture has been recognised as a deliberate pinch. */
    fun isPinching(): Boolean = pinching

    /** The fingers left. The next gesture starts its own deadzone. */
    fun onGestureEnd() {
        pinchAccum = 1f
        pinching = false
    }
}

/**
 * How a held scroll button repeats.
 *
 * A wheel notch per tap is right for a nudge and useless for a long document,
 * so the buttons repeat while held — the same bargain a keyboard makes with
 * key repeat, and the same two numbers.
 *
 * Pure, so the pacing is arguable in a millisecond on the JVM rather than by
 * holding a button on a phone and counting.
 */
object ScrollRepeat {

    /**
     * How long the button must be held before it starts repeating.
     *
     * Long enough that an ordinary tap sends exactly one notch and nothing
     * else — a button that fires twice when tapped once is worse than one that
     * does not repeat at all.
     */
    const val INITIAL_DELAY_MS = 400L

    /** The gap between repeats once they start. Roughly a brisk wheel spin. */
    const val REPEAT_INTERVAL_MS = 90L

    /**
     * The delay before the notch after [notchesSent] have already gone.
     *
     * @param notchesSent how many notches this press has sent so far; the first
     *   press sends one immediately, so this is 1 when the first repeat is
     *   being scheduled.
     */
    fun delayAfter(notchesSent: Int): Long =
        if (notchesSent <= 1) INITIAL_DELAY_MS else REPEAT_INTERVAL_MS
}
