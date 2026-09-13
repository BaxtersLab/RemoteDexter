package com.remotedexter

/**
 * How a finger drives the remote cursor.
 *
 * # Why both exist
 *
 * `MouseMove` carries `Absolute` and `Relative` on the wire, and the client has
 * a working, tested implementation of each. Neither is right for every job:
 *
 * **Touch** puts the cursor where the finger is. It is direct and obvious, and
 * it is what makes tapping a button feel like tapping a button. Its weakness is
 * precision — one finger-width covers roughly 40 desktop pixels on a 6" screen
 * showing a 1920px desktop, which is wider than most click targets, and the
 * finger hides the thing being aimed at.
 *
 * **Trackpad** moves the cursor by the distance the finger travelled, exactly
 * like a laptop touchpad. The cursor stays visible because it is not under the
 * finger, and a small careful movement can land on a target a fingertip could
 * never hit. Its weakness is indirectness: crossing the screen takes several
 * strokes.
 *
 * So this is a mode the user picks per task, not a default to be argued about:
 * dragging a window wants Touch, hitting a close button wants Trackpad.
 */
enum class PointerMode {
    /** The cursor goes where the finger is. */
    Touch,

    /** The cursor moves by how far the finger moved. */
    Trackpad;

    fun next(): PointerMode = if (this == Touch) Trackpad else Touch
}

/** What one finger movement should send. */
sealed class PointerMove {
    /** Put the cursor at this VIEW point; the caller maps it to the desktop. */
    data class Absolute(val viewX: Float, val viewY: Float) : PointerMove()

    /** Move the cursor by this much, in view pixels. */
    data class Relative(val dx: Float, val dy: Float) : PointerMove()
}

/**
 * Turns a stream of touch points into moves, according to the mode.
 *
 * Stateful only in the one way trackpad mode requires: it remembers the
 * previous point so it can produce a delta. That state is the reason this is a
 * class with tests rather than a function — see
 * [PointerModeRouter.onMove]'s first-touch rule, which is the bug this exists
 * to prevent.
 */
class PointerModeRouter {

    private var lastX: Float? = null
    private var lastY: Float? = null

    /**
     * The move for one touch sample, or null if there is nothing to send.
     *
     * **The first touch of a gesture produces no relative move.** Without that
     * rule the delta would be measured from wherever the previous gesture
     * ended, so lifting a finger and putting it down somewhere else would hurl
     * the cursor across the desktop by exactly that distance — the classic
     * trackpad bug, and one that only shows up after the second gesture, which
     * is why it survives casual testing.
     *
     * Touch mode is stateless and always yields a point.
     */
    fun onMove(mode: PointerMode, viewX: Float, viewY: Float): PointerMove? {
        if (mode == PointerMode.Touch) {
            // Still recorded, so that switching to Trackpad mid-gesture does
            // not treat the next sample as a first touch and lose it.
            lastX = viewX
            lastY = viewY
            return PointerMove.Absolute(viewX, viewY)
        }
        val px = lastX
        val py = lastY
        lastX = viewX
        lastY = viewY
        if (px == null || py == null) return null
        val dx = viewX - px
        val dy = viewY - py
        // A sample that did not move is not worth a message. The host would
        // apply a zero delta and nothing would happen, at the cost of a wire
        // round trip on a link this project already had to fight for.
        if (dx == 0f && dy == 0f) return null
        return PointerMove.Relative(dx, dy)
    }

    /**
     * The gesture ended; forget the reference point.
     *
     * Called on finger-up. Skipping it is what re-creates the jump the
     * first-touch rule prevents.
     */
    fun onGestureEnd() {
        lastX = null
        lastY = null
    }
}
