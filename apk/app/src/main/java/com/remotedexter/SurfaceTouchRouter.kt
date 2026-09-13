package com.remotedexter

import android.content.Context
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import kotlin.math.abs

/**
 * What the video surface's touch stream means, expressed as intent rather than
 * as events. [SurfaceTouchRouter] turns raw `MotionEvent`s into these calls;
 * `MainActivity` forwards them to [InputController] and the render pipeline.
 *
 * The interface exists so the routing can be driven by real `MotionEvent`s in an
 * instrumentation test and *observed*, without a session, a host, or the JNI
 * bridge being involved. It is a seam in the product, not a stub: the shipped
 * implementation is `MainActivity`'s own, and there is exactly one.
 */
interface SurfaceGestures {
    /**
     * Where the one finger currently is, in view pixels, with the event's own
     * timestamp.
     *
     * A **position**, not a delta. The cursor-offset feature exists to put the
     * host pointer somewhere other than under the fingertip, and a stream of
     * deltas cannot express that: a constant offset subtracted from successive
     * positions cancels itself out exactly
     * (`(p2 - o) - (p1 - o) == p2 - p1`), so the slider would visibly move and
     * change nothing. `CursorOffsetNoOpControlTest` is that argument executed.
     */
    fun onTouchAt(viewX: Float, viewY: Float, eventTimeMs: Long)

    /** Confirmed single tap at a view position — a left click there. */
    fun onTap(viewX: Float, viewY: Float)

    /** Long press at a view position — latch the left button for a click-and-drag. */
    fun onLongPress(viewX: Float, viewY: Float)

    /** Finger left the surface, or the gesture was cancelled. Always fires. */
    fun onGestureEnd(eventTimeMs: Long)

    /** Double tap — client-side view reset, no host traffic. */
    fun onResetZoomPan()

    /** Two-finger pinch/pan — client-side view navigation, no host traffic. */
    fun onZoomPan(scaleFactor: Float, focusX: Float, focusY: Float, panDx: Float, panDy: Float)

    /**
     * Two fingers touched and lifted without travelling — a right click at the
     * point between them.
     *
     * The operator asked for this directly: *"also a 2 finger tap should be a
     * right click"*. It is the one gesture on a touch screen that has an
     * unambiguous desktop meaning and no other claimant here.
     */
    fun onTwoFingerTap(viewX: Float, viewY: Float)

    /**
     * A two-finger gesture ended.
     *
     * Needed so the scroll accumulator forgets its part-notch. Travel left over
     * from one swipe added to the start of the next eventually produces a notch
     * nobody asked for — invisible until the second gesture, like every other
     * bug of this shape.
     */
    fun onTwoFingerGestureEnd()
}

/**
 * Routes the desktop surface's touch stream.
 *
 * Split by finger count: one finger drives the remote cursor, two navigate the
 * view. `scaleGestureDetector` sees every event so it can notice a second finger
 * arriving; `gestureDetector` is held back once a second pointer is down, so a
 * two-finger gesture cannot also be read as a stray one-finger drag or tap on
 * whichever pointer happens to be primary.
 */
class SurfaceTouchRouter(context: Context, private val out: SurfaceGestures) {

    private var lastScaleFocusX = 0f
    private var lastScaleFocusY = 0f
    private var longPressActive = false

    /** Where the two fingers were centred when the second landed. */
    private var twoFingerStartX = 0f
    private var twoFingerStartY = 0f
    private var twoFingerStartMs = 0L

    /**
     * True once the pair has moved further than [touchSlop] from where it
     * started. A tap that drifts is a drag, and must not also right-click.
     */
    private var twoFingerTravelled = false

    private val touchSlop = android.view.ViewConfiguration.get(context).scaledTouchSlop

    /**
     * True once a second finger has touched down at any point in the current
     * gesture, and until every finger lifts.
     *
     * Without it, lifting one finger from a pinch drops the pointer count back
     * to one and the remaining finger resumes driving the cursor — which, with
     * absolute positioning, teleports the host pointer to wherever that finger
     * happens to be. A gesture that began as navigation stays navigation.
     */
    private var multiTouchSeen = false

    private val gestureDetector = GestureDetector(
        context,
        object : GestureDetector.SimpleOnGestureListener() {
            override fun onDown(e: MotionEvent) = true // must return true or no further events arrive

            // onSingleTapConfirmed, not onSingleTapUp: the latter fires
            // immediately on every tap-up, including the first half of a
            // double-tap, which would send a spurious click to the host on
            // every double-tap-to-reset-zoom.
            override fun onSingleTapConfirmed(e: MotionEvent): Boolean {
                out.onTap(e.x, e.y)
                return true
            }

            override fun onDoubleTap(e: MotionEvent): Boolean {
                out.onResetZoomPan()
                return true
            }

            // Latches the host's left button so the drag that follows is a real
            // click-and-drag. GestureDetector suppresses onSingleTapConfirmed
            // once this fires, so a latched press never also emits a click.
            override fun onLongPress(e: MotionEvent) {
                longPressActive = true
                out.onLongPress(e.x, e.y)
            }
        }
    )

    private val scaleGestureDetector = ScaleGestureDetector(
        context,
        object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
            override fun onScaleBegin(detector: ScaleGestureDetector): Boolean {
                lastScaleFocusX = detector.focusX
                lastScaleFocusY = detector.focusY
                return true
            }

            override fun onScale(detector: ScaleGestureDetector): Boolean {
                // onScale fires for ANY two-finger movement, not only pinching,
                // so tracking the focus point's own movement between calls is
                // what yields the pan delta.
                out.onZoomPan(
                    detector.scaleFactor,
                    detector.focusX,
                    detector.focusY,
                    detector.focusX - lastScaleFocusX,
                    detector.focusY - lastScaleFocusY
                )
                lastScaleFocusX = detector.focusX
                lastScaleFocusY = detector.focusY
                return true
            }
        }
    )

    /**
     * A second finger has joined. Two things have to happen before the gesture
     * is allowed to carry on as navigation.
     *
     * **The armed long-press has to be disarmed.** `GestureDetector` cancels
     * its own long-press timer the moment it sees `ACTION_POINTER_DOWN` — but
     * it never sees one, because from that event onwards the detector is held
     * back so a two-finger gesture cannot also be read as a one-finger drag.
     * The timer stays armed and fires part-way through the gesture, pressing
     * the host's left button at wherever the FIRST finger landed. A pinch is
     * over too quickly to reach it; a two-finger **scroll** is held far longer
     * than the long-press timeout, so it hits every time. Feeding the detector
     * a synthetic cancel disarms it through its own path rather than
     * reimplementing the bookkeeping.
     *
     * **A long-press that already fired has to be released.** If the second
     * finger arrives after the latch, the host is holding its left button and
     * nothing in the remainder of a two-finger gesture releases it: the button
     * stays down for the whole swipe, and if the session drops or the app is
     * backgrounded before the fingers lift, it stays down on the host with no
     * client left to send the Up.
     */
    private fun onSecondFingerArrived(event: MotionEvent) {
        val (fx, fy) = focus(event)
        twoFingerStartX = fx
        twoFingerStartY = fy
        twoFingerStartMs = event.eventTime
        twoFingerTravelled = false
        val cancel = MotionEvent.obtain(event)
        cancel.action = MotionEvent.ACTION_CANCEL
        gestureDetector.onTouchEvent(cancel)
        cancel.recycle()
        if (longPressActive) {
            longPressActive = false
            out.onGestureEnd(event.eventTime)
        }
    }

    /** The midpoint of every finger currently down, in view pixels. */
    private fun focus(event: MotionEvent): Pair<Float, Float> {
        var sx = 0f
        var sy = 0f
        for (i in 0 until event.pointerCount) {
            sx += event.getX(i)
            sy += event.getY(i)
        }
        return Pair(sx / event.pointerCount, sy / event.pointerCount)
    }

    companion object {
        /**
         * How long two fingers may rest before their lift stops being a tap.
         *
         * The framework's own tap timeout is 100ms, which is tuned for one
         * finger arriving and leaving; two fingers rarely land together and
         * rarely leave together, so it rejects taps people meant. The long-press
         * timeout of 500ms is at the other extreme and would swallow the start
         * of a slow drag. 300ms is the double-tap window, which is the
         * framework's own answer to "two touches the user intended as one act".
         */
        const val TWO_FINGER_TAP_TIMEOUT_MS = 300L
    }

    /** Feed one raw touch event. Always returns true — the surface consumes all. */
    fun onTouch(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_DOWN) {
            longPressActive = false
            multiTouchSeen = false
        }
        if (event.pointerCount > 1 && !multiTouchSeen) {
            multiTouchSeen = true
            onSecondFingerArrived(event)
        }
        scaleGestureDetector.onTouchEvent(event)
        if (multiTouchSeen && event.actionMasked == MotionEvent.ACTION_MOVE) {
            val (fx, fy) = focus(event)
            if (abs(fx - twoFingerStartX) > touchSlop || abs(fy - twoFingerStartY) > touchSlop) {
                twoFingerTravelled = true
            }
        }
        // A two-finger tap: both fingers down and up again, quickly, without
        // travelling. Reported at the point between them, which is where the
        // operator was pointing — not at whichever finger happened to lift last.
        if (multiTouchSeen &&
            event.actionMasked == MotionEvent.ACTION_UP &&
            !twoFingerTravelled &&
            event.eventTime - twoFingerStartMs <= TWO_FINGER_TAP_TIMEOUT_MS
        ) {
            out.onTwoFingerTap(twoFingerStartX, twoFingerStartY)
        }
        // The end of a multi-touch gesture, whichever way it ends.
        if (multiTouchSeen &&
            (event.actionMasked == MotionEvent.ACTION_UP ||
                event.actionMasked == MotionEvent.ACTION_CANCEL)
        ) {
            out.onTwoFingerGestureEnd()
        }
        val oneFinger = event.pointerCount == 1 && !multiTouchSeen
        if (oneFinger) {
            gestureDetector.onTouchEvent(event)
        }
        // The absolute position stream. Emitted on the finger landing and on
        // every move, so the host pointer tracks the finger continuously rather
        // than only while a drag is latched.
        if (oneFinger &&
            (event.actionMasked == MotionEvent.ACTION_DOWN ||
                event.actionMasked == MotionEvent.ACTION_MOVE)
        ) {
            out.onTouchAt(event.x, event.y, event.eventTime)
        }
        // GestureDetector has no "the drag ended" callback, so the end of every
        // gesture is taken from the raw stream. ACTION_CANCEL matters as much as
        // ACTION_UP: a cancel (the surface losing the gesture to a parent, a call
        // arriving) would otherwise leave a latched drag holding the host's left
        // button down indefinitely.
        when (event.actionMasked) {
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                longPressActive = false
                multiTouchSeen = false
                out.onGestureEnd(event.eventTime)
            }
        }
        return true
    }
}
