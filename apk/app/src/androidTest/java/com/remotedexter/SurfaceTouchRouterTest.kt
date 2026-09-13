package com.remotedexter

import android.os.SystemClock
import android.view.MotionEvent
import android.view.ViewConfiguration
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device proof of the touch plumbing.
 *
 * Everything asserted here is **Android's** behaviour, not ours, which is
 * exactly why it cannot be a JVM test: whether `GestureDetector` fires
 * `onLongPress` on its own schedule, and whether `ACTION_CANCEL` is delivered
 * to a touch listener at all, are properties of the framework. The arithmetic
 * that sits behind these callbacks is already covered on the JVM by
 * `PointerMotionTest` and `DragLatchTest`.
 *
 * `ACTION_CANCEL` is the case that matters most. A cancel that does not reach
 * `onGestureEnd` leaves a latched drag holding the host's left mouse button
 * down, drag-selecting everything the cursor crosses, with no further touch
 * event coming to release it.
 */
@RunWith(AndroidJUnit4::class)
class SurfaceTouchRouterTest {

    /** Records intent. A test observer, not a stand-in for any shipped code. */
    private class Recorder : SurfaceGestures {
        val calls = mutableListOf<String>()
        /** Every reported one-finger position, in order. */
        val positions = mutableListOf<Pair<Float, Float>>()
        var tapAt: Pair<Float, Float>? = null
        var longPressAt: Pair<Float, Float>? = null
        override fun onTouchAt(viewX: Float, viewY: Float, eventTimeMs: Long) {
            positions += Pair(viewX, viewY)
            calls += "touchAt"
        }
        override fun onTap(viewX: Float, viewY: Float) {
            tapAt = Pair(viewX, viewY)
            calls += "tap"
        }
        override fun onLongPress(viewX: Float, viewY: Float) {
            longPressAt = Pair(viewX, viewY)
            calls += "longPress"
        }
        override fun onGestureEnd(eventTimeMs: Long) { calls += "gestureEnd" }
        override fun onResetZoomPan() { calls += "resetZoomPan" }
        override fun onZoomPan(
            scaleFactor: Float, focusX: Float, focusY: Float, panDx: Float, panDy: Float
        ) { calls += "zoomPan" }
        override fun onTwoFingerGestureEnd() { calls += "twoFingerEnd" }
        var twoFingerTapAt: Pair<Float, Float>? = null
        override fun onTwoFingerTap(viewX: Float, viewY: Float) {
            twoFingerTapAt = Pair(viewX, viewY)
            calls += "twoFingerTap"
        }
    }

    /**
     * The end of a two-finger gesture has to be reported, or the scroll
     * accumulator keeps its part-notch.
     *
     * Travel left over from one swipe added to the start of the next eventually
     * scrolls a document nobody touched — the same shape as the latched-drag
     * bug this suite already exists for, and just as invisible until the second
     * gesture.
     *
     * ACTION_CANCEL matters as much as ACTION_UP: the system takes a gesture
     * away without a clean finish, and that is exactly when leftover state
     * survives.
     */
    @Test
    fun aTwoFingerGestureReportsItsEndOnUpAndOnCancel() {
        for (finish in listOf(MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL)) {
            // The router is built on the main looper by setUp and reused; only
            // the record needs clearing. `multiTouchSeen` resets on ACTION_DOWN,
            // so the second pass really is a fresh gesture.
            rec.calls.clear()
            val t = SystemClock.uptimeMillis()
            val pointerDown =
                MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
            send(MotionEvent.ACTION_DOWN, 100f, 100f, t, t)
            sendTwoFinger(pointerDown, 100f, 100f, 400f, 400f, t, t + 10)
            sendTwoFinger(MotionEvent.ACTION_MOVE, 100f, 200f, 400f, 500f, t, t + 20)
            send(finish, 100f, 200f, t, t + 30)
            assertTrue(
                "a two-finger gesture ending in action $finish never reported its end. " +
                    "Saw: ${rec.calls}",
                rec.calls.contains("twoFingerEnd")
            )
        }
    }

    private lateinit var rec: Recorder
    private lateinit var router: SurfaceTouchRouter

    @Before
    fun setUp() {
        rec = Recorder()
        // GestureDetector posts its long-press timeout to a Handler bound to the
        // thread that constructs it, so it must be built on the main looper.
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            router = SurfaceTouchRouter(
                InstrumentationRegistry.getInstrumentation().targetContext,
                rec
            )
        }
    }

    private fun send(action: Int, x: Float, y: Float, downTime: Long, eventTime: Long) {
        val e = MotionEvent.obtain(downTime, eventTime, action, x, y, 0)
        InstrumentationRegistry.getInstrumentation().runOnMainSync { router.onTouch(e) }
        e.recycle()
    }

    /**
     * A genuine TWO-POINTER event.
     *
     * `MotionEvent.obtain(downTime, eventTime, action, x, y, meta)` always
     * builds a single-pointer event, whatever action constant is passed — so
     * sending `ACTION_POINTER_DOWN` through [send] produces an event whose
     * `pointerCount` is still 1, and any test of two-finger behaviour written
     * that way passes without exercising anything. The pointer arrays are the
     * only way to make the count real.
     */
    private fun sendTwoFinger(
        action: Int,
        x0: Float, y0: Float,
        x1: Float, y1: Float,
        downTime: Long, eventTime: Long
    ) {
        val props = arrayOf(
            MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER },
            MotionEvent.PointerProperties().apply { id = 1; toolType = MotionEvent.TOOL_TYPE_FINGER }
        )
        val coords = arrayOf(
            MotionEvent.PointerCoords().apply { x = x0; y = y0; pressure = 1f; size = 1f },
            MotionEvent.PointerCoords().apply { x = x1; y = y1; pressure = 1f; size = 1f }
        )
        val e = MotionEvent.obtain(
            downTime, eventTime, action, 2, props, coords,
            0, 0, 1f, 1f, 0, 0, 0, 0
        )
        InstrumentationRegistry.getInstrumentation().runOnMainSync { router.onTouch(e) }
        e.recycle()
    }

    /** THE case. A cancel must end the gesture exactly as an up does. */
    @Test
    fun actionCancelEndsTheGesture() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 100f, 100f, t, t)
        send(MotionEvent.ACTION_MOVE, 140f, 100f, t, t + 20)
        send(MotionEvent.ACTION_CANCEL, 140f, 100f, t, t + 30)
        assertTrue(
            "ACTION_CANCEL did not reach onGestureEnd — a latched drag would " +
                "hold the host's left button down with nothing left to release it. " +
                "Saw: ${rec.calls}",
            rec.calls.contains("gestureEnd")
        )
    }

    @Test
    fun actionCancelAfterLongPressEndsTheLatchedGestureExactlyOnce() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 100f, 100f, t, t)
        Thread.sleep(ViewConfiguration.getLongPressTimeout().toLong() + 350L)
        assertTrue("the drag never latched. Saw: ${rec.calls}", rec.calls.contains("longPress"))

        send(MotionEvent.ACTION_CANCEL, 100f, 100f, t, SystemClock.uptimeMillis())
        assertEquals(1, rec.calls.count { it == "gestureEnd" })
        assertTrue(
            "cancel ended the gesture before its latch. Saw: ${rec.calls}",
            rec.calls.indexOf("gestureEnd") > rec.calls.indexOf("longPress")
        )
    }

    @Test
    fun actionUpEndsTheGesture() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 100f, 100f, t, t)
        send(MotionEvent.ACTION_MOVE, 160f, 100f, t, t + 20)
        send(MotionEvent.ACTION_UP, 160f, 100f, t, t + 30)
        assertTrue("ACTION_UP did not reach onGestureEnd. Saw: ${rec.calls}",
            rec.calls.contains("gestureEnd"))
    }

    /** Exactly one gesture end per gesture — a doubled Up is a real button release. */
    @Test
    fun aGestureEndsExactlyOnce() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 10f, 10f, t, t)
        send(MotionEvent.ACTION_MOVE, 60f, 10f, t, t + 20)
        send(MotionEvent.ACTION_UP, 60f, 10f, t, t + 30)
        assertEquals(
            "gestureEnd fired ${rec.calls.count { it == "gestureEnd" }} times for one gesture",
            1, rec.calls.count { it == "gestureEnd" }
        )
    }

    /** A held finger must latch the drag before the finger is lifted. */
    @Test
    fun holdingStillFiresLongPressBeforeTheGestureEnds() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 200f, 200f, t, t)
        // GestureDetector's own timeout, plus margin — never a magic number.
        Thread.sleep(ViewConfiguration.getLongPressTimeout().toLong() + 350L)
        assertTrue(
            "onLongPress never fired after ${ViewConfiguration.getLongPressTimeout()}ms " +
                "of a still finger — click-and-drag can never latch. Saw: ${rec.calls}",
            rec.calls.contains("longPress")
        )
        val endedBeforeLongPress = rec.calls.indexOf("gestureEnd")
            .let { it >= 0 && it < rec.calls.indexOf("longPress") }
        assertFalse("the gesture ended before the long press latched", endedBeforeLongPress)
        send(MotionEvent.ACTION_UP, 200f, 200f, t, SystemClock.uptimeMillis())
        assertTrue("the latching gesture never ended", rec.calls.contains("gestureEnd"))
    }

    @Test
    fun movementAfterLongPressStillReportsPositions() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 200f, 200f, t, t)
        Thread.sleep(ViewConfiguration.getLongPressTimeout().toLong() + 350L)
        assertTrue("the drag never latched. Saw: ${rec.calls}", rec.calls.contains("longPress"))

        val before = rec.positions.size
        send(MotionEvent.ACTION_MOVE, 320f, 260f, t, SystemClock.uptimeMillis())
        assertTrue(
            "movement after long-press reported no position. Saw: ${rec.calls}",
            rec.positions.size > before
        )
        assertEquals(
            "the latched drag must report where the finger actually is",
            Pair(320f, 260f),
            rec.positions.last()
        )
        send(MotionEvent.ACTION_UP, 320f, 260f, t, SystemClock.uptimeMillis())
    }

    /** A moving finger must actually produce cursor movement. */
    @Test
    fun aDragReportsThePositionsTheFingerActuallyVisited() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 100f, 300f, t, t)
        var x = 100f
        repeat(8) { i ->
            x += 25f
            send(MotionEvent.ACTION_MOVE, x, 300f, t, t + 10L * (i + 1))
        }
        send(MotionEvent.ACTION_UP, x, 300f, t, t + 100)
        assertTrue("a rightward drag reported no position at all. Saw: ${rec.calls}",
            rec.positions.isNotEmpty())
        // Absolute positions, so the assertion is about WHERE the finger was,
        // not how far it moved. A sign-convention error would now show up as
        // the reported positions running backwards.
        val xs = rec.positions.map { it.first }
        assertEquals("the first reported position is where the finger landed", 100f, xs.first(), 0.5f)
        assertEquals("the last reported position is where the finger ended", x, xs.last(), 0.5f)
        assertTrue(
            "a rightward drag reported positions running leftward: $xs",
            xs.last() > xs.first()
        )
        assertTrue(
            "positions must be monotonically rightward for a rightward drag: $xs",
            xs.zipWithNext().all { (a, b) -> b >= a }
        )
    }

    /**
     * Once a second finger has joined, the gesture is view navigation for the
     * rest of its life. Without this, lifting one finger from a pinch drops the
     * pointer count back to one and the remaining finger resumes driving the
     * cursor — which, with absolute positioning, teleports the host pointer to
     * wherever that finger happens to be sitting.
     */
    @Test
    fun aSecondFingerSuppressesCursorMovementForTheRestOfTheGesture() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 100f, 100f, t, t)
        val afterFirstFinger = rec.positions.size
        // Real two-pointer events: pointerCount is genuinely 2 here.
        val pointerDown = MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        val pointerUp = MotionEvent.ACTION_POINTER_UP or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        sendTwoFinger(pointerDown, 100f, 100f, 400f, 400f, t, t + 10)
        sendTwoFinger(MotionEvent.ACTION_MOVE, 110f, 110f, 420f, 420f, t, t + 20)
        sendTwoFinger(pointerUp, 110f, 110f, 420f, 420f, t, t + 30)
        // One finger again — but this gesture is already navigation.
        send(MotionEvent.ACTION_MOVE, 800f, 800f, t, t + 40)
        assertEquals(
            "a one-finger position was reported after a two-finger gesture. Saw: ${rec.positions}",
            afterFirstFinger,
            rec.positions.size
        )
        send(MotionEvent.ACTION_UP, 800f, 800f, t, t + 50)
        assertTrue("the gesture still has to end", rec.calls.contains("gestureEnd"))
    }

    /** A tap reports where it happened, not merely that it happened. */
    @Test
    fun aTapReportsItsOwnPosition() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 640f, 480f, t, t)
        send(MotionEvent.ACTION_UP, 640f, 480f, t, t + 40)
        Thread.sleep(ViewConfiguration.getDoubleTapTimeout().toLong() + 250L)
        assertEquals("the tap must carry the position it happened at", Pair(640f, 480f), rec.tapAt)
    }

    /**
     * A two-finger gesture must never press the host's left button.
     *
     * `GestureDetector` arms a long-press timer on `ACTION_DOWN` and cancels it
     * when it sees `ACTION_POINTER_DOWN`. The router deliberately stops feeding
     * the detector once a second finger is down, so that cancel never arrives
     * and the timer stays armed — it then fires part-way through the gesture
     * and latches the host's left button at wherever the first finger landed.
     *
     * A pinch ends before the timeout and never showed this. A two-finger
     * **scroll** is held for far longer than the timeout, so introducing that
     * gesture made a latent bug reachable on essentially every swipe: the
     * operator's report was that the desktop's mouse layer froze and clicks
     * stopped landing while hovering still highlighted, which is what a held
     * left button looks like from the other end.
     */
    @Test
    fun aTwoFingerGestureNeverLatchesAStrayLongPress() {
        val t = SystemClock.uptimeMillis()
        val pointerDown =
            MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        val pointerUp =
            MotionEvent.ACTION_POINTER_UP or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        send(MotionEvent.ACTION_DOWN, 100f, 100f, t, t)
        sendTwoFinger(pointerDown, 100f, 100f, 100f, 400f, t, t + 10)
        // Held well past the long-press timeout, which is what a scroll swipe
        // does. Moving, because a real swipe moves; a still gesture would be
        // the easier case and would not prove the timer was disarmed.
        val hold = ViewConfiguration.getLongPressTimeout().toLong() + 350L
        val step = 30L
        var elapsed = 0L
        var offset = 0f
        while (elapsed < hold) {
            offset += 4f
            sendTwoFinger(
                MotionEvent.ACTION_MOVE,
                100f, 100f + offset, 100f, 400f + offset, t, t + 10 + elapsed
            )
            Thread.sleep(step)
            elapsed += step
        }
        sendTwoFinger(pointerUp, 100f, 100f + offset, 100f, 400f + offset, t, t + 10 + elapsed)
        send(MotionEvent.ACTION_UP, 100f, 100f + offset, t, t + 20 + elapsed)
        // The timer is posted, so it can still land after the gesture ended.
        Thread.sleep(ViewConfiguration.getLongPressTimeout().toLong() + 350L)
        assertFalse(
            "a two-finger gesture latched the host's left button. Saw: ${rec.calls}",
            rec.calls.contains("longPress")
        )
    }

    /**
     * A long-press that fired before the second finger landed has to be
     * released when it lands.
     *
     * Otherwise the host holds its left button for the whole of the two-finger
     * gesture that follows — and if the session drops or the app is
     * backgrounded before the fingers lift, there is no client left to send the
     * Up and the host holds it until it is stopped outright.
     */
    @Test
    fun aSecondFingerReleasesADragThatAlreadyLatched() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 100f, 100f, t, t)
        Thread.sleep(ViewConfiguration.getLongPressTimeout().toLong() + 350L)
        assertTrue("the drag never latched. Saw: ${rec.calls}", rec.calls.contains("longPress"))
        val pointerDown =
            MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        sendTwoFinger(pointerDown, 100f, 100f, 400f, 400f, t, t + 800)
        assertTrue(
            "the second finger did not end the latched gesture. Saw: ${rec.calls}",
            rec.calls.indexOf("gestureEnd") > rec.calls.indexOf("longPress")
        )
    }

    /**
     * Two fingers down and up again is a right click, reported at the point
     * BETWEEN them.
     *
     * The operator asked for it directly: *"also a 2 finger tap should be a
     * right click"*. The position matters as much as the event — a context menu
     * opens where the pointer is, and reporting whichever finger happened to
     * lift last would open it beside what they were pointing at.
     */
    @Test
    fun twoFingersDownAndUpIsAReportedTap() {
        val t = SystemClock.uptimeMillis()
        val pointerDown =
            MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        val pointerUp =
            MotionEvent.ACTION_POINTER_UP or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        send(MotionEvent.ACTION_DOWN, 300f, 500f, t, t)
        sendTwoFinger(pointerDown, 300f, 500f, 500f, 500f, t, t + 15)
        sendTwoFinger(pointerUp, 300f, 500f, 500f, 500f, t, t + 60)
        send(MotionEvent.ACTION_UP, 300f, 500f, t, t + 70)
        assertTrue(
            "a two-finger tap was not reported. Saw: ${rec.calls}",
            rec.calls.contains("twoFingerTap")
        )
        val at = rec.twoFingerTapAt
        assertTrue("the tap carried no position", at != null)
        assertEquals("the tap must land between the fingers", 400f, at!!.first, 1f)
        assertEquals(500f, at.second, 1f)
    }

    /**
     * A two-finger DRAG is not a tap.
     *
     * Without this the pan gesture would right-click on every release, opening
     * a context menu each time the operator finished moving the view — and the
     * menu would then swallow the next touch.
     */
    @Test
    fun aTwoFingerDragIsNotATap() {
        val t = SystemClock.uptimeMillis()
        val pointerDown =
            MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        val pointerUp =
            MotionEvent.ACTION_POINTER_UP or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        send(MotionEvent.ACTION_DOWN, 300f, 500f, t, t)
        sendTwoFinger(pointerDown, 300f, 500f, 500f, 500f, t, t + 15)
        // Well past any plausible touch slop.
        sendTwoFinger(MotionEvent.ACTION_MOVE, 300f, 700f, 500f, 700f, t, t + 40)
        sendTwoFinger(pointerUp, 300f, 700f, 500f, 700f, t, t + 60)
        send(MotionEvent.ACTION_UP, 300f, 700f, t, t + 70)
        assertFalse(
            "a two-finger drag right-clicked. Saw: ${rec.calls}",
            rec.calls.contains("twoFingerTap")
        )
    }

    /**
     * Two fingers resting and then lifting is not a tap either. A tap is a
     * quick act; a long rest is somebody deciding what to do.
     */
    @Test
    fun aSlowTwoFingerReleaseIsNotATap() {
        val t = SystemClock.uptimeMillis()
        val pointerDown =
            MotionEvent.ACTION_POINTER_DOWN or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        val pointerUp =
            MotionEvent.ACTION_POINTER_UP or (1 shl MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        val slow = SurfaceTouchRouter.TWO_FINGER_TAP_TIMEOUT_MS + 200L
        send(MotionEvent.ACTION_DOWN, 300f, 500f, t, t)
        sendTwoFinger(pointerDown, 300f, 500f, 500f, 500f, t, t + 15)
        sendTwoFinger(pointerUp, 300f, 500f, 500f, 500f, t, t + slow)
        send(MotionEvent.ACTION_UP, 300f, 500f, t, t + slow + 10)
        assertFalse(
            "a long two-finger rest was reported as a tap. Saw: ${rec.calls}",
            rec.calls.contains("twoFingerTap")
        )
    }

    /** A tap must not be swallowed by the long-press path. */
    @Test
    fun aQuickTapIsReportedAsATap() {
        val t = SystemClock.uptimeMillis()
        send(MotionEvent.ACTION_DOWN, 50f, 50f, t, t)
        send(MotionEvent.ACTION_UP, 50f, 50f, t, t + 40)
        // onSingleTapConfirmed waits out the double-tap window before firing.
        Thread.sleep(ViewConfiguration.getDoubleTapTimeout().toLong() + 250L)
        assertTrue("a quick tap never produced onTap. Saw: ${rec.calls}",
            rec.calls.contains("tap"))
    }
}
