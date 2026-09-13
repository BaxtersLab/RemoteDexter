package com.remotedexter

/**
 * Pure pointer-motion arithmetic for [InputController] — sub-pixel
 * accumulation, send coalescing, and the drag-latch state machine.
 *
 * **Deliberately free of every Android and JNI dependency.** Nothing here
 * imports `android.*` or touches [RDRust], so the whole of it runs as a plain
 * JVM unit test with no device, no emulator and no test doubles. The classes
 * that *do* need the platform ([InputController], `MainActivity`) keep only the
 * parts that genuinely need it: sending bytes, and receiving gestures.
 *
 * This is the same split the estate already uses for GGUF-Chatbox's slot logic,
 * and for the same reason — the arithmetic is where the defects live, and
 * arithmetic is cheap to test exhaustively when it is not entangled with a
 * platform.
 */

/** Whole-pixel cursor delta ready to go on the wire. */
data class Delta(val dx: Int, val dy: Int)

/**
 * Accumulates touch deltas into whole-pixel cursor movement and decides when to
 * actually send.
 *
 * ### Why a carried remainder rather than a bigger sensitivity
 *
 * The original `(dxPixels * SENSITIVITY).toInt()` truncated **per sample** and
 * dropped the fraction on the floor. That produced two distinct defects,
 * measured against the shipped code and recorded in
 * `ANDROID_INPUT_SPEC_2026-08-19.md` §5.1:
 *
 * * a **dead zone** — any component below `1/sensitivity` px rounded to zero and
 *   was discarded, so slow precise movement moved the cursor not at all;
 * * **systematic under-travel at every speed** — a 3.0px sample scaled to 4.5
 *   and truncated to 4, losing 0.5px each time, about 11% short. The loss
 *   shrinks as samples get larger, so effective sensitivity *varied with drag
 *   speed*. That is why it read as inconsistent rather than merely slow, and
 *   why retuning the constant could never have fixed it.
 *
 * Carrying the fraction into the next sample fixes both: nothing is discarded,
 * only deferred, and total travel is exact to within one pixel over any gesture.
 *
 * ### Why coalescing
 *
 * `onScroll` fires per touch sample — 60–120 Hz on ordinary hardware. Sending
 * one `input_event` per sample means that many JSON round trips per second over
 * the Noise session for a single drag. The wire protocol already anticipates
 * this: `module10`'s `Capabilities { max_coalesce }` and its `MoveCoalescer`
 * exist to fold samples together. This is the client half of that idea.
 *
 * Two independent budgets, whichever comes first — a time interval, so a slow
 * drag still feels immediate, and a sample cap, so a burst arriving faster than
 * the clock can still not be held indefinitely.
 */
class PointerMotion(
    private val sensitivity: Float = DEFAULT_SENSITIVITY,
    private val minSendIntervalMs: Long = DEFAULT_MIN_SEND_INTERVAL_MS,
    private val maxCoalesce: Int = DEFAULT_MAX_COALESCE,
) {
    companion object {
        /**
         * Touch-pixels-to-cursor-delta multiplier. 1.0 would move the remote
         * cursor as many pixels as the finger moved; lower so a comfortable
         * drag across a phone screen does not fling the cursor across the whole
         * remote desktop. Client-side feel only — no protocol meaning.
         */
        const val DEFAULT_SENSITIVITY = 1.5f

        /** ~60 Hz. One encrypted round trip per touch sample is the thing to avoid. */
        const val DEFAULT_MIN_SEND_INTERVAL_MS = 16L

        /**
         * Hard cap on samples folded into one send, mirroring the protocol's own
         * `Capabilities { max_coalesce }`. Bounds worst-case latency when
         * samples arrive faster than the interval.
         */
        const val DEFAULT_MAX_COALESCE = 8
    }

    /** Sub-pixel remainder, carried forward. Never discarded, only deferred. */
    private var carryX = 0f
    private var carryY = 0f

    /** Whole pixels accumulated but not yet sent. */
    private var pendingX = 0
    private var pendingY = 0

    private var samples = 0
    private var lastSendMs = UNSET

    /**
     * Feed one drag sample, in on-screen touch pixels. Returns the delta to
     * send when a budget says so, or null to keep accumulating.
     */
    fun onDragSample(dxPixels: Float, dyPixels: Float, nowMs: Long): Delta? {
        carryX += dxPixels * sensitivity
        carryY += dyPixels * sensitivity

        // toInt() truncates toward zero, which is symmetric for negatives —
        // floor() would bias every leftward/upward drag by a pixel per sample.
        val wholeX = carryX.toInt()
        val wholeY = carryY.toInt()
        carryX -= wholeX
        carryY -= wholeY

        pendingX += wholeX
        pendingY += wholeY
        samples++

        // The clock starts at the first sample of a gesture, not at epoch;
        // otherwise the very first sample always looks overdue.
        if (lastSendMs == UNSET) lastSendMs = nowMs

        val dueByTime = nowMs - lastSendMs >= minSendIntervalMs
        val dueByCount = samples >= maxCoalesce
        return if (dueByTime || dueByCount) emit(nowMs) else null
    }

    /**
     * End of gesture. Always call this — a pending sub-whole-pixel movement
     * would otherwise be stranded until the next unrelated gesture pushed it
     * over the line, which reads as the cursor twitching on the next touch.
     */
    fun flush(nowMs: Long): Delta? = emit(nowMs)

    /** Back to the pre-gesture state, carried fraction included. */
    fun reset() {
        carryX = 0f
        carryY = 0f
        pendingX = 0
        pendingY = 0
        samples = 0
        lastSendMs = UNSET
    }

    private fun emit(nowMs: Long): Delta? {
        samples = 0
        lastSendMs = nowMs
        if (pendingX == 0 && pendingY == 0) return null
        val d = Delta(pendingX, pendingY)
        pendingX = 0
        pendingY = 0
        return d
    }
}

private const val UNSET = Long.MIN_VALUE

/**
 * Whether the host's left button is currently held down by a latched drag.
 *
 * Every method returns whether the caller must actually send something, so the
 * caller never has to track this itself and can never double-send. That matters
 * more here than anywhere else in the client: a `MouseButton{Down}` that is
 * never matched by an `Up` leaves the host with a button held, selecting and
 * dragging everything the cursor passes over. It is the worst failure this
 * feature can produce, so releasing is made idempotent and unconditional —
 * [reset] releases if and only if something is actually latched.
 */
class DragLatch {
    private var latched = false

    fun isLatched(): Boolean = latched

    /** @return true if a `MouseButton{button:0,action:"Down"}` must be sent. */
    fun press(): Boolean {
        if (latched) return false
        latched = true
        return true
    }

    /** @return true if a `MouseButton{button:0,action:"Up"}` must be sent. */
    fun release(): Boolean {
        if (!latched) return false
        latched = false
        return true
    }

    /** Session end, ACTION_CANCEL, control revoked. @return true if an Up is owed. */
    fun reset(): Boolean = release()
}
