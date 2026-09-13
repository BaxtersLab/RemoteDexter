package com.remotedexter

/**
 * The order in which an absolute click's parts go on the wire.
 *
 * This is a separate, Android-free object for the same reason
 * [ControlDisableSequence] is: the ordering *is* the correctness, and it is
 * worth being able to assert it on the JVM in a millisecond rather than only on
 * a device against a live host.
 *
 * ### Why the move must come first
 *
 * With a cursor lift set, the host pointer is deliberately **not** under the
 * fingertip. So a click that does not move first clicks wherever the pointer was
 * last left — which is the exact failure the cursor-offset feature exists to
 * prevent, and it would be invisible at zero offset and wrong at every other
 * setting.
 */
object AbsoluteInputSequence {

    /** Left button, matching the host's `0 = left` convention. */
    const val LEFT_BUTTON = 0

    /** Right button — `1` on the same host convention. */
    const val RIGHT_BUTTON = 1

    /**
     * A tap: put the pointer on the target, then press and release it there.
     */
    fun tap(
        x: Int,
        y: Int,
        move: (Int, Int) -> Unit,
        button: (Int, String) -> Unit
    ) {
        move(x, y)
        button(LEFT_BUTTON, "Down")
        button(LEFT_BUTTON, "Up")
    }

    /**
     * A two-finger tap: the same shape as [tap], with the right button.
     *
     * Move first for exactly the reason [tap] does. A context menu opens where
     * the pointer is, so a right click that does not move first opens one
     * somewhere the operator is not looking — a worse failure than a misplaced
     * left click, because the menu then swallows the next tap as well.
     */
    fun secondaryTap(
        x: Int,
        y: Int,
        move: (Int, Int) -> Unit,
        button: (Int, String) -> Unit
    ) {
        move(x, y)
        button(RIGHT_BUTTON, "Down")
        button(RIGHT_BUTTON, "Up")
    }

    /**
     * A long press: put the pointer on the target, then hold the button down.
     *
     * No `Up` — the latch is released by the gesture ending, by control being
     * revoked, or by a session reset, and those paths already exist. Emitting an
     * `Up` here would break click-and-drag entirely.
     */
    fun longPress(
        x: Int,
        y: Int,
        move: (Int, Int) -> Unit,
        button: (Int, String) -> Unit
    ) {
        move(x, y)
        button(LEFT_BUTTON, "Down")
    }
}

/**
 * Whether an input event may be put on the wire at all.
 *
 * Two independent conditions, and both are load-bearing. Control being enabled
 * is the user's explicit grant — viewing mode must be genuinely silent, not
 * merely visually inert. A valid window id is the session actually existing;
 * without it the host has nothing to aim at and the event would be discarded
 * anyway, so sending it only creates log noise during teardown.
 */
object InputEmissionPolicy {
    fun mayEmit(controlEnabled: Boolean, windowId: Long): Boolean =
        controlEnabled && windowId >= 0
}
