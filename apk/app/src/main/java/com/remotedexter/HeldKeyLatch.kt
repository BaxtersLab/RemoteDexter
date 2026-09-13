package com.remotedexter

/**
 * Whether a debug-only test affordance is holding one host key down.
 *
 * # Why this exists at all
 *
 * Windows round 13 could not produce the `N key(s)` half of the host's shutdown
 * message from a phone, and said so rather than adjusting the test:
 *
 * > `[module10] shutdown released input state: 0 key(s), 1 button(s)`
 *
 * The button half is hardware-proven. The key half is not, and **cannot** be by
 * the shipping client, because [InputController.sendKeyStroke] sends Down and Up
 * together and unconditionally — deliberately, since a key left down on the host
 * repeats forever with nothing on the phone able to stop it. There is a
 * long-press latch for the left button ([DragLatch]); there was no equivalent
 * for keys and no client path emitting a lone key `Down`.
 *
 * The operator's decision on 2026-09-08 was to provide a deliberate test
 * affordance rather than accept the gap. This is the state behind it.
 *
 * # Why it holds exactly one key
 *
 * `N key(s)` needs N ≥ 1 to be proven, and one key proves the field. A set would
 * buy a larger number at the cost of the one property that makes this safe to
 * ship in a debug build: what is held is always nameable in a single `Int`, and
 * releasing it is a single unconditional call that cannot half-succeed.
 *
 * # The invariant
 *
 * Every method returns whether the caller must actually put something on the
 * wire, exactly as [DragLatch] does, so the caller never tracks this itself and
 * can never double-send. A `KeyEvent{action:"Down"}` never matched by an `Up`
 * is the worst thing this affordance can produce — it is the whole point of the
 * thing, and also its only hazard — so releasing is idempotent and
 * unconditional: [release] reports false when nothing is held.
 */
class HeldKeyLatch {

    private var heldScanCode: Int? = null

    /** The scan code currently held, or null. */
    fun held(): Int? = heldScanCode

    fun isHeld(): Boolean = heldScanCode != null

    /**
     * Latch [scanCode] down.
     *
     * @return true if a `KeyEvent{action:"Down"}` must be sent. False when a key
     *   is already held — including the same one, because a second Down for a
     *   key already down would owe a second Up that nothing tracks.
     */
    fun press(scanCode: Int): Boolean {
        if (heldScanCode != null) return false
        heldScanCode = scanCode
        return true
    }

    /**
     * Let go.
     *
     * @return the scan code owed a `KeyEvent{action:"Up"}`, or null when nothing
     *   is held. Safe to call at any time and any number of times.
     */
    fun release(): Int? {
        val owed = heldScanCode
        heldScanCode = null
        return owed
    }

    /** Session end, control revoked, activity destroyed. @return the scan code owed an Up. */
    fun reset(): Int? = release()
}
