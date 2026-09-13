package com.remotedexter

/**
 * Whether the phone will accept a QR from a host it does not already know.
 *
 * ## The decision this implements
 *
 * Until now the app trusted exactly one host, and [
 * com.remotedexter.bootstrap18.InviteTrustPolicy] refused any invite carrying a
 * different identity. That refusal is real protection: a QR handed to you for a
 * machine you did not mean to pair with is caught outright, with no dialog to
 * click through.
 *
 * Pairing with a second machine has to weaken that somehow — a list of hosts is
 * a list of identities that were once unknown. The operator chose the shape
 * that weakens it least: **the scan path keeps refusing unknown identities, and
 * enrolling a new host requires arming it first from Settings.** So a QR alone
 * can never add a host. Adding one takes a deliberate act, on a different
 * screen, before the camera is ever opened.
 *
 * ## Why it expires
 *
 * An arm that never ends is the same thing as having no refusal at all, just
 * with an extra step once. The window is short and starts when the operator
 * presses the button, so the open state exists only for as long as it takes to
 * walk to the other machine and scan its code.
 *
 * ## Why it is one-shot
 *
 * Consumed by an enrollment, not by a scan. A scan that fails for some other
 * reason — an expired invite, a bad signature — leaves the arm standing,
 * because the operator has not yet added the host they set out to add. A scan
 * that *succeeds* closes it, so one press adds one host.
 *
 * Pure: the caller supplies the clock. Time-dependent security rules that read
 * the clock themselves can only be tested by waiting.
 */
object EnrollmentArming {

    /**
     * How long an arm stays open, in milliseconds.
     *
     * Five minutes: long enough to cross a room and scan, short enough that an
     * arm left on by accident has closed itself before it could matter. It is
     * deliberately in the same order as an invite's own lifetime — a window
     * that outlived the codes it admits would be the longer-lived of the two
     * secrets protecting the same act.
     */
    const val WINDOW_MS: Long = 5 * 60 * 1000

    /**
     * True when a new host may be enrolled.
     *
     * @param armedAtMs when Settings armed it, or null if it never was.
     * @param nowMs the current clock.
     *
     * Every uncertain case answers **no**. A null arm is closed. An arm from
     * the future — which is what a clock change or a restored backup looks like
     * — is closed rather than treated as freshly pressed, because the one thing
     * that must not happen is a device that admits unknown hosts and cannot say
     * why.
     */
    fun isArmed(armedAtMs: Long?, nowMs: Long): Boolean {
        if (armedAtMs == null) return false
        if (armedAtMs > nowMs) return false
        return nowMs - armedAtMs < WINDOW_MS
    }

    /** Milliseconds left on the arm, or 0 when it is closed. */
    fun remainingMs(armedAtMs: Long?, nowMs: Long): Long {
        if (!isArmed(armedAtMs, nowMs)) return 0
        return WINDOW_MS - (nowMs - armedAtMs!!)
    }
}

/**
 * Where the arm is kept.
 *
 * Thin on purpose: the decision is [EnrollmentArming], which is pure and
 * tested. This holds a timestamp and nothing else, so there is no rule here
 * that could disagree with the rule there.
 *
 * Its own preferences file, so clearing it cannot disturb a pairing and a
 * cleared pairing cannot leave an arm standing.
 */
class EnrollmentArmingStore(context: android.content.Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE)

    /** Open the door for one new host, starting now. */
    fun arm(nowMs: Long = System.currentTimeMillis()) {
        prefs.edit().putLong(KEY_ARMED_AT, nowMs).apply()
        RdxLog.w(TAG, "enrollment armed: the next scan may add a host this device does not know")
    }

    /** When it was armed, or null. */
    fun armedAt(): Long? =
        if (prefs.contains(KEY_ARMED_AT)) prefs.getLong(KEY_ARMED_AT, 0) else null

    /** Whether an unknown host may be enrolled right now. */
    fun isArmed(nowMs: Long = System.currentTimeMillis()): Boolean =
        EnrollmentArming.isArmed(armedAt(), nowMs)

    /**
     * Close the door.
     *
     * Called after an enrollment actually happens, and by Settings when the
     * operator changes their mind. Idempotent.
     */
    fun disarm() {
        if (prefs.contains(KEY_ARMED_AT)) {
            prefs.edit().remove(KEY_ARMED_AT).apply()
            RdxLog.i(TAG, "enrollment disarmed")
        }
    }

    private companion object {
        const val TAG = "EnrollmentArming"
        const val PREFS_NAME = "enrollment_arming"
        const val KEY_ARMED_AT = "armed_at_ms"
    }
}
