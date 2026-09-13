package com.remotedexter

import com.remotedexter.bootstrap18.InviteTrustPolicy
import com.remotedexter.bootstrap18.InviteTrustResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pairing security boundary, now that a device can know more than one host.
 *
 * This is the change the operator was asked about before a line of it was
 * written, because it alters **what the product refuses**. Before, an invite
 * carrying an identity other than the single trusted one was rejected outright.
 * A list of hosts is a list of identities that were each once unknown, so
 * something had to give.
 *
 * What was chosen: the scan path still refuses an unknown identity, and the
 * only way in is to arm enrollment from Settings first. These tests are what
 * hold that shape — in particular [theScanPathIsUnchangedWhileTheArmIsClosed],
 * which is the claim that with the arm shut this is the same decision it always
 * was.
 */
class TrustedHostSetTest {

    private val known = "AAAAknownhostidentity="
    private val other = "BBBBotherhostidentity="
    private val third = "CCCCthirdhostidentity="

    @Test
    fun aHostAlreadyOnTheListIsAcceptedAndNothingIsWritten() {
        assertEquals(
            InviteTrustResult.Accepted,
            InviteTrustPolicy.evaluate(known, true, setOf(known, other))
        )
    }

    /** Trust on first use survives. A fresh install has nothing to contradict. */
    @Test
    fun theFirstHostIsAdoptedOnSight() {
        assertEquals(
            InviteTrustResult.AcceptedNewEnrollment,
            InviteTrustPolicy.evaluate(known, true, emptySet())
        )
    }

    /**
     * **The claim this whole design rests on.** With the arm closed, an unknown
     * identity is refused exactly as it was when the device could hold one
     * host — no prompt, no dialog to click through, no difference at all.
     */
    @Test
    fun theScanPathIsUnchangedWhileTheArmIsClosed() {
        assertEquals(
            InviteTrustResult.RejectedIdentityChanged,
            InviteTrustPolicy.evaluate(third, true, setOf(known, other), enrollmentArmed = false)
        )
    }

    /**
     * The arm is the only door, and it opens for an identity that is genuinely
     * new — not for one that fails an earlier gate.
     */
    @Test
    fun anArmedDeviceEnrollsAnUnknownHost() {
        assertEquals(
            InviteTrustResult.AcceptedNewEnrollment,
            InviteTrustPolicy.evaluate(third, true, setOf(known, other), enrollmentArmed = true)
        )
    }

    /**
     * Arming does not weaken the signature check. It says "this host may be
     * new", never "this invite need not be genuine" — a QR that fails
     * verification is a QR that proves nothing about who issued it, and an
     * armed phone accepting one would be the worst possible reading of the
     * operator's intent.
     */
    @Test
    fun armingDoesNotExcuseABadSignature() {
        assertEquals(
            InviteTrustResult.RejectedBadSignature,
            InviteTrustPolicy.evaluate(third, false, setOf(known), enrollmentArmed = true)
        )
        assertEquals(
            InviteTrustResult.RejectedMissingSignature,
            InviteTrustPolicy.evaluate("", true, setOf(known), enrollmentArmed = true)
        )
    }

    /**
     * The default is the safe one. A caller that forgets the argument gets a
     * refusal, not a pass — the direction a forgotten security parameter must
     * fail in.
     */
    @Test
    fun theArmDefaultsToClosed() {
        assertEquals(
            InviteTrustResult.RejectedIdentityChanged,
            InviteTrustPolicy.evaluate(third, true, setOf(known))
        )
    }

    /**
     * A known host is accepted whether or not the arm is open, and it is still
     * `Accepted` rather than `AcceptedNewEnrollment` — the distinction is what
     * stops an armed reconnect from rewriting a record it did not need to
     * touch.
     */
    @Test
    fun armingChangesNothingForAHostWeAlreadyKnow() {
        assertEquals(
            InviteTrustResult.Accepted,
            InviteTrustPolicy.evaluate(known, true, setOf(known), enrollmentArmed = true)
        )
    }

    // ── the arm's lifetime ────────────────────────────────────────────────

    @Test
    fun anArmThatWasNeverPressedIsClosed() {
        assertFalse(EnrollmentArming.isArmed(null, 1_000_000))
    }

    @Test
    fun anArmIsOpenInsideItsWindowAndShutAtTheEdge() {
        val t = 1_000_000L
        assertTrue(EnrollmentArming.isArmed(t, t))
        assertTrue(EnrollmentArming.isArmed(t, t + EnrollmentArming.WINDOW_MS - 1))
        assertFalse(
            "the window must CLOSE at its edge, not one tick later",
            EnrollmentArming.isArmed(t, t + EnrollmentArming.WINDOW_MS)
        )
        assertFalse(EnrollmentArming.isArmed(t, t + EnrollmentArming.WINDOW_MS + 1))
    }

    /**
     * An arm stamped in the future is what a clock change or a restored backup
     * looks like. It is treated as closed rather than as freshly pressed: the
     * one thing that must not happen is a phone admitting unknown hosts for a
     * reason nobody can see.
     */
    @Test
    fun anArmFromTheFutureIsClosed() {
        assertFalse(EnrollmentArming.isArmed(2_000_000, 1_000_000))
        assertEquals(0, EnrollmentArming.remainingMs(2_000_000, 1_000_000))
    }

    @Test
    fun theRemainingTimeRunsDownAndStopsAtZero() {
        val t = 500_000L
        assertEquals(EnrollmentArming.WINDOW_MS, EnrollmentArming.remainingMs(t, t))
        assertEquals(1, EnrollmentArming.remainingMs(t, t + EnrollmentArming.WINDOW_MS - 1))
        assertEquals(0, EnrollmentArming.remainingMs(t, t + EnrollmentArming.WINDOW_MS))
        assertEquals(0, EnrollmentArming.remainingMs(null, t))
    }
}
