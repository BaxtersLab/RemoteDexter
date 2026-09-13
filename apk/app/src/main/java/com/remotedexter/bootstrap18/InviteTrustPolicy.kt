package com.remotedexter.bootstrap18

/**
 * Decides whether an invite's host identity may be acted on.
 *
 * Trust-on-first-use, then a closed door. The first identity seen is adopted;
 * after that an invite must present an identity this device already knows, or
 * the scan is refused. Same model as SSH host keys, same caveat — the first
 * pairing is taken on faith, so it should happen on a network you control.
 *
 * ## The one way in for a host that is not known yet
 *
 * A device that can only ever trust one host cannot be paired with two
 * machines, so [enrollmentArmed] exists. It is **not** a prompt on the scan
 * path: the operator arms enrollment in Settings, deliberately, before opening
 * the camera, and only then will a QR from an unknown identity be accepted. A
 * QR on its own can never add a host. See [com.remotedexter.EnrollmentArming]
 * for why the arm is short-lived and one-shot.
 *
 * That is the whole of the weakening, and it is worth being precise about what
 * it costs: with the arm closed — which is every moment the operator has not
 * just pressed the button — this decision is byte-for-byte the one it was when
 * the device could hold a single host.
 *
 * Deliberately pure: no Android types, no I/O, no stored state, no clock. The
 * caller reads the trusted set and the arm and passes them in. These five
 * branches are the entire security boundary for pairing, and they are testable
 * on the JVM without a device.
 */
object InviteTrustPolicy {

    /**
     * @param identityPubKeyB64 the identity key the invite claims, base64.
     * @param signatureValid result of [InviteSignatureVerifier.isValid].
     * @param trustedIdentities every host identity this device has paired with.
     *   Empty on a fresh install.
     * @param enrollmentArmed whether Settings has opened the door for one new
     *   host. Defaulted to false so that a caller which forgets to pass it gets
     *   the SAFE behaviour rather than the permissive one.
     *
     * Order matters. Presence is checked before validity, and validity before
     * any identity comparison, so the reported reason is the most specific true
     * one rather than whichever check happened to run first.
     */
    fun evaluate(
        identityPubKeyB64: String,
        signatureValid: Boolean,
        trustedIdentities: Set<String>,
        enrollmentArmed: Boolean = false
    ): InviteTrustResult {
        if (identityPubKeyB64.isBlank()) return InviteTrustResult.RejectedMissingSignature
        if (!signatureValid) return InviteTrustResult.RejectedBadSignature

        // A host we already know. Nothing to write; this is the ordinary case.
        if (identityPubKeyB64 in trustedIdentities) return InviteTrustResult.Accepted

        // Nothing stored at all — first use. Adopt it, exactly as before.
        if (trustedIdentities.isEmpty()) return InviteTrustResult.AcceptedNewEnrollment

        // An identity we do not know, and we already know at least one other.
        // This is a substituted host and a deliberate second pairing wearing
        // the same face; the device cannot tell them apart and does not try.
        // The arm is the operator saying which one it is, in advance.
        if (enrollmentArmed) return InviteTrustResult.AcceptedNewEnrollment

        return InviteTrustResult.RejectedIdentityChanged
    }
}
