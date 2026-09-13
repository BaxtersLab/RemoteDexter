package com.remotedexter.bootstrap18

/**
 * Outcome of evaluating an invite's host identity against what this device
 * already trusts.
 *
 * Sealed so [SessionStarter] cannot silently forget to handle a rejection: a new
 * refusal reason added here surfaces as a non-exhaustive `when` at compile time
 * rather than as an invite that quietly proceeds.
 */
sealed class InviteTrustResult {

    /**
     * Signature verified against an identity this device already trusts.
     *
     * Nothing is written. Separated from [AcceptedNewEnrollment] because
     * "should this host be stored" used to be decided at the call site by
     * checking whether the trusted value happened to be null — a condition that
     * lived nowhere near the rule it was implementing, and that could not stay
     * correct once there could be several trusted hosts and still nothing to
     * write.
     */
    object Accepted : InviteTrustResult()

    /**
     * Signature verified, the identity is new, and adding it is allowed —
     * either because this is a fresh install with nothing to contradict it, or
     * because the operator armed enrollment in Settings first.
     *
     * The caller must store the host. This is the ONLY result that grows what
     * the device trusts.
     */
    object AcceptedNewEnrollment : InviteTrustResult()

    /** The invite carried no host identity key, so nothing could be verified. */
    object RejectedMissingSignature : InviteTrustResult()

    /** An identity key was present but its signature did not verify. */
    object RejectedBadSignature : InviteTrustResult()

    /**
     * The signature verified, but against a *different* identity than the one
     * this device previously paired with.
     *
     * This is the interesting rejection: it is what a machine-in-the-middle
     * looks like, and it is also what a legitimate host re-key looks like. The
     * two are indistinguishable from here, so the device refuses and defers to
     * the user rather than guessing — re-pairing requires explicitly forgetting
     * the stored identity, and pairing an ADDITIONAL host requires arming
     * enrollment in Settings before the scan.
     */
    object RejectedIdentityChanged : InviteTrustResult()
}
