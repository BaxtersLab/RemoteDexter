package com.remotedexter

/**
 * What the app is actually doing, as one observable value.
 *
 * ## Why this type exists
 *
 * Before Block 5 the app's state lived in callback singletons and log lines.
 * Security refusals — a bad signature, a changed host identity, an expired
 * invite — were `Log.w` and nothing else: the user saw a screen that had not
 * changed, and concluded the app was broken rather than that it had *refused*.
 * A refusal the user cannot see is indistinguishable from a bug, and it trains
 * people to retry.
 *
 * Every state below is one the UI renders differently. There is no "something
 * went wrong" bucket.
 */
sealed class SessionState {

    /** Nothing is running. No service, no wake lock, no socket. */
    object Idle : SessionState()

    /** The user asked to connect and it is in progress. */
    data class Connecting(val hostLabel: String) : SessionState()

    /** A live remote session. This is the only state that may hold a wake lock. */
    data class Streaming(val hostLabel: String) : SessionState()

    /**
     * A refusal or failure, with a reason the UI can render specifically.
     *
     * `detail` is already redacted by the code that constructs it and is safe
     * to display and log.
     */
    data class Failed(val reason: FailureReason, val detail: String) : SessionState()

    /**
     * The host presented a different identity than the one this device paired
     * with. **Blocking, and deliberately not a `Failed` variant** — it is not a
     * transient error and must never be cleared by a retry.
     *
     * Both fingerprints are public keys. Nothing secret is displayed.
     */
    data class IdentityMismatch(
        val expectedFingerprint: String,
        val receivedFingerprint: String
    ) : SessionState()

    /** True while a session is live or being established. */
    val isActive: Boolean
        get() = this is Connecting || this is Streaming

    /** True when the session has ended for any reason, including refusal. */
    val isTerminal: Boolean
        get() = this is Failed || this is IdentityMismatch || this is Idle
}

/**
 * Every distinct way a connection can fail, each with its own visible state.
 *
 * The plan names nine; they are all here and none of them collapses into
 * another. `Unknown` is deliberately absent: an unmapped failure should be a
 * compile error when a new one is added, not a silent fallback that hides it.
 */
enum class FailureReason {
    /** The QR was not a RemoteDexter pairing code — often the install link. */
    QrNotPairingCode,

    /** The invite's JSON was malformed or missing a required field. */
    InviteParse,

    /** The invite's Ed25519 signature did not verify. */
    InviteSignature,

    /** The invite had already expired when it was scanned. */
    InviteExpired,

    /** This build does not have a native library for this device's ABI. */
    UnsupportedAbi,

    /** The host could not be reached at the address in the invite. */
    Network,

    /** The pinned Noise handshake failed. */
    NoiseHandshake,

    /** The host refused the pairing token: wrong, expired, or already used. */
    PairingRefused,

    /** The host refused a capture or input request mid-session. */
    Authorization,

    /** The frame stream stopped or could not be decoded. */
    Stream,

    /**
     * The relay did not know the session this device presented.
     *
     * The relay gives this one answer for a host that is not connected to it
     * and for an id it no longer recognises after its own restart — on purpose,
     * so a stranger cannot probe which ids are real. So the detail names both
     * remedies. Reported as a stream failure before this existed, which was
     * false: nothing had streamed.
     */
    RelaySessionUnknown;

    /** A short, user-facing label. Names what happened, not what to do about it. */
    fun label(): String = when (this) {
        QrNotPairingCode -> "Not a pairing code"
        InviteParse -> "Pairing code unreadable"
        InviteSignature -> "Pairing code not signed by this host"
        InviteExpired -> "Pairing code expired"
        UnsupportedAbi -> "Unsupported device"
        Network -> "Cannot reach the host"
        NoiseHandshake -> "Secure handshake failed"
        PairingRefused -> "Host refused the pairing code"
        Authorization -> "Host refused the request"
        Stream -> "Screen stream stopped"
        RelaySessionUnknown -> "The relay does not know this host"
    }

    /**
     * Whether offering "try again" makes sense.
     *
     * A one-use token cannot be retried, and a bad signature will not become
     * good. Offering retry where it cannot work teaches users to mash it.
     */
    fun isRetryable(): Boolean = when (this) {
        // Retry can work: a host that was not running may be now. The detail
        // says what else it might need.
        Network, Stream, RelaySessionUnknown -> true
        QrNotPairingCode, InviteParse, InviteSignature, InviteExpired,
        UnsupportedAbi, NoiseHandshake, PairingRefused, Authorization -> false
    }
}

/** Translate the native worker's latest status while a stream is active. */
object SessionStatusPolicy {
    fun streamingFailure(status: String): String? {
        val state = status.substringBefore('|')
        val detail = status.substringAfter('|', "").ifBlank { "no detail" }
        return when (state) {
            "connected" -> null
            "failed" -> detail
            "idle" -> "native session ended: $detail"
            else -> "native session entered unexpected state '$state': $detail"
        }
    }
}

/**
 * What a failure reported by the native session means to the person holding
 * the phone.
 *
 * Pure, so the mapping is tested on the JVM rather than by provoking each
 * failure on a device.
 */
object NativeFailure {

    /**
     * The text the native client puts in front of a relay's refusal. Pinned on
     * the Rust side by a test that reads this file, so the two cannot drift
     * apart and quietly turn every relay refusal back into "stream stopped".
     */
    const val RELAY_REFUSED_MARK = "the relay refused this session"

    /** Classify a native failure detail. */
    fun classify(detail: String, reconnectingViaRelay: Boolean): SessionState.Failed {
        if (!detail.contains(RELAY_REFUSED_MARK)) {
            return SessionState.Failed(FailureReason.Stream, detail)
        }
        val advice = if (reconnectingViaRelay) {
            // A stored route. Either the host is not connected to the relay, or
            // the relay restarted since this device paired and the stored id is
            // gone. The relay will not say which.
            "Start RemoteDexter on the host. If it is already running, the relay has " +
                "restarted since this phone paired — scan a fresh code from the host."
        } else {
            // A code just scanned. The session it names is not on the relay.
            "Check RemoteDexter is running on the host and connected to the relay, " +
                "then make a fresh code."
        }
        return SessionState.Failed(FailureReason.RelaySessionUnknown, advice)
    }
}
