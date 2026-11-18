package com.remotedexter.bootstrap18

import android.content.Context
import android.content.Intent
import android.location.Location
import android.location.LocationManager
import android.os.Build
import com.remotedexter.FailureReason
import com.remotedexter.PendingConnects
import com.remotedexter.RDRust
import com.remotedexter.RDService
import com.remotedexter.RdxLog
import com.remotedexter.SessionState
import com.remotedexter.SessionStateHolder
import com.remotedexter.security.GeoFenceChecker
import java.security.MessageDigest

/**
 * Turns a scanned invite into a live session, or refuses and says why.
 *
 * This is the security boundary for pairing. Every gate below refuses by
 * logging through [RdxLog] and returning — none of them throws. That is
 * deliberate: a thrown exception here would be caught by the scanner's generic
 * handler and reported as a generic parse failure, which would tell the user
 * (and us) nothing about which check actually refused.
 *
 * The consequence is that a refusal is **silent in the UI**. The log is the only
 * record, which is exactly why it goes to [RdxLog] rather than `android.util.Log`
 * — the operator can read it on the device without a cable.
 */
object SessionStarter {

    private const val TAG = "SessionStarter"

    /** A Noise static X25519 key is exactly this many bytes. */
    private const val NOISE_PUBKEY_BYTES = 32

    /**
     * Validate an invite and, if it passes every gate, open the session.
     *
     * @param context needed for the trust store and the optional geo-fence.
     *   Nullable so callers without one still get a defined refusal rather than
     *   a crash.
     */
    fun startFromInvite(payload: InvitePayload, context: Context?) {
        RdxLog.i(
            TAG,
            "startFromInvite → lan=${payload.lan_ip} wan=${payload.wan_ip} " +
                "port=${payload.port} token=${tokenFingerprint(payload.session_token)} " +
                "protocol=${payload.protocol} v=${payload.version}"
        )

        val policy = payload.security_policy

        // ── Gate 1: a token must exist ───────────────────────────────────────
        if (payload.session_token.isBlank()) {
            RdxLog.e(TAG, "Security gate BLOCKED: missing session token")
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "missing pairing token")
            )
            return
        }

        // ── Gate 2: the Noise key pin must be well-formed ────────────────────
        // Fail closed. Without a valid 32-byte pin the transport has nothing to
        // compare the handshake against, and an unpinned session would connect
        // to whoever answers on that address.
        val pin = hexToBytes(payload.host_pubkey)
        if (pin == null || pin.size != NOISE_PUBKEY_BYTES) {
            RdxLog.e(TAG, "Security gate BLOCKED: invite is missing a valid 32-byte host_pubkey pin")
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "invalid host key pin")
            )
            return
        }

        // ── Gate 3: the invite must be signed by a trusted host identity ─────
        val signatureValid = InviteSignatureVerifier.isValid(payload)
        val registry = context?.let { com.remotedexter.PairedHostRegistry(it) }
        val arming = context?.let { com.remotedexter.EnrollmentArmingStore(it) }
        val trustedIdentities = registry?.trustedIdentities() ?: emptySet()
        // No context means no stored trust and no way to arm anything, so the
        // set is empty and the arm is shut. That reads as a fresh install,
        // which is the safe interpretation: it cannot turn a known-host check
        // into a pass, only a first-use adoption that has nowhere to be stored.
        val enrollmentArmed = arming?.isArmed() ?: false

        when (InviteTrustPolicy.evaluate(
            payload.host_identity_pubkey,
            signatureValid,
            trustedIdentities,
            enrollmentArmed
        )) {
            is InviteTrustResult.RejectedMissingSignature -> {
                RdxLog.e(TAG, "Security gate BLOCKED: invite has no host identity signature")
                SessionStateHolder.set(
                    SessionState.Failed(FailureReason.InviteSignature, "signature is missing")
                )
                return
            }
            is InviteTrustResult.RejectedBadSignature -> {
                RdxLog.e(TAG, "Security gate BLOCKED: invite signature failed verification")
                SessionStateHolder.set(
                    SessionState.Failed(FailureReason.InviteSignature, "signature verification failed")
                )
                return
            }
            is InviteTrustResult.RejectedIdentityChanged -> {
                RdxLog.e(
                    TAG,
                    "Security gate BLOCKED: host identity differs from the previously " +
                        "trusted host — forget the paired host in Session Permissions to " +
                        "intentionally re-pair"
                )
                SessionStateHolder.set(
                    SessionState.IdentityMismatch(
                        // The active host is the one Connect would have used,
                        // so it is the one the operator is comparing against.
                        // With several paired, naming any other would answer a
                        // question they did not ask.
                        expectedFingerprint = registry?.active()?.identityB64.orEmpty().take(16),
                        receivedFingerprint = payload.host_identity_pubkey.take(16)
                    )
                )
                return
            }
            is InviteTrustResult.Accepted -> {
                // A host already on the list. Nothing to store.
            }
            is InviteTrustResult.AcceptedNewEnrollment -> {
                RdxLog.w(
                    TAG,
                    "Enrolling a host identity this device did not know: " +
                        "${payload.host_identity_pubkey.take(12)}… " +
                        "(armed=$enrollmentArmed, already trusted=${trustedIdentities.size})"
                )
                // Nothing is stored here. SessionOrchestrator writes the record
                // once the handshake reports `connected`, reading the identity
                // off the invite it already holds — so the two halves are
                // stored as one thing, and a host that has not yet accepted us
                // is never trusted.
                //
                // The arm is spent on the enrollment, not on the scan: a scan
                // that fails for some other reason leaves it standing, because
                // the operator has not yet added the host they set out to add.
                arming?.disarm()
            }
        }

        if (payload.version == InviteDecoder.INVITE_VERSION &&
            System.currentTimeMillis() / 1000 >= payload.expires_at
        ) {
            RdxLog.e(TAG, "Security gate BLOCKED: pairing code expired")
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteExpired, "scan a fresh code")
            )
            return
        }

        if (payload.protocol != "rdv3") {
            SessionStateHolder.set(
                SessionState.Failed(
                    FailureReason.PairingRefused,
                    "unsupported protocol ${payload.protocol}"
                )
            )
            return
        }

        val v4 = payload.toV4()
        if (v4 == null) {
            SessionStateHolder.set(
                SessionState.Failed(
                    FailureReason.PairingRefused,
                    "this host uses the retired v3 pairing transport; upgrade the host"
                )
            )
            return
        }

        if ("view" !in v4.capabilities) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.Authorization, "invite does not grant viewing")
            )
            return
        }

        // ── Gate 4: device pairing, if the host demands it ───────────────────
        if (policy.require_device_pairing) {
            RdxLog.e(
                TAG,
                "Security gate BLOCKED: require_device_pairing=true but known-host " +
                    "verification is not implemented"
            )
            return
        }

        // ── Gate 5: geo-fence, if the host demands it ────────────────────────
        if (policy.require_geo_fence && !passesGeoFence(policy, context)) return

        // ── Gate 6: an address to dial ───────────────────────────────────────
        val targetIp = payload.lan_ip.trim().ifBlank { payload.wan_ip.trim() }
        if (targetIp.isBlank()) {
            RdxLog.e(TAG, "No usable IP in invite payload")
            return
        }

        if (context == null) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "connection context unavailable")
            )
            return
        }

        val requestId = PendingConnects.submit(v4)
        val service = Intent(context, RDService::class.java)
            .setAction(PendingConnects.ACTION_CONNECT)
            .putExtra(PendingConnects.EXTRA_REQUEST_ID, requestId)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(service)
        } else {
            context.startService(service)
        }
    }

    /**
     * Validate a v5 (relay) invite and, if it passes every gate, open the
     * session through the relay it names.
     *
     * **Gate for gate the same as [startFromInvite], in the same order.** This
     * is not a shortcut around the direct path's checks — it is the same checks
     * against a different schema. A route that reached the transport with fewer
     * gates would make "scan the relay code instead" a way to bypass them.
     *
     * It does not store a paired-host record itself, and neither path does: the
     * record is written by `SessionOrchestrator` only once the host reports
     * `connected`, which it does only after accepting this device. The relay
     * route IS recorded now — the relay gives an enrolled host the same session
     * id across the host's restarts, so the route stays usable (see
     * [com.remotedexter.RelayRoute]).
     */
    fun startFromRelayInvite(invite: InviteV5, context: Context?) {
        RdxLog.i(
            TAG,
            "startFromRelayInvite → relay=${invite.relayAddr}:${invite.relayPort} " +
                "token=${tokenFingerprint(invite.token)} protocol=${invite.protocol} " +
                "v=${invite.version}"
        )
        // The SESSION ID IS NOT LOGGED. It is what this device presents to the
        // relay to be spliced to a host, so it is a credential against the
        // relay and belongs in the invite and nowhere else.

        // ── Gate 1: a token must exist ───────────────────────────────────────
        if (invite.token.isBlank()) {
            RdxLog.e(TAG, "Security gate BLOCKED: missing session token")
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "missing pairing token")
            )
            return
        }

        // ── Gate 1b: a session to ask the relay for ──────────────────────────
        if (invite.session.isBlank()) {
            RdxLog.e(TAG, "Security gate BLOCKED: relay invite carries no session")
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "pairing code names no session")
            )
            return
        }

        // ── Gate 2: the Noise key pin must be well-formed ────────────────────
        // Unchanged by the route. The relay is a wire; what stops it splicing
        // this device to a host of its own choosing is this pin, checked in the
        // handshake that runs end to end through the splice.
        val pin = hexToBytes(invite.hostPubkey)
        if (pin == null || pin.size != NOISE_PUBKEY_BYTES) {
            RdxLog.e(TAG, "Security gate BLOCKED: invite is missing a valid 32-byte host_pubkey pin")
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "invite has no valid host key pin")
            )
            return
        }

        // ── Gate 3: signed by a trusted host identity ────────────────────────
        val signatureValid = InviteSignatureVerifier.isValidV5(invite)
        val registry = context?.let { com.remotedexter.PairedHostRegistry(it) }
        val arming = context?.let { com.remotedexter.EnrollmentArmingStore(it) }
        val trustedIdentities = registry?.trustedIdentities() ?: emptySet()
        val enrollmentArmed = arming?.isArmed() ?: false

        when (InviteTrustPolicy.evaluate(
            invite.hostIdentityPubkey,
            signatureValid,
            trustedIdentities,
            enrollmentArmed
        )) {
            is InviteTrustResult.RejectedMissingSignature -> {
                RdxLog.e(TAG, "Security gate BLOCKED: relay invite has no host identity signature")
                SessionStateHolder.set(
                    SessionState.Failed(FailureReason.InviteSignature, "signature is missing")
                )
                return
            }
            is InviteTrustResult.RejectedBadSignature -> {
                RdxLog.e(TAG, "Security gate BLOCKED: relay invite signature failed verification")
                SessionStateHolder.set(
                    SessionState.Failed(
                        FailureReason.InviteSignature,
                        "signature verification failed"
                    )
                )
                return
            }
            is InviteTrustResult.RejectedIdentityChanged -> {
                RdxLog.e(
                    TAG,
                    "Security gate BLOCKED: host identity differs from the previously " +
                        "trusted host — forget the paired host in Session Permissions to " +
                        "intentionally re-pair"
                )
                SessionStateHolder.set(
                    SessionState.IdentityMismatch(
                        expectedFingerprint = registry?.active()?.identityB64.orEmpty().take(16),
                        receivedFingerprint = invite.hostIdentityPubkey.take(16)
                    )
                )
                return
            }
            is InviteTrustResult.Accepted -> {
                // A host already on the list. Nothing to store.
            }
            is InviteTrustResult.AcceptedNewEnrollment -> {
                RdxLog.w(
                    TAG,
                    "Enrolling a host identity this device did not know: " +
                        "${invite.hostIdentityPubkey.take(12)}… " +
                        "(armed=$enrollmentArmed, already trusted=${trustedIdentities.size})"
                )
                arming?.disarm()
            }
        }

        // ── Gate 3b: expiry ──────────────────────────────────────────────────
        if (InviteDecoder.isExpired(invite, System.currentTimeMillis() / 1000)) {
            RdxLog.e(TAG, "Security gate BLOCKED: pairing code expired")
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteExpired, "scan a fresh code")
            )
            return
        }

        if (invite.protocol != "rdv3") {
            SessionStateHolder.set(
                SessionState.Failed(
                    FailureReason.PairingRefused,
                    "unsupported protocol ${invite.protocol}"
                )
            )
            return
        }

        // ── Gate 3c: the invite must actually grant viewing ──────────────────
        if ("view" !in invite.capabilities) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.Authorization, "invite does not grant viewing")
            )
            return
        }

        if (context == null) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "connection context unavailable")
            )
            return
        }

        val requestId = PendingConnects.submitRelay(invite)
        val service = Intent(context, RDService::class.java)
            .setAction(PendingConnects.ACTION_CONNECT)
            .putExtra(PendingConnects.EXTRA_REQUEST_ID, requestId)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(service)
        } else {
            context.startService(service)
        }
    }

    /**
     * Legacy entry point for callers that have only an address and a token.
     *
     * Builds a payload with no signature, no identity and no pin, which means it
     * cannot pass gate 2 or gate 3 — it always refuses. Kept so any remaining
     * caller fails loudly in the log rather than silently bypassing the
     * verification the four-argument path enforces.
     */
    fun startFromInvite(hostIp: String, port: Int, token: String) {
        RdxLog.w(TAG, "legacy startFromInvite() called — no pin or signature, will refuse")
        startFromInvite(
            InvitePayload(
                lan_ip = hostIp,
                wan_ip = "",
                port = port,
                session_token = token,
                protocol = "rdv3",
                version = 3,
                security_policy = SecurityPolicy.fromJson(org.json.JSONObject()),
                nonce = "",
                signature = "",
                host_pubkey = "",
                host_identity_pubkey = ""
            ),
            null
        )
    }

    /** True when the device is inside the host's fence. Logs its own refusals. */
    private fun passesGeoFence(policy: SecurityPolicy, context: Context?): Boolean {
        val lat = policy.geo_fence_lat
        val lon = policy.geo_fence_lon
        val radius = policy.geo_fence_radius_m

        if (lat == null || lon == null || radius == null) {
            RdxLog.e(TAG, "Security gate BLOCKED: require_geo_fence=true but fence coords missing")
            return false
        }
        if (context == null) {
            RdxLog.e(TAG, "Security gate BLOCKED: require_geo_fence=true but no Context provided")
            return false
        }

        // Location access can be revoked at any time; a SecurityException here
        // must refuse, never proceed unfenced.
        val fix: Location? = try {
            val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            lm?.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
                ?: lm?.getLastKnownLocation(LocationManager.GPS_PROVIDER)
        } catch (e: SecurityException) {
            RdxLog.e(TAG, "Location permission denied — cannot enforce geo fence", e)
            null
        }

        if (fix == null) {
            RdxLog.e(TAG, "Security gate BLOCKED: require_geo_fence=true but location unavailable")
            return false
        }

        val inside = GeoFenceChecker.isWithinFence(fix.latitude, fix.longitude, lat, lon, radius)
        if (!inside) {
            RdxLog.e(
                TAG,
                "Security gate BLOCKED: device outside host geofence " +
                    "(fence=$lat,$lon r=${radius}m)"
            )
        }
        return inside
    }

    /**
     * Short, non-reversible tag for a session token, for logs.
     *
     * The token is a bearer credential — logging it whole would put a working
     * credential in a file the user is encouraged to copy and paste to us. Four
     * bytes of SHA-256 is enough to correlate a log line with a host-side
     * invite without being useful to anyone who reads it.
     */
    private fun tokenFingerprint(token: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(token.toByteArray())
        return digest.take(4).joinToString("") { "%02x".format(it) } + "…"
    }

    /**
     * Decode lowercase hex to bytes, or null if it is not valid hex.
     *
     * Returns null rather than throwing so gate 2 can report a specific reason.
     */
    private fun hexToBytes(hex: String): ByteArray? {
        if (hex.isEmpty() || hex.length % 2 != 0) return null
        return try {
            ByteArray(hex.length / 2) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        } catch (e: NumberFormatException) {
            null
        }
    }
}
