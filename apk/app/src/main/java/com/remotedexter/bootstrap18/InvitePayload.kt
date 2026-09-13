package com.remotedexter.bootstrap18

import com.remotedexter.FailureReason
import org.json.JSONObject

/**
 * The invite the host encodes into the pairing QR (also written to NFC and
 * broadcast over the Wi-Fi beacon).
 *
 * Produced by `modules/module17_bootstrap_invite` on the Rust side. Property
 * names deliberately mirror the JSON keys — see the note in [SecurityPolicy].
 *
 * Two distinct public keys travel here and they must not be confused:
 *
 * - [host_pubkey] is the host's **Noise static X25519 key**, lowercase hex. It is
 *   the key the transport pins; the session refuses to proceed unless the
 *   handshake presents exactly this key.
 * - [host_identity_pubkey] is the host's **durable Ed25519 identity**, standard
 *   base64. [signature] is made by *this* key over the canonical encoding in
 *   [InviteSignatureVerifier.canonicalBytes], and it covers [host_pubkey].
 *
 * That split is what stops [host_pubkey] being self-asserted: without a valid
 * signature from a trusted identity, anyone who could craft an invite could also
 * name the key it pins, and pinning would prove nothing.
 */
data class InvitePayload(
    val lan_ip: String,
    val wan_ip: String,
    val port: Int,
    val session_token: String,
    val protocol: String,
    val version: Int,
    val security_policy: SecurityPolicy,
    val nonce: String,
    val signature: String,
    val host_pubkey: String,
    val host_identity_pubkey: String,
    val kind: String = "",
    val expires_at: Long = Long.MAX_VALUE,
    val capabilities: List<String> = emptyList()
) {
    fun toV4(): InviteV4? = if (version == InviteDecoder.INVITE_VERSION) {
        InviteV4(
            kind = kind,
            version = version,
            protocol = protocol,
            addr = lan_ip,
            port = port,
            token = session_token,
            nonce = nonce,
            expiresAt = expires_at,
            capabilities = capabilities,
            hostPubkey = host_pubkey,
            hostIdentityPubkey = host_identity_pubkey,
            signature = signature
        )
    } else {
        null
    }

    companion object {
        /**
         * Parse an invite from the scanned JSON.
         *
         * Only `port` and `session_token` are hard requirements — without a
         * reachable port and a token there is nothing to attempt. Everything
         * else is optional here and enforced later by [SessionStarter], which
         * can name the specific reason it refused. Failing early with a bare
         * `JSONException` would collapse every distinct refusal into one
         * indistinguishable "invalid" and hide which field was at fault.
         *
         * **`lan_ip` accepts `host_ip` as a fallback.** Builds up to March 2026
         * emitted the address as `host_ip`; the host now emits `lan_ip`. Reading
         * both keeps old invites working. Dropping this fallback silently breaks
         * pairing against any older host — it is the exact rename that produced
         * the "Invalid QR" failure those builds showed.
         */
        fun fromJson(obj: JSONObject): InvitePayload {
            return when (val decoded = InviteDecoder.decode(obj.toString())) {
                is Decoded.V4 -> {
                    val invite = decoded.invite
                    InvitePayload(
                        lan_ip = invite.addr,
                        wan_ip = "",
                        port = invite.port,
                        session_token = invite.token,
                        protocol = invite.protocol,
                        version = invite.version,
                        security_policy = SecurityPolicy.fromJson(JSONObject()),
                        nonce = invite.nonce,
                        signature = invite.signature,
                        host_pubkey = invite.hostPubkey,
                        host_identity_pubkey = invite.hostIdentityPubkey,
                        kind = invite.kind,
                        expires_at = invite.expiresAt,
                        capabilities = invite.capabilities
                    )
                }
                is Decoded.V3 -> {
                    val invite = decoded.invite
                    InvitePayload(
                        lan_ip = invite.addr,
                        wan_ip = invite.wanIp,
                        port = invite.port,
                        session_token = invite.token,
                        protocol = invite.protocol,
                        version = InviteDecoder.LEGACY_INVITE_VERSION,
                        security_policy = SecurityPolicy.fromJson(obj),
                        nonce = invite.nonce,
                        signature = invite.signature,
                        host_pubkey = invite.hostPubkey,
                        host_identity_pubkey = invite.hostIdentityPubkey
                    )
                }
                // A v5 invite names a RELAY and a session, and carries no host
                // address at all. [InvitePayload] is built around `lan_ip` and
                // `port`, so representing one here would mean inventing an
                // address the host is not listening on — the same mistake v3
                // made when it probed a public resolver for a "public" one.
                //
                // Refused by name instead. Teaching the client to open a relay
                // session is its own piece of work; until it exists, a v5 QR is
                // a code this build genuinely cannot act on, and saying so is
                // the only honest answer.
                is Decoded.V5 -> throw InviteDecodeException(
                    FailureReason.InviteParse,
                    "this pairing code is for a host reached through a relay, " +
                        "which this build cannot connect to yet"
                )
                is Decoded.SeparatorInField -> throw InviteDecodeException(
                    FailureReason.InviteParse,
                    "pairing code field ${decoded.field} is not a shape this build will verify"
                )
                is Decoded.WrongKind -> throw InviteDecodeException(
                    FailureReason.QrNotPairingCode,
                    "expected ${InviteDecoder.INVITE_KIND}, found ${decoded.found.ifBlank { "no kind" }}"
                )
                is Decoded.UnsupportedVersion -> throw InviteDecodeException(
                    FailureReason.InviteParse,
                    "pairing code version ${decoded.found} is not supported"
                )
                is Decoded.Malformed -> throw InviteDecodeException(
                    FailureReason.InviteParse,
                    "pairing code is missing ${decoded.field}"
                )
                Decoded.NotJson -> throw InviteDecodeException(
                    FailureReason.QrNotPairingCode,
                    "code is not RemoteDexter pairing JSON"
                )
            }
        }
    }
}

class InviteDecodeException(
    val reason: FailureReason,
    message: String
) : IllegalArgumentException(message)
