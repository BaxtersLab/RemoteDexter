package com.remotedexter.bootstrap18

import org.json.JSONObject

/**
 * The pairing invites, and a strict decoder.
 *
 * **This file holds v4 AND v5 deliberately.** Their canonical encoders must be
 * read together — they are the halves of a format that fails silently when they
 * disagree, and the Rust side keeps them in one file for the same reason
 * (`crates/pairing/src/invite.rs`).
 *
 * ## v5 is not "v4 but newer"
 *
 * Both are current. The number names the ROUTE. A host bound to an interface
 * emits v4, carrying `addr` and `port`. A host that dialled out to a relay emits
 * v5, carrying `relay_addr`, `relay_port` and the `session` id the relay issued
 * — and no host address at all, because there is none.
 *
 * The v4 pairing invite, and a strict decoder that also accepts v3.
 *
 * ## What changed from v3, and why
 *
 * * **`kind` is required.** A QR that is valid JSON but not a pairing invite —
 *   most plausibly the app's own download link — is now named as such instead
 *   of collapsing into "Invalid QR". Two full test rounds were lost to that
 *   ambiguity once already.
 * * **`expires_at` and `capabilities` are signed.** v3 signed neither, so an
 *   invite's lifetime could be extended and a view-only grant widened to
 *   control without breaking the signature.
 * * **`wan_ip` is gone.** The host used to discover it by opening a UDP socket
 *   to `8.8.8.8:80`, disclosing the timing of every invitation to a third
 *   party. The client fell back off it anyway.
 * * **`security_policy` is gone.** It advertised `allowed_transports` including
 *   `bluetooth` and `usb`, neither of which existed.
 *
 * ## One version back, strictly
 *
 * A v3 invite is decoded into [Decoded.V3] and verified against **v3's**
 * canonical bytes. It is never re-signed or promoted to v4. That is what
 * "strict one-version-back" means: old invites still work, old *rules* still
 * apply to them, and nothing in between is invented.
 */
data class InviteV4(
    val kind: String,
    val version: Int,
    val protocol: String,
    val addr: String,
    val port: Int,
    val token: String,
    val nonce: String,
    val expiresAt: Long,
    val capabilities: List<String>,
    val hostPubkey: String,
    val hostIdentityPubkey: String,
    val signature: String
)

/**
 * The v5 pairing invite: a host reached THROUGH A RELAY.
 *
 * The relay splices ciphertext and is never trusted — [hostPubkey] is still the
 * pinned Noise key and the handshake still runs end to end through the splice,
 * so a relay that substituted itself would fail it.
 */
data class InviteV5(
    val kind: String,
    val version: Int,
    val protocol: String,
    val relayAddr: String,
    val relayPort: Int,
    val session: String,
    val token: String,
    val nonce: String,
    val expiresAt: Long,
    val capabilities: List<String>,
    val hostPubkey: String,
    val hostIdentityPubkey: String,
    val signature: String
)

/** A v3 invite, kept for one migration release. */
data class InviteV3(
    val addr: String,
    val port: Int,
    val token: String,
    val nonce: String,
    val protocol: String,
    val wanIp: String,
    val hostPubkey: String,
    val hostIdentityPubkey: String,
    val signature: String
)

/** Outcome of decoding scanned QR text. */
sealed class Decoded {
    /** A host reached through a relay. */
    data class V5(val invite: InviteV5) : Decoded()
    /** A host bound to an interface. */
    data class V4(val invite: InviteV4) : Decoded()
    /** One version back. */
    data class V3(val invite: InviteV3) : Decoded()

    /** Not JSON at all — a URL, a wifi config, a random barcode. */
    object NotJson : Decoded()
    /** JSON, but not a pairing invite. [found] is what `kind` said. */
    data class WrongKind(val found: String) : Decoded()
    /** A version this build does not decode. */
    data class UnsupportedVersion(val found: Int) : Decoded()
    /** A required field was missing. */
    data class Malformed(val field: String) : Decoded()
    /**
     * A field contains the canonical separator, so the bytes it would be signed
     * as are ambiguous. See [InviteDecoder.fieldCarriesSeparator].
     */
    data class SeparatorInField(val field: String) : Decoded()
}

object InviteDecoder {

    const val INVITE_KIND = "remotedexter-pair"

    /** The invite schema for a host BOUND to an interface. */
    const val INVITE_VERSION = 4

    /**
     * The invite schema for a host reached THROUGH A RELAY.
     *
     * Not a successor to [INVITE_VERSION] — see the file header.
     */
    const val RELAY_INVITE_VERSION = 5

    const val LEGACY_INVITE_VERSION = 3

    /** The character that separates fields in the canonical encoding. */
    const val CANONICAL_SEPARATOR = '\n'

    /**
     * Whether a field would break the canonical encoding by containing the
     * separator.
     *
     * **Mirrors `pairing::invite::field_carries_separator`.** Joining fields
     * with `\n` is only injective while no field contains one: two ADJACENT
     * free-form fields can be re-split so that a different invite encodes to
     * identical bytes, and one signature would cover both. No host emits such a
     * field, so this is not a live attack — it is refused anyway, because the
     * safety of a signing format should not rest on an argument about what the
     * other side happens to produce.
     */
    fun fieldCarriesSeparator(value: String): Boolean = value.contains(CANONICAL_SEPARATOR)

    /**
     * Decode scanned QR text. Mirrors `pairing::decode` on the Rust side,
     * including which refusals are distinguishable from which.
     */
    fun decode(text: String): Decoded {
        val obj = try {
            JSONObject(text)
        } catch (e: Exception) {
            return Decoded.NotJson
        }

        return when (val version = obj.optInt("version", LEGACY_INVITE_VERSION)) {
            INVITE_VERSION -> decodeV4(obj)
            RELAY_INVITE_VERSION -> decodeV5(obj)
            LEGACY_INVITE_VERSION -> decodeV3(obj)
            else -> Decoded.UnsupportedVersion(version)
        }
    }

    private fun decodeV4(obj: JSONObject): Decoded {
        val kind = obj.optString("kind", "")
        if (kind != INVITE_KIND) return Decoded.WrongKind(kind)

        for (required in listOf(
            "protocol", "addr", "port", "token", "nonce", "expires_at",
            "capabilities", "host_pubkey", "host_identity_pubkey", "signature"
        )) {
            if (!obj.has(required)) return Decoded.Malformed(required)
        }

        val capsArray = obj.optJSONArray("capabilities") ?: return Decoded.Malformed("capabilities")
        val caps = ArrayList<String>(capsArray.length())
        for (i in 0 until capsArray.length()) caps.add(capsArray.getString(i))

        val invite = InviteV4(
            kind = kind,
            version = INVITE_VERSION,
            protocol = obj.getString("protocol"),
            addr = obj.getString("addr"),
            port = obj.getInt("port"),
            token = obj.getString("token"),
            nonce = obj.getString("nonce"),
            expiresAt = obj.getLong("expires_at"),
            capabilities = caps,
            hostPubkey = obj.getString("host_pubkey"),
            hostIdentityPubkey = obj.getString("host_identity_pubkey"),
            signature = obj.getString("signature")
        )

        separatorInField(invite)?.let { return Decoded.SeparatorInField(it) }
        return Decoded.V4(invite)
    }

    private fun decodeV5(obj: JSONObject): Decoded {
        val kind = obj.optString("kind", "")
        if (kind != INVITE_KIND) return Decoded.WrongKind(kind)

        for (required in listOf(
            "protocol", "relay_addr", "relay_port", "session", "token", "nonce",
            "expires_at", "capabilities", "host_pubkey", "host_identity_pubkey", "signature"
        )) {
            if (!obj.has(required)) return Decoded.Malformed(required)
        }

        val capsArray = obj.optJSONArray("capabilities") ?: return Decoded.Malformed("capabilities")
        val caps = ArrayList<String>(capsArray.length())
        for (i in 0 until capsArray.length()) caps.add(capsArray.getString(i))

        val invite = InviteV5(
            kind = kind,
            version = RELAY_INVITE_VERSION,
            protocol = obj.getString("protocol"),
            relayAddr = obj.getString("relay_addr"),
            relayPort = obj.getInt("relay_port"),
            session = obj.getString("session"),
            token = obj.getString("token"),
            nonce = obj.getString("nonce"),
            expiresAt = obj.getLong("expires_at"),
            capabilities = caps,
            hostPubkey = obj.getString("host_pubkey"),
            hostIdentityPubkey = obj.getString("host_identity_pubkey"),
            signature = obj.getString("signature")
        )

        separatorInField(invite)?.let { return Decoded.SeparatorInField(it) }
        return Decoded.V5(invite)
    }

    /** The first field that would break the canonical encoding, if any. */
    private fun separatorInField(i: InviteV5): String? {
        for ((name, value) in listOf(
            "kind" to i.kind,
            "protocol" to i.protocol,
            "relay_addr" to i.relayAddr,
            "session" to i.session,
            "token" to i.token,
            "nonce" to i.nonce,
            "host_pubkey" to i.hostPubkey
        )) {
            if (fieldCarriesSeparator(value)) return name
        }
        return if (i.capabilities.any { fieldCarriesSeparator(it) }) "capabilities" else null
    }

    /** The first field that would break the canonical encoding, if any. */
    private fun separatorInField(i: InviteV4): String? {
        for ((name, value) in listOf(
            "kind" to i.kind,
            "protocol" to i.protocol,
            "addr" to i.addr,
            "token" to i.token,
            "nonce" to i.nonce,
            "host_pubkey" to i.hostPubkey
        )) {
            if (fieldCarriesSeparator(value)) return name
        }
        return if (i.capabilities.any { fieldCarriesSeparator(it) }) "capabilities" else null
    }

    private fun decodeV3(obj: JSONObject): Decoded {
        // v3 has no `kind`; requiring one would refuse every invite from the
        // release this migration exists to support.
        //
        // `lan_ip` with a `host_ip` fallback: builds before March 2026 emitted
        // the latter. Dropping it silently breaks pairing against a host the
        // user already owns.
        val addr = when {
            obj.has("lan_ip") -> obj.getString("lan_ip")
            obj.has("host_ip") -> obj.getString("host_ip")
            else -> return Decoded.Malformed("lan_ip")
        }
        for (required in listOf("port", "session_token", "host_pubkey", "host_identity_pubkey", "signature")) {
            if (!obj.has(required)) return Decoded.Malformed(required)
        }
        return Decoded.V3(
            InviteV3(
                addr = addr,
                port = obj.getInt("port"),
                token = obj.getString("session_token"),
                nonce = obj.optString("nonce", ""),
                protocol = obj.optString("protocol", "rdv3"),
                wanIp = obj.optString("wan_ip", ""),
                hostPubkey = obj.getString("host_pubkey"),
                hostIdentityPubkey = obj.getString("host_identity_pubkey"),
                signature = obj.getString("signature")
            )
        )
    }

    /**
     * The exact bytes a v4 signature covers.
     *
     * **Must match `pairing::invite::canonical_bytes` in Rust byte for byte** —
     * same fields, same order, same `\n` separator, same UTF-8, capabilities
     * joined with `,` in the order given. Divergence fails silently: every
     * signature simply stops verifying, on a phone, with both sides' own tests
     * green. `contract/signed_invite_v4.json` is what catches it here instead.
     *
     * Field order is load-bearing and is not alphabetical. Do not tidy it.
     */
    fun canonicalBytesV4(i: InviteV4): ByteArray =
        listOf(
            i.kind,
            i.version.toString(),
            i.protocol,
            i.addr,
            i.port.toString(),
            i.token,
            i.nonce,
            i.expiresAt.toString(),
            i.capabilities.joinToString(","),
            i.hostPubkey
        ).joinToString("\n").toByteArray(Charsets.UTF_8)

    /**
     * The exact bytes a v5 signature covers.
     *
     * **Must match `pairing::invite::relay_canonical_bytes` in Rust byte for
     * byte** — same fields, same order, same `\n` separator, same UTF-8,
     * capabilities joined with `,` in the order given. Divergence fails
     * silently: every signature simply stops verifying, on a phone, with both
     * sides' own tests green. `contract/signed_invite_v5.json` is what catches
     * it here instead.
     *
     * Field order is load-bearing and is not alphabetical. Do not tidy it.
     *
     * `session` sits with `relayAddr` and `relayPort` because the three
     * together are "where to connect and what to ask for", signed as a unit.
     */
    fun canonicalBytesV5(i: InviteV5): ByteArray =
        listOf(
            i.kind,
            i.version.toString(),
            i.protocol,
            i.relayAddr,
            i.relayPort.toString(),
            i.session,
            i.token,
            i.nonce,
            i.expiresAt.toString(),
            i.capabilities.joinToString(","),
            i.hostPubkey
        ).joinToString("\n").toByteArray(Charsets.UTF_8)

    /** True when the v5 invite has already expired at [nowEpochSeconds]. */
    fun isExpired(i: InviteV5, nowEpochSeconds: Long): Boolean = nowEpochSeconds >= i.expiresAt

    /** v3's canonical bytes, reproduced exactly as the old host produced them. */
    fun canonicalBytesV3(i: InviteV3): ByteArray =
        listOf(
            i.nonce,
            i.token,
            i.addr,
            i.wanIp,
            i.port.toString(),
            i.protocol,
            LEGACY_INVITE_VERSION.toString(),
            i.hostPubkey
        ).joinToString("\n").toByteArray(Charsets.UTF_8)

    /** True when the invite has already expired at [nowEpochSeconds]. */
    fun isExpired(i: InviteV4, nowEpochSeconds: Long): Boolean = nowEpochSeconds >= i.expiresAt
}
