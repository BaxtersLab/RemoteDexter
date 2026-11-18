package com.remotedexter.bootstrap18

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.util.Base64

/**
 * Verifies that an invite really came from the host it claims to be.
 *
 * The signature covers [InvitePayload.host_pubkey], so a valid signature is what
 * makes the Noise key pin meaningful — see the note on [InvitePayload].
 */
object InviteSignatureVerifier {

    /** Ed25519 public keys are exactly this long. */
    private const val ED25519_PUBLIC_KEY_BYTES = 32

    /** Ed25519 signatures are exactly this long. */
    private const val ED25519_SIGNATURE_BYTES = 64

    /**
     * The exact bytes the host signs.
     *
     * **This must match `canonical_signing_bytes` in
     * `modules/module17_bootstrap_invite/src/lib.rs` byte for byte** — same
     * fields, same order, same `\n` separator, same UTF-8 encoding. Any
     * divergence makes every signature fail to verify, and it fails *silently*:
     * [SessionStarter] refuses without showing the user anything. If pairing
     * starts rejecting every invite, compare this function against the Rust one
     * before looking anywhere else.
     *
     * Field order is load-bearing and is not alphabetical. Do not "tidy" it.
     *
     * Note the numbers are rendered with `toString()`, i.e. their plain decimal
     * form with no padding — matching Rust's `{port}` / `{version}` formatting.
     */
    fun canonicalBytes(payload: InvitePayload): ByteArray =
        if (payload.version == InviteDecoder.INVITE_VERSION) {
            payload.toV4()?.let(InviteDecoder::canonicalBytesV4) ?: byteArrayOf()
        } else {
            listOf(
                payload.nonce,
                payload.session_token,
                payload.lan_ip,
                payload.wan_ip,
                payload.port.toString(),
                payload.protocol,
                payload.version.toString(),
                payload.host_pubkey
            ).joinToString("\n").toByteArray(Charsets.UTF_8)
        }

    /**
     * True only if [invite] carries an Ed25519 signature that verifies against
     * the identity key it names.
     *
     * The v5 counterpart of [isValid]. Same fail-closed rules throughout, and
     * the same division of labour: this answers "is the signature valid for the
     * key IN the invite", never "should that key be trusted" — which remains
     * [InviteTrustPolicy]'s job, and both checks are required.
     *
     * There is deliberately no path that falls back to [canonicalBytes]: a v5
     * invite verified under v4's encoding would be a downgrade, and the version
     * is inside the signed bytes precisely so that cannot happen quietly.
     */
    /**
     * The v6 counterpart of [isValidV5]: both routes, one signature, verified
     * only under v6's own encoding. Signature validity, never trust — trust is
     * still [InviteTrustPolicy]'s job, and both checks are required.
     */
    fun isValidV6(invite: InviteV6): Boolean =
        isValidFor(
            invite.signature,
            invite.hostIdentityPubkey,
            invite.version == InviteDecoder.DUAL_INVITE_VERSION
        ) { InviteDecoder.canonicalBytesV6(invite) }

    /**
     * The shared, fail-closed body: a blank or wrong-sized key or signature, a
     * version the caller did not expect, or any decoding error is `false`.
     * The canonical bytes are computed only once those checks pass.
     */
    private fun isValidFor(
        signature: String,
        identity: String,
        versionMatches: Boolean,
        canonical: () -> ByteArray
    ): Boolean {
        if (signature.isBlank() || identity.isBlank() || !versionMatches) return false
        return try {
            val publicKeyBytes = Base64.getDecoder().decode(identity)
            val signatureBytes = Base64.getDecoder().decode(signature)
            if (publicKeyBytes.size != ED25519_PUBLIC_KEY_BYTES ||
                signatureBytes.size != ED25519_SIGNATURE_BYTES
            ) {
                return false
            }
            val message = canonical()
            val verifier = Ed25519Signer().apply {
                init(false, Ed25519PublicKeyParameters(publicKeyBytes, 0))
                update(message, 0, message.size)
            }
            verifier.verifySignature(signatureBytes)
        } catch (e: Exception) {
            false
        }
    }

    fun isValidV5(invite: InviteV5): Boolean {
        if (invite.signature.isBlank() || invite.hostIdentityPubkey.isBlank()) {
            return false
        }
        if (invite.version != InviteDecoder.RELAY_INVITE_VERSION) {
            return false
        }
        return try {
            val publicKeyBytes = Base64.getDecoder().decode(invite.hostIdentityPubkey)
            val signatureBytes = Base64.getDecoder().decode(invite.signature)
            if (publicKeyBytes.size != ED25519_PUBLIC_KEY_BYTES ||
                signatureBytes.size != ED25519_SIGNATURE_BYTES
            ) {
                return false
            }
            val message = InviteDecoder.canonicalBytesV5(invite)
            val verifier = Ed25519Signer().apply {
                init(false, Ed25519PublicKeyParameters(publicKeyBytes, 0))
                update(message, 0, message.size)
            }
            verifier.verifySignature(signatureBytes)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * True only if [payload] carries an Ed25519 signature that verifies against
     * the identity key it names.
     *
     * Fail-closed throughout: a missing signature, a missing identity key, a
     * wrong-length key or signature, malformed base64, or any exception from the
     * verifier all return false. There is no path where an unverifiable invite
     * is treated as verified.
     *
     * This answers only "is the signature valid for the key *in the invite*". It
     * says nothing about whether that key should be trusted — an attacker can
     * sign their own invite with their own key perfectly well. Deciding whether
     * the identity is the *expected* one is [InviteTrustPolicy]'s job, and both
     * checks are required.
     *
     * Uses the standard base64 alphabet with padding (`java.util.Base64`, API
     * 26+), matching the Rust host's `base64::engine::general_purpose::STANDARD`.
     * URL-safe base64 will not decode here.
     */
    fun isValid(payload: InvitePayload): Boolean {
        if (payload.signature.isBlank() || payload.host_identity_pubkey.isBlank()) {
            return false
        }

        return try {
            val publicKeyBytes = Base64.getDecoder().decode(payload.host_identity_pubkey)
            val signatureBytes = Base64.getDecoder().decode(payload.signature)

            if (publicKeyBytes.size != ED25519_PUBLIC_KEY_BYTES ||
                signatureBytes.size != ED25519_SIGNATURE_BYTES
            ) {
                return false
            }

            val message = canonicalBytes(payload)
            val verifier = Ed25519Signer().apply {
                init(false, Ed25519PublicKeyParameters(publicKeyBytes, 0))
                update(message, 0, message.size)
            }
            verifier.verifySignature(signatureBytes)
        } catch (e: Exception) {
            false
        }
    }
}
