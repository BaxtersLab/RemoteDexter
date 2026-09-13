package com.remotedexter.bootstrap18

import android.content.Context

/**
 * Persists the host identity this device has paired with.
 *
 * One host per device, stored as the base64 Ed25519 identity key. Backed by
 * `SharedPreferences` under a dedicated file so clearing pairing state cannot
 * disturb unrelated settings.
 *
 * Only a *public* key is stored here — nothing secret. The value is not
 * confidential; what matters is that it cannot be changed without the user
 * knowing, since silently overwriting it would defeat the whole
 * trust-on-first-use model in [InviteTrustPolicy].
 */
class HostIdentityTrust(context: Context) {

    private val prefs =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** The stored identity, or null if this device has never paired. */
    fun trustedIdentity(): String? = prefs.getString(KEY_TRUSTED_IDENTITY, null)

    /**
     * Adopt [identityPubKeyB64] as the trusted host.
     *
     * Call this only after [InviteTrustPolicy] returns
     * [InviteTrustResult.Accepted] *and* no identity is stored yet. Calling it
     * on a rejected invite would overwrite the good identity with an attacker's
     * and permanently disable the substitution check.
     */
    fun trust(identityPubKeyB64: String) {
        prefs.edit().putString(KEY_TRUSTED_IDENTITY, identityPubKeyB64).apply()
    }

    /**
     * Forget the paired host so the next invite is trusted on first use again.
     *
     * This is the deliberate escape hatch for a legitimate host re-key, and it
     * is why [InviteTrustResult.RejectedIdentityChanged] refuses instead of
     * re-pairing automatically — the reset is a user decision, not an
     * inference.
     */
    fun forget() {
        prefs.edit().remove(KEY_TRUSTED_IDENTITY).apply()
    }

    private companion object {
        const val PREFS_NAME = "host_identity_trust"
        const val KEY_TRUSTED_IDENTITY = "trusted_host_identity_pubkey_b64"
    }
}
