package com.remotedexter

import android.content.Context
import com.remotedexter.bootstrap18.HostIdentityTrust

/**
 * Every host this device is paired with, and which one Connect uses.
 *
 * Replaces the pair of single-value stores it is built on top of: the identity
 * lived in [HostIdentityTrust] and the address/port/pin lived in
 * [PairedHostStore], with nothing joining them. See [PairedHostRecord] for why
 * they had to become one thing.
 *
 * Kept in its own `SharedPreferences` file so clearing pairings cannot disturb
 * unrelated settings. Nothing secret is stored — an address, a port, and two
 * public keys.
 *
 * ## Forgetting one host is not unpairing this device
 *
 * A distinction that did not exist while there was one host, and the reason
 * this class is careful about the difference. The device's own Noise identity
 * — the key the HOST enrolls and recognises — is one key shared by every
 * pairing. So:
 *
 * - [forget] drops one host's record. The device identity is untouched and
 *   every other pairing keeps working.
 * - Unpairing the device entirely is still [DeviceUnpair.forgetEverything],
 *   which drops the device identity as well, and therefore must clear ALL
 *   records — a device identity that is gone cannot be recognised by any host,
 *   so a record left behind would be an offer to reconnect somewhere that will
 *   refuse.
 *
 * Getting that backwards in either direction is a real defect: forgetting one
 * host silently breaking the others, or "unpair" leaving an identity the host
 * still accepts.
 */
class PairedHostRegistry(context: Context) {

    private val app = context.applicationContext
    private val prefs = app.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    init {
        migrateLegacyPairingIfNeeded()
    }

    /** Every paired host, in the order they were added. */
    fun all(): List<PairedHostRecord> = PairedHostCodec.decode(prefs.getString(KEY_RECORDS, null))

    /** Every identity this device trusts. What [InviteTrustPolicy] is given. */
    fun trustedIdentities(): Set<String> = all().map { it.identityB64 }.toSet()

    /**
     * The host Connect targets, or null when there is none.
     *
     * Falls back to the first record when the stored pointer names a host that
     * is no longer there — which is what forgetting the active host leaves
     * behind. The alternative is a phone with pairings and a Connect button
     * that refuses, and the user has no way to see why.
     */
    fun active(): PairedHostRecord? {
        val records = all()
        if (records.isEmpty()) return null
        val wanted = prefs.getString(KEY_ACTIVE, null)
        return records.firstOrNull { it.identityB64 == wanted } ?: records.first()
    }

    /** Point Connect at a host. False if this device is not paired with it. */
    fun setActive(identityB64: String): Boolean {
        if (all().none { it.identityB64 == identityB64 }) return false
        prefs.edit().putString(KEY_ACTIVE, identityB64).apply()
        return true
    }

    /**
     * Remember a host we have actually connected to, and make it active.
     *
     * Call only once the handshake has reported `connected` — the point at
     * which the host has accepted the pairing token and enrolled this device's
     * key. Before it, the phone would be offering to reconnect to a host that
     * has never heard of it, and every attempt would be refused with no way for
     * the user to tell that from a network fault.
     *
     * Re-adding a host that is already known REPLACES its record rather than
     * appending a second one. A host whose DHCP lease moved presents the same
     * identity at a new address, and that is an update, not a new machine.
     */
    fun remember(record: PairedHostRecord?) {
        if (record == null) {
            RdxLog.w(TAG, "refusing to remember a malformed host record")
            return
        }
        val kept = all().filterNot { it.identityB64 == record.identityB64 }
        prefs.edit()
            .putString(KEY_RECORDS, PairedHostCodec.encode(kept + record))
            .putString(KEY_ACTIVE, record.identityB64)
            .apply()
        RdxLog.i(TAG, "paired host ${record.label()} (${record.fingerprint()}…) is now active")
    }

    /**
     * Drop one host. Idempotent; returns whether anything was there.
     *
     * The device's own identity is deliberately NOT touched — see the class
     * note. Other pairings keep working.
     */
    fun forget(identityB64: String): Boolean {
        val before = all()
        val after = before.filterNot { it.identityB64 == identityB64 }
        if (after.size == before.size) return false
        prefs.edit().putString(KEY_RECORDS, PairedHostCodec.encode(after)).apply()
        RdxLog.i(TAG, "forgot one paired host; ${after.size} remain")
        return true
    }

    /** Drop every host. Used by the full device unpair, not by the UI's Forget. */
    fun forgetAll() {
        prefs.edit().remove(KEY_RECORDS).remove(KEY_ACTIVE).apply()
        RdxLog.i(TAG, "forgot every paired host")
    }

    /**
     * Adopt a pairing written by a build that could only hold one.
     *
     * Runs once and records that it ran. The legacy keys are left in place
     * rather than deleted: if this migration is wrong, nothing has been
     * destroyed, and the flag is what stops a forgotten host from being
     * resurrected on the next launch.
     *
     * Joining the two legacy values into one record is safe **because the old
     * code wrote and cleared them together** — there was only ever one pairing
     * they could belong to. That guarantee is exactly what stops holding once
     * there are several, which is why they are being joined now.
     */
    private fun migrateLegacyPairingIfNeeded() {
        if (prefs.getBoolean(KEY_MIGRATED, false)) return
        prefs.edit().putBoolean(KEY_MIGRATED, true).apply()
        if (!prefs.getString(KEY_RECORDS, null).isNullOrEmpty()) return

        val identity = HostIdentityTrust(app).trustedIdentity() ?: return
        val host = PairedHostStore(app).stored() ?: return
        val record = PairedHostRecord.of(identity, host.addr, host.port, host.pinHex) ?: return
        prefs.edit()
            .putString(KEY_RECORDS, PairedHostCodec.encode(listOf(record)))
            .putString(KEY_ACTIVE, record.identityB64)
            .apply()
        RdxLog.i(TAG, "migrated the single stored pairing (${record.label()}) into the host list")
    }

    private companion object {
        const val TAG = "PairedHostRegistry"
        const val PREFS_NAME = "paired_hosts"
        const val KEY_RECORDS = "records"
        const val KEY_ACTIVE = "active_identity"
        const val KEY_MIGRATED = "migrated_from_single_host"
    }
}
