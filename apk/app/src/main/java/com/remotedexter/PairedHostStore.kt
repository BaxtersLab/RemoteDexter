package com.remotedexter

import android.content.Context

/**
 * Persists the one host this device can reconnect to without a QR.
 *
 * One host, like [com.remotedexter.bootstrap18.HostIdentityTrust] — the two are
 * halves of the same pairing and are written and cleared together. Kept in its
 * own `SharedPreferences` file so clearing a pairing cannot disturb unrelated
 * settings, and so a corrupt or partial record here can never be mistaken for a
 * trusted identity there.
 *
 * Nothing secret is stored; see [PairedHost].
 */
class PairedHostStore(context: Context) {

    private val prefs =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * The stored host, or null if there is nothing usable.
     *
     * Re-validated through [PairedHost.of] on every read rather than trusted
     * because it was validated on write. Preferences survive app upgrades,
     * downgrades and restores from backup, so "we wrote it, therefore it is
     * well-formed" is an assumption about a file this code did not necessarily
     * write. A record that no longer passes is treated as absent, which fails
     * closed: the user is asked to scan.
     */
    fun stored(): PairedHost? {
        val addr = prefs.getString(KEY_ADDR, null) ?: return null
        val pin = prefs.getString(KEY_PIN, null) ?: return null
        return PairedHost.of(addr, prefs.getInt(KEY_PORT, 0), pin)
    }

    /**
     * Remember a host we have actually connected to.
     *
     * Call only once the handshake has reported `connected`. That is the point
     * at which the host has accepted the pairing token and enrolled this
     * device's key — before it, the phone would be offering to reconnect to a
     * host that has never heard of it, and every attempt would be refused with
     * no way for the user to tell that from a network fault.
     *
     * Refuses to store an invalid record rather than storing it and failing at
     * connect time.
     */
    fun remember(host: PairedHost?) {
        if (host == null) {
            RdxLog.w(TAG, "refusing to remember a malformed host record")
            return
        }
        prefs.edit()
            .putString(KEY_ADDR, host.addr)
            .putInt(KEY_PORT, host.port)
            .putString(KEY_PIN, host.pinHex)
            .apply()
        RdxLog.i(TAG, "remembered host ${host.addr}:${host.port} for reconnect")
    }

    /** Drop the reconnect target. Idempotent. */
    fun forget() {
        prefs.edit().remove(KEY_ADDR).remove(KEY_PORT).remove(KEY_PIN).apply()
    }

    private companion object {
        const val TAG = "PairedHostStore"
        const val PREFS_NAME = "paired_host"
        const val KEY_ADDR = "addr"
        const val KEY_PORT = "port"
        const val KEY_PIN = "host_noise_pin_hex"
    }
}
