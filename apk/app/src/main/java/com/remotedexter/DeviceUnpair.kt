package com.remotedexter

import android.content.Context
import com.remotedexter.bootstrap18.HostIdentityTrust

/**
 * The one place that knows everything a pairing consists of.
 *
 * ## The defect this fixes
 *
 * A pairing is four things, and "unpair" used to clear one of them. Both UI
 * paths — Diagnostics → Unpair, and the identity-mismatch sheet — called
 * `HostIdentityTrust.forget()` and stopped there. That clears the *pin*, which
 * is the weaker half, and leaves behind:
 *
 * - the device's own Noise identity, which is what the host actually keys on.
 *   The host still had this phone enrolled and would still accept a token-less
 *   reconnect from it;
 * - the stored reconnect target.
 *
 * So a user who unpaired a phone was told it was unpaired while the host would
 * still let it in. Worse, it is precisely the order [ForgetPairing] documents as
 * unsafe: pin gone, identity kept, so the next QR scan re-pairs silently to the
 * *same* enrolled record rather than being seen as a new device.
 *
 * ## Order
 *
 * [ForgetPairing] owns it and is tested on the JVM: identity first, because it
 * is the half the host recognises, and both attempted even if the first fails.
 * This object supplies the Android-side actions and nothing more, which is what
 * keeps that ordering testable without a device.
 */
object DeviceUnpair {

    private const val TAG = "DeviceUnpair"

    /**
     * Undo the pairing completely.
     *
     * @return true only when this device's own identity really went. False
     *   means the host may still recognise this phone, so the caller must not
     *   report a clean unpair — the remedy then is to revoke the device at the
     *   host, which is the lever that does not depend on this one working.
     */
    fun forgetEverything(context: Context): Boolean {
        val app = context.applicationContext
        val identityGone = ForgetPairing.forget(
            forgetIdentity = { TransportBindings.rd_forget_identity() },
            forgetHostPin = {
                // EVERY host, not one. This path also drops the device's own
                // Noise identity, which is a single key shared by every
                // pairing — once it is gone no host recognises this phone, so
                // a record left behind would be an offer to reconnect
                // somewhere that will refuse. Forgetting ONE host is
                // PairedHostRegistry.forget, which deliberately leaves the
                // device identity alone.
                PairedHostRegistry(app).forgetAll()
                // The superseded single-host stores. Cleared too, so an unpair
                // leaves nothing behind for the migration to resurrect.
                HostIdentityTrust(app).forget()
                PairedHostStore(app).forget()
            }
        )
        if (identityGone) {
            RdxLog.i(TAG, "unpaired: device identity, host pin and reconnect target cleared")
        } else {
            RdxLog.e(
                TAG,
                "unpair INCOMPLETE: host pin and reconnect target cleared, but this " +
                    "device's identity could not be removed — the host may still " +
                    "recognise this phone. Revoke it at the host."
            )
        }
        return identityGone
    }
}
