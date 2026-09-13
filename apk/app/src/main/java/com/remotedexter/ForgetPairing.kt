package com.remotedexter

/**
 * Undo a pairing from this phone's side.
 *
 * Block 9 requires that "host revocation and Android Forget fully prevent
 * future reconnects". Those are two independent levers and both exist: the
 * owner can revoke a device at the host, and the device can renounce itself
 * here. Either alone is enough to stop a reconnect; a phone that is lost needs
 * the host-side one, because nobody will be pressing buttons on the phone.
 *
 * Two things have to go:
 *
 * 1. **This device's own Noise identity** — what the host keys on. Without it
 *    the next connection presents a new key and is refused as unknown.
 * 2. **The trusted host key** — the pin. Without it the phone will not connect
 *    to that host again without a fresh signed QR.
 *
 * Pure of Android types on purpose: the two actions arrive as lambdas so the
 * ORDER, and what happens when one fails, are testable on the JVM.
 */
object ForgetPairing {

    /**
     * Forget, identity first.
     *
     * The identity is cleared **before** the host pin, because it is the
     * stronger of the two: it is what the host recognises. If the order were
     * reversed and the process died in between, the phone would be left with an
     * identity the host still knows and no pin — which re-pairs silently to the
     * same enrolled record on the next QR scan.
     *
     * Both are attempted even when the first fails, because clearing the pin
     * still forces a fresh QR. The return value is `true` only when the
     * identity really went, so a caller must not tell the owner they are
     * unpaired when the host would still recognise this phone.
     */
    fun forget(forgetIdentity: () -> Boolean, forgetHostPin: () -> Unit): Boolean {
        val identityGone = try {
            forgetIdentity()
        } catch (_: Throwable) {
            // A native failure must not leave the pin behind as well.
            false
        }
        forgetHostPin()
        return identityGone
    }
}
