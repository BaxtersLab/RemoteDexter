package com.remotedexter

/**
 * What the status line says when nothing is running.
 *
 * # Why "Not connected" was not enough
 *
 * The idle line said "Not connected" whether or not a host was remembered, so
 * the screen looked identical in two states that need different actions: one
 * wants a QR, the other wants Connect. The operator hit exactly this — a greyed
 * Connect button with no explanation of what would un-grey it — and read it as
 * a broken control rather than a missing pairing.
 *
 * Block 11 asks for a home that "lists paired hosts by user name plus
 * fingerprint suffix and last status". This is that idea at the size the
 * current single-host store supports: naming the one host we would reconnect
 * to, so the state of the app is legible without pressing anything.
 *
 * # Not a fingerprint
 *
 * The address, not the key. A fingerprint suffix identifies WHICH host among
 * several, which matters once there is a list; with one stored host the address
 * is what tells the operator whether it is the machine in front of them, and it
 * is the thing that actually goes stale when a DHCP lease moves.
 */
object IdleStatus {

    /** What to render on the idle line. */
    sealed class Line {
        /** No pairing stored. The user needs a QR. */
        object NeedsPairing : Line()

        /** A host is remembered and Connect will reach for it. */
        data class Paired(val hostLabel: String) : Line()
    }

    /**
     * Describe the idle state.
     *
     * A blank or missing label is treated as no pairing. A record that cannot
     * name its host cannot be offered as one — "Paired with " followed by
     * nothing is worse than saying there is no pairing, because it invites the
     * user to press a button that will fail.
     */
    fun describe(storedHostLabel: String?): Line =
        if (storedHostLabel.isNullOrBlank()) {
            Line.NeedsPairing
        } else {
            Line.Paired(storedHostLabel)
        }
}
