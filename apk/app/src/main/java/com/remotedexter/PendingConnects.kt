package com.remotedexter

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Connection requests waiting to be picked up by the service, keyed by an
 * opaque in-process id.
 *
 * ## Why an id instead of the invite
 *
 * `RDService` is started with an `Intent`. Intent extras are not a private
 * channel: they are visible to anything that can observe the start, they land
 * in system logs and bug reports, and they persist in `ActivityManager`'s
 * recent-task state. A pairing token in an extra is a bearer credential written
 * somewhere neither the app nor the user controls.
 *
 * So the intent carries a random 128-bit id and nothing else. The invite —
 * including its one-use token — stays in this process-memory map, and the
 * service exchanges the id for it exactly once.
 */
/**
 * A parked invite, tagged by the route it names.
 *
 * ONE store, not one per route. The one-shot guarantee is the point of this
 * object, and two maps would be two stores with two chances to get it wrong.
 */
sealed class PendingInvite {
    /** A host listening on an address. */
    data class Direct(val invite: com.remotedexter.bootstrap18.InviteV4) : PendingInvite()

    /** A host reached through a relay. */
    data class ViaRelay(val invite: com.remotedexter.bootstrap18.InviteV5) : PendingInvite()
}

object PendingConnects {

    private val random = SecureRandom()
    private val pending = ConcurrentHashMap<String, PendingInvite>()

    /** Extra key for the opaque id. Carries an id, never a credential. */
    const val EXTRA_REQUEST_ID = "com.remotedexter.REQUEST_ID"

    /** Action for a deliberate, user-initiated connection. */
    const val ACTION_CONNECT = "com.remotedexter.action.CONNECT"

    /**
     * Action for a deliberate reconnect to the already-paired host.
     *
     * Carries no extras at all — not even an id. There is no invite and no
     * token to park: the destination comes from [PairedHostStore] and the
     * credential is the device's own Noise key, which never leaves native code.
     * A replayed copy of this intent can therefore do nothing an unreplayed one
     * could not, which is why it needs none of [ACTION_CONNECT]'s one-shot
     * machinery.
     */
    const val ACTION_RECONNECT = "com.remotedexter.action.RECONNECT"

    /** Action for a deliberate disconnect. */
    const val ACTION_DISCONNECT = "com.remotedexter.action.DISCONNECT"

    /** Park a direct invite and return the opaque id that stands for it. */
    fun submit(invite: com.remotedexter.bootstrap18.InviteV4): String =
        park(PendingInvite.Direct(invite))

    /** Park a relay invite and return the opaque id that stands for it. */
    fun submitRelay(invite: com.remotedexter.bootstrap18.InviteV5): String =
        park(PendingInvite.ViaRelay(invite))

    private fun park(invite: PendingInvite): String {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        val id = bytes.joinToString("") { "%02x".format(it) }
        pending[id] = invite
        return id
    }

    /**
     * Exchange an id for its invite, **once**.
     *
     * One-shot for the same reason the token is: a request that could be
     * redeemed twice would let a replayed intent start a second session from
     * one user action.
     */
    fun take(id: String?): PendingInvite? =
        if (id == null) null else pending.remove(id)

    /** Drop everything pending. Called when the app returns to Idle. */
    fun clear() = pending.clear()

    /** How many requests are parked. For tests and diagnostics. */
    fun size(): Int = pending.size
}
