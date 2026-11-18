package com.remotedexter

/**
 * How long the app waits for a session to connect before giving up, by route.
 *
 * Found 2026-09-19 on the operator's phone: a paired reconnect through the relay
 * connected 10.9 s after it began, and the app had given up at 10.0 s ("timed out
 * waiting for the host to connect") — a working session was thrown away 7 ms
 * after it arrived, and the operator saw "session failed". One ceiling of 10 s
 * had been chosen for the LAN, where it means "nothing is answering". Through
 * the relay the host has to be told, dial back, and complete the pinned
 * handshake across two hops, and the relay itself gives the host 15 s
 * (`ATTACH_TTL`) to dial back — so the app was giving up before the relay did.
 *
 * Kept apart from SessionOrchestrator so a plain JVM test can hold it.
 */
object ConnectCeiling {
    /** LAN: nothing answering in 10 s is a host that is not there. */
    const val LAN_MS = 10_000L

    /**
     * Relay: the relay's 15 s wait for the host to dial back, plus room for the
     * handshake on a congested link. `host_app`'s relay_dial tests hold this
     * above the relay crate's ATTACH_TTL, so the two cannot drift apart again.
     */
    const val RELAY_MS = 30_000L

    fun forRoute(viaRelay: Boolean): Long = if (viaRelay) RELAY_MS else LAN_MS

    /** Poll attempts that fill the route's ceiling at [pollMs] each. */
    fun tries(viaRelay: Boolean, pollMs: Long): Int =
        (forRoute(viaRelay) / pollMs).toInt().coerceAtLeast(1)
}
