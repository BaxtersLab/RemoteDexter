package com.remotedexter

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The app gives a relayed connection long enough to arrive.
 *
 * 2026-09-19: a paired reconnect through the relay connected at 10.9 s, the app
 * had given up at 10.0 s, and the operator saw "session failed" for a session
 * that worked. The LAN keeps its 10 s — there it means nothing is answering.
 */
class ConnectCeilingTest {

    @Test
    fun theRelayIsGivenLongerThanTheRelayGivesTheHost() {
        // The relay waits 15 s (ATTACH_TTL) for the host to dial back; the
        // pinned handshake then crosses two hops. host_app's relay_dial tests
        // hold RELAY_MS against the relay crate's real constant.
        assertTrue(
            "a relayed connect is abandoned after ${ConnectCeiling.RELAY_MS} ms",
            ConnectCeiling.forRoute(viaRelay = true) >= 25_000L
        )
        assertTrue(ConnectCeiling.forRoute(viaRelay = true) > ConnectCeiling.forRoute(viaRelay = false))
    }

    @Test
    fun theLanKeepsItsTenSeconds() {
        assertEquals(10_000L, ConnectCeiling.forRoute(viaRelay = false))
    }

    @Test
    fun theCeilingIsFilledByPollsAtTheWatchersCadence() {
        assertEquals(40, ConnectCeiling.tries(viaRelay = false, pollMs = 250L))
        assertEquals(120, ConnectCeiling.tries(viaRelay = true, pollMs = 250L))
        assertEquals("never zero attempts", 1, ConnectCeiling.tries(viaRelay = false, pollMs = 60_000L))
    }

    /**
     * **Each way of connecting tells the watcher which route it is on.** The
     * ceiling above is only right if the relay paths ask for it: the 2026-09-19
     * failure was a paired RELAY reconnect, and a call site that said LAN
     * would bring it back with every test above still green.
     *
     * This reads source text, as [SecureWindowTest] does; the three paths start
     * native sessions, which a JVM test cannot run. Editing a call site changes
     * the compiled classes, so Gradle does not replay an old pass.
     */
    @Test
    fun everyConnectPathNamesItsOwnRoute() {
        val source = File("src/main/java/com/remotedexter/SessionOrchestrator.kt").readText()
        fun body(name: String): String {
            val start = source.indexOf("    fun $name(")
            assertTrue("SessionOrchestrator has no $name", start >= 0)
            val end = source.indexOf("\n    fun ", start + 1).let { if (it < 0) source.length else it }
            return source.substring(start, end)
        }
        val expected = mapOf(
            "beginRelayConnect" to "watch(context, viaRelay = true)",
            "beginConnect" to "watch(context, viaRelay = false)",
            "beginReconnect" to "watch(context, viaRelay = route is PairedHostRecord.Reconnect.ViaRelay)"
        )
        for ((name, call) in expected) {
            val text = body(name)
            assertEquals("$name must start the watcher exactly once", 1, Regex("""\bwatch\(""").findAll(text).count())
            assertTrue("$name does not pass its own route: expected `$call`", text.contains(call))
        }
        assertEquals(
            "a new caller of watch() must be added here with its route",
            expected.size + 1, // the three callers and watch's own declaration
            Regex("""\bwatch\(""").findAll(source).count()
        )
    }
}
