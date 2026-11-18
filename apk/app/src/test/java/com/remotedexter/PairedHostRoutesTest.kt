package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A paired host reachable on the LAN, through the relay, or both — and the
 * stored format that has to carry that without costing any released phone its
 * pairing.
 *
 * Every test here is on the JVM, deliberately. A device test that wrote the
 * real pairing store would unpair the phone it ran on, and the gate's
 * instrumentation run wipes app data on any attached device as it is.
 */
class PairedHostRoutesTest {

    private val identity = "HostIdentityAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private val other = "HostIdentityBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    private val pinA = "a".repeat(64)
    private val pinB = "b".repeat(64)
    // Shaped like the relay's ids, and distinctive enough to find anywhere.
    private val session = "SeSsIoNiDkEePsEcReT_-1"
    private val freshSession = "FrEsHsEsSiOnAfTeRrEsT2"

    private fun lan(addr: String = "192.168.1.40", pin: String = pinA) =
        PairedHostRecord.of(identity, addr, 8082, pin)!!

    private fun relay(s: String = session, pin: String = pinA) =
        PairedHostRecord.viaRelay(identity, "203.0.113.9", 9443, s, pin)!!

    /**
     * What every released 3.0.13 build reads, kept here as it was so a
     * downgrade is a tested claim rather than an argument. Released decoders
     * keep a line only if it has exactly four fields.
     */
    private fun releasedDecode(text: String): List<String> =
        text.split('\n').filter { it.isNotBlank() && it.split('\t').size == 4 }

    // ── what released phones hold ─────────────────────────────────────────

    /**
     * **Every pairing on every released phone must survive the upgrade.**
     *
     * The line below is the exact shape all eleven 3.0.13 builds write. A
     * decoder that required the new fields would drop it silently, and the
     * phone would show "Scan a QR" to a host that still recognises it.
     */
    @Test
    fun aReleasedLanLineDecodesExactlyAsBefore() {
        val released = "$identity\t192.168.1.40\t8082\t$pinA"
        val decoded = PairedHostCodec.decode(released)
        assertEquals(1, decoded.size)
        val r = decoded.single()
        assertEquals(identity, r.identityB64)
        assertEquals(PairedHost("192.168.1.40", 8082, pinA), r.lan)
        assertNull("a released line grew a relay route", r.relay)
        assertEquals("192.168.1.40:8082", r.label())
        assertEquals("the idle line of a LAN-paired phone changed", "192.168.1.40", r.idleLabel())
        assertTrue(r.reconnectRoute() is PairedHostRecord.Reconnect.Lan)
    }

    /**
     * A LAN-only host is still written as the released line, byte for byte, so
     * installing an older 3.0.13 build over this one keeps it.
     */
    @Test
    fun aLanOnlyHostIsStillWrittenAsTheReleasedLine() {
        assertEquals(
            "$identity\t192.168.1.40\t8082\t$pinA",
            PairedHostCodec.encode(listOf(lan()))
        )
    }

    // ── the relay route ──────────────────────────────────────────────────

    @Test
    fun aRelayPairedHostSurvivesARoundTrip() {
        val records = listOf(relay())
        val decoded = PairedHostCodec.decode(PairedHostCodec.encode(records))
        assertEquals(records, decoded)
        val route = decoded.single().reconnectRoute()
        assertTrue(route is PairedHostRecord.Reconnect.ViaRelay)
        route as PairedHostRecord.Reconnect.ViaRelay
        assertEquals(session, route.route.session)
        assertEquals(9443, route.route.relayPort)
        assertEquals("relay 203.0.113.9:9443", decoded.single().label())
    }

    /**
     * **A host paired both ways is two lines, and a released build keeps the
     * LAN one.**
     *
     * One longer line would have been dropped whole by every released decoder,
     * LAN route and all — so a phone downgraded after pairing through the relay
     * would lose a pairing it had long before relay routes existed.
     */
    @Test
    fun aDowngradeKeepsTheLanRouteOfAHostPairedBothWays() {
        val both = lan().mergedWith(relay())
        assertNotNull(both.lan)
        assertNotNull(both.relay)
        val text = PairedHostCodec.encode(listOf(both))
        assertEquals("a host paired both ways must be two stored lines", 2, text.split('\n').size)

        val kept = releasedDecode(text)
        assertEquals(
            "a released build would not keep exactly the LAN line",
            listOf("$identity\t192.168.1.40\t8082\t$pinA"),
            kept
        )

        // And this build reads the two lines back as ONE host.
        assertEquals(listOf(both), PairedHostCodec.decode(text))
    }

    // ── the session id is a credential against the relay ───────────────────

    /**
     * **The session id is never rendered.** A data class prints every field,
     * and a record is exactly what gets put in a log line — which the Diagnostics
     * screen shows and the crash log keeps.
     */
    @Test
    fun theSessionIdIsNeverRenderedOrLabelled() {
        val both = lan().mergedWith(relay())
        for (r in listOf(relay(), both, both.copy(preferRelay = false))) {
            for (shown in listOf(
                r.toString(), r.label(), r.idleLabel(), r.fingerprint(),
                r.relay.toString(), r.relay!!.label()
            )) {
                assertFalse("the relay session id reached a rendered string: $shown", shown.contains(session))
            }
        }
    }

    /**
     * Every stored value lives inside one tab-separated line. A tab or newline
     * inside one would be read back as other fields — a different record, or
     * none — so they are refused before they are ever stored.
     */
    @Test
    fun aRelayValueThatCouldSplitALineIsRefused() {
        val good = PairedHostRecord.viaRelay(identity, "203.0.113.9", 9443, session, pinA)
        assertNotNull(good)
        for (addr in listOf("", "   ", "203.0.113.9\t1", "203.0.113.9\n1", "203 .0.113.9")) {
            assertNull("relay address `$addr` was accepted",
                PairedHostRecord.viaRelay(identity, addr, 9443, session, pinA))
        }
        for (port in listOf(0, -1, 65536)) {
            assertNull("relay port $port was accepted",
                PairedHostRecord.viaRelay(identity, "203.0.113.9", port, session, pinA))
        }
        for (s in listOf("", "has space", "tab\there", "new\nline", "plus+slash/", "x".repeat(129))) {
            assertNull("session `$s` was accepted",
                PairedHostRecord.viaRelay(identity, "203.0.113.9", 9443, s, pinA))
        }
        assertNull("a short pin was accepted",
            PairedHostRecord.viaRelay(identity, "203.0.113.9", 9443, session, "ab"))
        assertNull("an identity carrying a tab was accepted",
            PairedHostRecord.viaRelay("id\tentity", "203.0.113.9", 9443, session, pinA))
    }

    // ── which route, and what a new pairing does to the old one ───────────

    /**
     * **Pairing a LAN-paired host through the relay must not cost it its LAN
     * route.** The registry used to replace a record by identity, which would
     * have erased the LAN route the first time a relay code was scanned for the
     * same host.
     */
    @Test
    fun pairingThroughTheRelayKeepsTheLanRouteAndPrefersTheRelay() {
        val merged = PairedHostRegistry.merged(listOf(lan()), relay())
        val r = merged.single()
        assertEquals(PairedHost("192.168.1.40", 8082, pinA), r.lan)
        assertEquals(session, r.relay?.session)
        assertTrue("Connect should take the route just paired by", r.preferRelay)
        assertTrue(r.reconnectRoute() is PairedHostRecord.Reconnect.ViaRelay)
    }

    /** And the reverse: a LAN re-pair keeps the relay route and prefers the LAN. */
    @Test
    fun pairingOnTheLanAgainKeepsTheRelayRouteAndPrefersTheLan() {
        val both = PairedHostRegistry.merged(listOf(lan()), relay())
        val again = PairedHostRegistry.merged(both, lan(addr = "192.168.1.77")).single()
        assertEquals("192.168.1.77", again.lan?.addr)
        assertEquals(session, again.relay?.session)
        assertFalse(again.preferRelay)
        assertTrue(again.reconnectRoute() is PairedHostRecord.Reconnect.Lan)
        assertEquals("192.168.1.77", again.idleLabel())
    }

    /**
     * **After a relay restart, a fresh code is the remedy — so it has to
     * replace the stale id.** A merge that kept the old one would leave the
     * phone reconnecting to an id the relay has forgotten, however many codes
     * the operator scanned.
     */
    @Test
    fun aFreshRelayPairingReplacesAStaleSession() {
        val merged = PairedHostRegistry.merged(listOf(relay()), relay(freshSession)).single()
        assertEquals(freshSession, merged.relay?.session)
    }

    /**
     * Two routes that pin different keys cannot both reach this host. The
     * newer pairing is the one the host just proved itself on, so the older
     * route goes.
     */
    @Test
    fun aRouteThatPinsAKeyTheHostNoLongerHasIsDropped() {
        val merged = PairedHostRegistry.merged(listOf(lan(pin = pinA)), relay(pin = pinB)).single()
        assertNull("a LAN route pinning the old key was kept", merged.lan)
        assertEquals(pinB, merged.relay?.pinHex)
    }

    /**
     * On disk, the same disagreement is damage. The LAN route is the one every
     * build can read, so it is the one kept.
     */
    @Test
    fun storedRoutesThatDisagreeAboutThePinKeepTheLanRoute() {
        val text = listOf(
            "$identity\t192.168.1.40\t8082\t$pinA",
            "relay\t$identity\t203.0.113.9\t9443\t$session\t$pinB\tpreferred"
        ).joinToString("\n")
        val r = PairedHostCodec.decode(text).single()
        assertEquals(pinA, r.lan?.pinHex)
        assertNull("a relay route pinning a different key was kept", r.relay)
    }

    /** Merging two hosts is exactly the failure a record exists to prevent. */
    @Test
    fun aDifferentHostIsNeverMergedIntoThisOne() {
        val stranger = PairedHostRecord.viaRelay(other, "203.0.113.9", 9443, freshSession, pinB)!!
        assertEquals(stranger, lan().mergedWith(stranger))
        val list = PairedHostRegistry.merged(listOf(lan()), stranger)
        assertEquals(2, list.size)
        assertEquals(lan(), list[0])
    }

    // ── damage ──────────────────────────────────────────────────────────

    /** A corrupt relay line must not cost a host the LAN route beside it. */
    @Test
    fun aCorruptRelayLineDoesNotCostTheLanRoute() {
        for (bad in listOf(
            "relay\t$identity\t203.0.113.9\tnotaport\t$session\t$pinA\tpreferred",
            "relay\t$identity\t203.0.113.9\t9443\t$session\t$pinA\tmaybe",
            "relay\t$identity\t203.0.113.9\t9443\t\t$pinA\tpreferred",
            "relay\t$identity\t203.0.113.9\t9443\t$session\t$pinA",
            "notrelay\t$identity\t203.0.113.9\t9443\t$session\t$pinA\tpreferred"
        )) {
            val text = "$identity\t192.168.1.40\t8082\t$pinA\n$bad"
            val r = PairedHostCodec.decode(text)
            assertEquals("`$bad` cost the host its LAN route", listOf(lan()), r)
        }
    }

    /** Forgetting a host takes every route it has, not just the one shown. */
    @Test
    fun aForgottenHostLeavesNoRouteBehind() {
        val both = lan().mergedWith(relay())
        val keeper = PairedHostRecord.of(other, "192.168.1.9", 8081, pinB)!!
        val after = listOf(both, keeper).filterNot { it.identityB64 == identity }
        val text = PairedHostCodec.encode(after)
        assertFalse("a route of the forgotten host was still written", text.contains(identity))
        assertFalse(text.contains(session))
        assertEquals(listOf(keeper), PairedHostCodec.decode(text))
    }

    // ── what the person holding the phone is told ─────────────────────────

    /**
     * **A relay refusal is not "stream stopped".** Nothing had streamed. It
     * used to be reported that way, which sends the operator looking at the
     * screen capture for a problem that is on the relay's side.
     */
    @Test
    fun aRelayRefusalIsReportedAsTheRelayNotKnowingTheHost() {
        val detail = "relay 203.0.113.9:9443: ${NativeFailure.RELAY_REFUSED_MARK}: no such session"
        val onReconnect = NativeFailure.classify(detail, reconnectingViaRelay = true)
        assertEquals(FailureReason.RelaySessionUnknown, onReconnect.reason)
        // Both remedies, because the relay will not say which applies.
        assertTrue(onReconnect.detail, onReconnect.detail.contains("Start RemoteDexter on the host"))
        assertTrue(onReconnect.detail, onReconnect.detail.contains("scan a fresh code"))

        val onPairing = NativeFailure.classify(detail, reconnectingViaRelay = false)
        assertEquals(FailureReason.RelaySessionUnknown, onPairing.reason)
        assertTrue(onPairing.detail, onPairing.detail.contains("make a fresh code"))
    }

    /** Everything else is still what it was. */
    @Test
    fun otherNativeFailuresAreUnchanged() {
        for (detail in listOf(
            "192.168.1.40:8082: pairing refused by host",
            "relay 203.0.113.9:9443: host key pin MISMATCH — aborting (possible MITM)",
            "timed out waiting for the host to connect"
        )) {
            val failed = NativeFailure.classify(detail, reconnectingViaRelay = true)
            assertEquals(detail, FailureReason.Stream, failed.reason)
            assertEquals(detail, failed.detail)
        }
    }
}
