package com.remotedexter

import com.remotedexter.bootstrap18.InviteDecoder
import com.remotedexter.bootstrap18.InviteV4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The Block 5 lifecycle contract, on the JVM.
 *
 * These run without an emulator because the rules they check are pure: given a
 * [SessionState], may the service exist, may a wake lock be held, must it stop.
 * That is deliberate — these decide whether the app keeps someone's phone awake
 * and whether a refusal is visible, so they have to be cheap enough to run on
 * every change rather than only when a device is plugged in.
 *
 * What Android itself does — that a service really is absent after a cold
 * launch, that a wake lock really is released — is in `ColdLaunchTest` and
 * `LifecycleInstrumentationTest`, because only a real runtime can answer that.
 */
class LifecycleStateTest {

    @Before fun reset() { SessionStateHolder.resetForTest(); PendingConnects.clear() }
    @After fun cleanup() { SessionStateHolder.resetForTest(); PendingConnects.clear() }

    private fun invite(addr: String = "192.168.1.20", expires: Long = 4_000_000_000L) = InviteV4(
        kind = InviteDecoder.INVITE_KIND, version = 4, protocol = "rdv3",
        addr = addr, port = 8082, token = "1f".repeat(32), nonce = "9c".repeat(16),
        expiresAt = expires, capabilities = listOf("view"),
        hostPubkey = "ab".repeat(32), hostIdentityPubkey = "aWQ=", signature = "c2ln"
    )

    // ── 1 ────────────────────────────────────────────────────────────────
    /** The app starts Idle, and Idle runs nothing. */
    @Test
    fun coldStartIsIdleAndRunsNothing() {
        assertEquals(SessionState.Idle, SessionStateHolder.current())
        assertFalse(ServicePolicy.serviceShouldRun(SessionState.Idle))
        assertFalse(ServicePolicy.wakeLockShouldBeHeld(SessionState.Idle))
        assertFalse(ServicePolicy.shouldRequestBatteryExemptionOnLaunch())
    }

    // ── 2 ────────────────────────────────────────────────────────────────
    /** Only an explicit connection puts the service in a running state. */
    @Test
    fun onlyConnectingOrStreamingJustifyTheService() {
        assertTrue(ServicePolicy.serviceShouldRun(SessionState.Connecting("h")))
        assertTrue(ServicePolicy.serviceShouldRun(SessionState.Streaming("h")))
        assertFalse(ServicePolicy.serviceShouldRun(SessionState.Idle))
        assertFalse(
            ServicePolicy.serviceShouldRun(
                SessionState.Failed(FailureReason.Network, "x")
            )
        )
        assertFalse(
            ServicePolicy.serviceShouldRun(SessionState.IdentityMismatch("a", "b"))
        )
    }

    // ── 3 ────────────────────────────────────────────────────────────────
    /**
     * The wake lock is narrower than the service. `Connecting` does not justify
     * keeping the phone awake; the old code held one from `onCreate` onward.
     */
    @Test
    fun theWakeLockIsHeldOnlyWhileStreaming() {
        assertTrue(ServicePolicy.wakeLockShouldBeHeld(SessionState.Streaming("h")))
        assertFalse(ServicePolicy.wakeLockShouldBeHeld(SessionState.Connecting("h")))
        assertFalse(ServicePolicy.wakeLockShouldBeHeld(SessionState.Idle))
        assertFalse(
            ServicePolicy.wakeLockShouldBeHeld(SessionState.Failed(FailureReason.Stream, "x"))
        )
    }

    // ── 4 ────────────────────────────────────────────────────────────────
    /** Every terminal state stops the service — failure included. */
    @Test
    fun failureAndDisconnectBothStopTheService() {
        assertTrue(ServicePolicy.shouldStopSelf(SessionState.Idle))
        assertTrue(
            ServicePolicy.shouldStopSelf(SessionState.Failed(FailureReason.NoiseHandshake, "x"))
        )
        assertTrue(ServicePolicy.shouldStopSelf(SessionState.IdentityMismatch("a", "b")))
        assertFalse(ServicePolicy.shouldStopSelf(SessionState.Streaming("h")))
        assertFalse(ServicePolicy.shouldStopSelf(SessionState.Connecting("h")))
    }

    // ── 5 ────────────────────────────────────────────────────────────────
    /** Task removal must never restart the service. */
    @Test
    fun taskRemovalNeverRestartsTheService() {
        assertFalse(ServicePolicy.shouldRestartOnTaskRemoved())
    }

    // ── 6 ────────────────────────────────────────────────────────────────
    /**
     * A new subscriber is given the current state immediately. This is what
     * makes rotation safe: a recreated view renders the live session rather
     * than a blank Home while it waits for the next change.
     */
    @Test
    fun rotationPreservesActiveState() {
        SessionStateHolder.set(SessionState.Streaming("192.168.1.20"))
        var seen: SessionState? = null
        SessionStateHolder.subscribe { seen = it } // a "recreated" view
        assertEquals(SessionState.Streaming("192.168.1.20"), seen)
    }

    // ── 7 ────────────────────────────────────────────────────────────────
    /**
     * An identity mismatch cannot be cleared by anything except a deliberate
     * unpair. An automatic reconnect must not be able to overwrite it — the
     * user would never learn the host's key had changed.
     */
    @Test
    fun anIdentityMismatchCannotBeAutoCleared() {
        SessionStateHolder.set(SessionState.IdentityMismatch("expectedFP", "receivedFP"))
        SessionStateHolder.set(SessionState.Connecting("h"))
        SessionStateHolder.set(SessionState.Idle)
        SessionStateHolder.set(SessionState.Streaming("h"))
        assertTrue(
            "a mismatch was cleared without a deliberate unpair",
            SessionStateHolder.current() is SessionState.IdentityMismatch
        )
    }

    // ── 8 ────────────────────────────────────────────────────────────────
    /** ...and a deliberate unpair does clear it. */
    @Test
    fun unpairIsTheOnlyWayOutOfAMismatch() {
        SessionStateHolder.set(SessionState.IdentityMismatch("a", "b"))
        SessionStateHolder.resolveIdentityMismatch()
        assertEquals(SessionState.Idle, SessionStateHolder.current())
    }

    // ── 9 ────────────────────────────────────────────────────────────────
    /**
     * The intent extra is an opaque id, not a credential. A token in an extra
     * would land in system logs, bug reports and recent-task state.
     */
    @Test
    fun theConnectIntentCarriesAnOpaqueIdNotTheToken() {
        val inv = invite()
        val id = PendingConnects.submit(inv)
        assertEquals(32, id.length)
        assertTrue(id.all { it.isDigit() || it in 'a'..'f' })
        assertFalse("the id must not contain the token", id.contains(inv.token))
        assertNotEquals(inv.token, id)
    }

    // ── 10 ───────────────────────────────────────────────────────────────
    /** A request id is redeemable once, like the token it stands for. */
    @Test
    fun aRequestIdIsRedeemableExactlyOnce() {
        val inv = invite()
        val id = PendingConnects.submit(inv)
        assertEquals(PendingInvite.Direct(inv), PendingConnects.take(id))
        assertNull("a replayed intent must not start a second session", PendingConnects.take(id))
        assertNull(PendingConnects.take(null))
        assertNull(PendingConnects.take("not-a-real-id"))
    }

    /**
     * The one-shot guarantee holds for a RELAY invite too, and both routes
     * share ONE store: two maps would be two stores with two chances to get
     * this wrong, and a replayed intent is a replayed intent either way.
     */
    @Test
    fun aRelayRequestIdIsRedeemableExactlyOnce() {
        val inv = com.remotedexter.bootstrap18.InviteV5(
            kind = "remotedexter-pair", version = 5, protocol = "rdv3",
            relayAddr = "203.0.113.9", relayPort = 9443,
            session = "Zm9vYmFyYmF6cXV4MDAwMA", token = "1f".repeat(32),
            nonce = "9c".repeat(16), expiresAt = 1787000060L,
            capabilities = listOf("view"), hostPubkey = "ab".repeat(32),
            hostIdentityPubkey = "", signature = ""
        )
        val id = PendingConnects.submitRelay(inv)
        assertEquals(PendingInvite.ViaRelay(inv), PendingConnects.take(id))
        assertNull("a replayed intent must not start a second relay session", PendingConnects.take(id))
    }

    /** A direct id and a relay id are drawn from the same space and neither
     * collides with nor redeems the other. */
    @Test
    fun theTwoRoutesShareOneOneShotStore() {
        PendingConnects.clear()
        val direct = PendingConnects.submit(invite())
        val relay = PendingConnects.submitRelay(
            com.remotedexter.bootstrap18.InviteV5(
                kind = "remotedexter-pair", version = 5, protocol = "rdv3",
                relayAddr = "203.0.113.9", relayPort = 9443,
                session = "Zm9vYmFyYmF6cXV4MDAwMA", token = "3c".repeat(32),
                nonce = "5e".repeat(16), expiresAt = 1787000060L,
                capabilities = listOf("view"), hostPubkey = "cd".repeat(32),
                hostIdentityPubkey = "", signature = ""
            )
        )
        assertEquals(2, PendingConnects.size())
        assertTrue(PendingConnects.take(direct) is PendingInvite.Direct)
        assertTrue(PendingConnects.take(relay) is PendingInvite.ViaRelay)
        assertEquals(0, PendingConnects.size())
    }

    // ── 11 ───────────────────────────────────────────────────────────────
    /**
     * Every failure the plan names maps to its own visible state, and none of
     * them collapses into another.
     */
    @Test
    fun everyFailureReasonIsDistinctAndVisible() {
        val all = FailureReason.values()
        assertEquals(
            "all nine plan-named failures, the QR-kind case, and the relay not knowing a host",
            11,
            all.size
        )
        val labels = all.map { it.label() }
        assertEquals("two failures share a label", labels.size, labels.toSet().size)
        assertTrue("a label must not be empty", labels.none { it.isBlank() })
        // Named explicitly so deleting one is a compile error, not a silent gap.
        listOf(
            FailureReason.InviteParse, FailureReason.InviteSignature,
            FailureReason.InviteExpired, FailureReason.UnsupportedAbi,
            FailureReason.Network, FailureReason.NoiseHandshake,
            FailureReason.PairingRefused, FailureReason.Authorization,
            FailureReason.Stream, FailureReason.QrNotPairingCode,
            FailureReason.RelaySessionUnknown
        ).forEach { assertTrue(all.contains(it)) }
    }

    // ── 12 ───────────────────────────────────────────────────────────────
    /**
     * Retry is offered only where it can work. A one-use token cannot be
     * retried and a bad signature will not become good; offering it there
     * teaches people to mash the button.
     */
    @Test
    fun retryIsOfferedOnlyWhereItCouldSucceed() {
        assertTrue(FailureReason.Network.isRetryable())
        assertTrue(FailureReason.Stream.isRetryable())
        // A host that was not connected to the relay may be now.
        assertTrue(FailureReason.RelaySessionUnknown.isRetryable())
        listOf(
            FailureReason.InviteSignature, FailureReason.InviteExpired,
            FailureReason.PairingRefused, FailureReason.UnsupportedAbi,
            FailureReason.QrNotPairingCode, FailureReason.InviteParse,
            FailureReason.NoiseHandshake, FailureReason.Authorization
        ).forEach {
            assertFalse("${it.name} must not offer retry", it.isRetryable())
        }
    }

    // ── 13: terminal state returns Home ──────────────────────────────────
    @Test
    fun aTerminalStateIsNotActive() {
        assertFalse(SessionState.Idle.isActive)
        assertFalse(SessionState.Failed(FailureReason.Network, "x").isActive)
        assertFalse(SessionState.IdentityMismatch("a", "b").isActive)
        assertTrue(SessionState.Connecting("h").isActive)
        assertTrue(SessionState.Streaming("h").isActive)
    }

    // ── 14: observers actually receive transitions ───────────────────────
    @Test
    fun observersSeeEveryTransitionInOrder() {
        val seen = mutableListOf<SessionState>()
        SessionStateHolder.subscribe { seen.add(it) }
        SessionStateHolder.set(SessionState.Connecting("h"))
        SessionStateHolder.set(SessionState.Streaming("h"))
        SessionStateHolder.set(SessionState.Idle)
        assertEquals(
            listOf(
                SessionState.Idle, // delivered on subscribe
                SessionState.Connecting("h"),
                SessionState.Streaming("h"),
                SessionState.Idle
            ),
            seen
        )
    }

    // ── 15: unsubscribed views stop receiving ────────────────────────────
    @Test
    fun anUnsubscribedObserverStopsReceiving() {
        val seen = mutableListOf<SessionState>()
        val obs = SessionStateHolder.subscribe { seen.add(it) }
        SessionStateHolder.unsubscribe(obs)
        SessionStateHolder.set(SessionState.Streaming("h"))
        assertEquals("a destroyed view kept receiving state", 1, seen.size)
    }

    // ── 16: a live transport cannot die silently ─────────────────────────
    @Test
    fun cableDisconnectBecomesATerminalStreamFailure() {
        assertNull(
            SessionStatusPolicy.streamingFailure(
                "connected|127.0.0.1:8082 — host key pinned"
            )
        )

        val detail = SessionStatusPolicy.streamingFailure(
            "failed|127.0.0.1:8082: early eof"
        )
        assertEquals("127.0.0.1:8082: early eof", detail)

        val state = SessionState.Failed(FailureReason.Stream, detail!!)
        assertTrue(ServicePolicy.shouldStopSelf(state))
        assertFalse(ServicePolicy.wakeLockShouldBeHeld(state))
    }
}
