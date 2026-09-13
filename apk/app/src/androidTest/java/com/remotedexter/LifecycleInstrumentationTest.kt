package com.remotedexter

import android.app.ActivityManager
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Lifecycle claims that only a real Android runtime can answer.
 *
 * ## What is deliberately NOT here
 *
 * Tests that start a real foreground service from instrumentation. Android
 * restricts background foreground-service starts (API 26 onward, hard on API
 * 34), so such a test spends its time fighting the platform's restriction
 * rather than checking the product. Four were written and removed for exactly
 * that reason.
 *
 * The rules those tests were reaching for — service only while active, wake
 * lock only while streaming, stopSelf on any terminal state — are proven in
 * `LifecycleStateTest` against [ServicePolicy], which is pure and exhaustive.
 * What is genuinely missing is whether **Android honours them during a live
 * session**, and that needs a real host to connect to. It is named as an
 * UNVERIFIED boundary in `scripts/gate.manifest` and closes in Block 6.
 *
 * Everything below runs without a host, and every one of them is a claim the
 * JVM cannot make.
 */
@RunWith(AndroidJUnit4::class)
class LifecycleInstrumentationTest {

    private fun ctx(): Context = ApplicationProvider.getApplicationContext()

    @Suppress("DEPRECATION")
    private fun rdServiceRunning(): Boolean {
        val am = ctx().getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        return am.getRunningServices(Int.MAX_VALUE)
            .any { it.service.className == RDService::class.java.name }
    }

    private fun ourNotifications(): Int {
        val nm = ctx().getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        return nm.activeNotifications.size
    }

    @Before fun reset() { SessionStateHolder.resetForTest(); PendingConnects.clear() }
    @After fun cleanup() { SessionStateHolder.resetForTest(); PendingConnects.clear() }

    /**
     * `RDService` must not be exported. An exported service would let any
     * installed app start a remote-control session.
     */
    @Test
    fun theServiceIsNotExported() {
        val info = ctx().packageManager.getServiceInfo(
            ComponentName(ctx(), RDService::class.java),
            PackageManager.GET_META_DATA
        )
        assertFalse("RDService is exported", info.exported)
    }

    /**
     * The exported surface, read off the INSTALLED package.
     *
     * In a release build this is exactly one component, the launcher. An
     * exported QR scanner would let any installed app drive pairing; an exported
     * service would let one start a session.
     *
     * ## Why the expected list is not simply that one name
     *
     * Instrumentation only ever runs against a debug build, so this test can
     * only ever read a debug package. On 2026-09-08 the operator authorised one
     * debug-only export — `HeldKeyDebugReceiver`, the test affordance that lets
     * Windows prove the `N key(s)` half of the host's shutdown message, which
     * round 13 established the shipping client cannot express. It has to be
     * exported: `am broadcast` runs as the shell UID and a non-exported receiver
     * is enqueued and never run, measured on this emulator in both directions.
     *
     * So the rule this asserts is the real one, stated in full rather than
     * loosened: the launcher is always exported, the receiver is exported if and
     * only if [BuildProfile.HELD_KEY_AFFORDANCE] compiled it in, and **nothing
     * else ever is**. A third export still fails this test, in either variant.
     *
     * The release surface is asserted where it can actually be read: the
     * `android-exported` gate row parses `src/main/AndroidManifest.xml`, which is
     * the whole of what a release APK is built from, and still expects
     * `activity:.MainActivity` alone. `android-exported-debug` pins this list.
     */
    @Test
    fun onlyTheLauncherAndTheAuthorisedDebugReceiverAreExported() {
        val pkg = ctx().packageManager.getPackageInfo(
            ctx().packageName,
            PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS
        )
        val exported = buildList {
            pkg.activities?.forEach { if (it.exported) add(it.name) }
            pkg.services?.forEach { if (it.exported) add(it.name) }
            pkg.receivers?.forEach { if (it.exported) add(it.name) }
        }.filter { it.startsWith("com.remotedexter") }.sorted()

        val expected = buildList {
            add("com.remotedexter.MainActivity")
            if (BuildProfile.HELD_KEY_AFFORDANCE) add("com.remotedexter.HeldKeyDebugReceiver")
        }.sorted()

        assertEquals(
            "the exported surface changed. Only the launcher may be exported, plus " +
                "the held-key debug receiver in a build that compiles the affordance in",
            expected,
            exported
        )
    }

    /**
     * An idle app posts no notification. This is the security-relevant half of
     * the foreground-notification contract and needs no session: a notification
     * without a session tells the user something is running when nothing is.
     */
    @Test
    fun anIdleAppPostsNoNotification() {
        ctx().stopService(android.content.Intent(ctx(), RDService::class.java))
        Thread.sleep(1200)
        assertEquals("the app posted a notification with no session", 0, ourNotifications())
    }

    /**
     * An identity mismatch survives every later transition on a real runtime,
     * including anything resembling an automatic reconnect.
     */
    @Test
    fun anIdentityMismatchIsStickyOnDevice() {
        SessionStateHolder.set(SessionState.IdentityMismatch("expectedFP", "receivedFP"))
        SessionStateHolder.set(SessionState.Connecting("10.0.0.1"))
        SessionStateHolder.set(SessionState.Streaming("10.0.0.1"))
        assertTrue(
            "a host-identity change was cleared without a deliberate unpair",
            SessionStateHolder.current() is SessionState.IdentityMismatch
        )
    }

    /** ...and only a deliberate unpair clears it. */
    @Test
    fun onlyADeliberateUnpairClearsAMismatchOnDevice() {
        SessionStateHolder.set(SessionState.IdentityMismatch("a", "b"))
        SessionStateHolder.resolveIdentityMismatch()
        assertEquals(SessionState.Idle, SessionStateHolder.current())
    }

    /** Terminal states leave the app inactive. */
    @Test
    fun aTerminalStateReturnsToAnInactiveApp() {
        SessionStateHolder.set(SessionState.Streaming("10.0.0.1"))
        assertTrue(SessionStateHolder.current().isActive)
        SessionStateHolder.set(SessionState.Failed(FailureReason.Stream, "ended"))
        assertFalse(SessionStateHolder.current().isActive)
        assertTrue(SessionStateHolder.current().isTerminal)
    }

    /**
     * A connect request id is redeemable once on a real runtime too, so a
     * replayed intent cannot start a second session from one user action.
     */
    @Test
    fun aConnectRequestIdIsSingleUseOnDevice() {
        val invite = com.remotedexter.bootstrap18.InviteV4(
            kind = com.remotedexter.bootstrap18.InviteDecoder.INVITE_KIND,
            version = 4, protocol = "rdv3", addr = "10.0.0.1", port = 8082,
            token = "1f".repeat(32), nonce = "9c".repeat(16),
            expiresAt = 4_000_000_000L, capabilities = listOf("view"),
            hostPubkey = "ab".repeat(32), hostIdentityPubkey = "aWQ=", signature = "c2ln"
        )
        val id = PendingConnects.submit(invite)
        assertEquals(PendingInvite.Direct(invite), PendingConnects.take(id))
        assertEquals(null, PendingConnects.take(id))
    }

    /** No service is running while the app sits idle. */
    @Test
    fun anIdleAppRunsNoService() {
        ctx().stopService(android.content.Intent(ctx(), RDService::class.java))
        Thread.sleep(1200)
        assertFalse("a service was running with no session", rdServiceRunning())
    }
}
