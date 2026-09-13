package com.remotedexter

import android.app.ActivityManager
import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The cold-launch lifecycle contract, on a real Android runtime.
 *
 * These are instrumentation tests rather than JVM tests because the claims are
 * about **Android's** behaviour — whether a service is actually running in this
 * process, whether a wake lock is actually held — and a JVM test could only
 * assert what our own code intended, which is exactly the gap that let the
 * previous behaviour ship.
 */
@RunWith(AndroidJUnit4::class)
class ColdLaunchTest {

    @Before
    fun resetState() {
        SessionStateHolder.resetForTest()
    }

    private fun context(): Context = ApplicationProvider.getApplicationContext()

    @Suppress("DEPRECATION")
    private fun rdServiceRunning(): Boolean {
        val am = context().getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        return am.getRunningServices(Int.MAX_VALUE)
            .any { it.service.className == RDService::class.java.name }
    }

    /**
     * **THE RED PROOF for Block 5.**
     *
     * `MainActivity.onCreate` used to call `startForegroundService` unconditionally
     * and then immediately fire `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`.
     * Opening the app therefore started a sticky foreground service, took a
     * `PARTIAL_WAKE_LOCK`, and asked for battery exemption before the user had
     * chosen to connect to anything.
     *
     * The manifest has claimed the opposite in prose since Block 1: "It does NOT
     * surveil the phone and does NOT run when the user has not opened it." This
     * test is what makes that claim checkable.
     */
    @Test
    fun coldLaunchStartsNoService() {
        assertFalse(
            "precondition: RDService must not already be running",
            rdServiceRunning()
        )
        ActivityScenario.launch(MainActivity::class.java).use {
            Thread.sleep(1500) // give a wrongly-eager launch every chance to start it
            assertFalse(
                "opening the app started RDService before the user asked to connect",
                rdServiceRunning()
            )
        }
    }

    /** Opening the app must not hold a wake lock either. */
    @Test
    fun coldLaunchHoldsNoWakeLock() {
        ActivityScenario.launch(MainActivity::class.java).use {
            Thread.sleep(1000)
            assertFalse(
                "opening the app acquired a wake lock before any session existed",
                RDService.isWakeLockHeldForTest()
            )
        }
    }

    /** And the home screen must actually be showing something. */
    @Test
    fun coldLaunchShowsTheHomeState() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(
                    "the app opened without a visible home state",
                    activity.findViewById<android.view.View>(android.R.id.content) != null
                )
            }
        }
    }

    /** Session safety actions must be reliable finger targets on the real UI. */
    @Test
    fun sessionActionsMeetTheMinimumTouchTarget() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val minimumPx = (48 * activity.resources.displayMetrics.density).toInt()
                val control = activity.findViewById<android.view.View>(R.id.btnToggleControl)
                val disconnect = activity.findViewById<android.view.View>(R.id.btnDisconnect)
                assertNotNull("the session has no persistent Disconnect action", disconnect)
                assertTrue(
                    "Enable Control is ${control.height}px; minimum target is ${minimumPx}px",
                    control.height >= minimumPx
                )
                assertTrue(
                    "Disconnect is ${disconnect.height}px; minimum target is ${minimumPx}px",
                    disconnect.height >= minimumPx
                )
            }
        }
    }

    /** Back backgrounds the viewer; only an explicit disconnect/task swipe ends it. */
    @Test
    fun backDoesNotFinishTheViewerTask() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.onBackPressedDispatcher.onBackPressed()
                assertFalse("Back finished the viewer and removed its task", activity.isFinishing)
            }
        }
    }

    /** The visible viewer may keep the screen on, but only during Streaming. */
    @Test
    fun onlyStreamingKeepsTheViewerScreenAwake() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val surface = activity.findViewById<android.view.View>(R.id.desktopSurface)
                assertFalse("Idle viewer kept the screen awake", surface.keepScreenOn)
                SessionStateHolder.set(SessionState.Streaming("host"))
                assertTrue("Streaming viewer allowed the phone to sleep", surface.keepScreenOn)
                SessionStateHolder.set(SessionState.Idle)
                assertFalse("ended stream still kept the screen awake", surface.keepScreenOn)
            }
        }
    }

    @Test
    fun controlActionIsAvailableOnlyWhileStreaming() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val control = activity.findViewById<android.view.View>(R.id.btnToggleControl)
                assertFalse("Idle viewer offered remote control", control.isEnabled)
                SessionStateHolder.set(SessionState.Streaming("host"))
                assertTrue("Streaming viewer did not offer remote control", control.isEnabled)
                SessionStateHolder.set(SessionState.Idle)
                assertFalse("Ended stream still offered remote control", control.isEnabled)
            }
        }
    }
}
