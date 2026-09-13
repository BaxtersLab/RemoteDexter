package com.remotedexter

import android.content.ComponentName
import android.content.pm.ActivityInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Turning the phone must not quietly hand the grant back.
 *
 * Regression test for the defect the operator reported as "it keeps reverting":
 * `MainActivity` declared no `configChanges`, so a rotation destroyed and
 * recreated it, and *three* separate call sites — `onDestroy`,
 * `surfaceDestroyed` and `onCreate` — each called `InputController.reset()` on
 * the way through. The session is owned by a foreground service and survives
 * that, and so does the host's grant, so the client silently disagreed with the
 * host about who was driving. Landscape is not an edge case: it is how anyone
 * holds a phone that is showing a desktop.
 *
 * ## Why this asserts the declaration rather than turning the screen
 *
 * The behavioural version of this test was written first and its red was real:
 * with the fix absent it failed
 * `expected:<Disable Control (Viewing Only)> but was:<Enable Control>`, and it
 * passed once the fix was in. It is not what ships, because making it
 * *reliable* proved to depend on the handset rather than the product:
 *
 * * `requestedOrientation` silently loses to the accelerometer on a
 *   free-rotating display — cornered, it reported `requestedOrientation=1`
 *   while the configuration stayed landscape;
 * * `UiAutomation.setRotation` turns the display, but under `ActivityScenario`
 *   it left the Activity's own window intact (one `ViewRootImpl` for the whole
 *   test), so the destroy/rebuild never happened and the suite passed with the
 *   fix removed — a false green;
 * * freezing the display to get a deterministic baseline then blocks the very
 *   rotation the test needs.
 *
 * A test that passes without the fix is worse than no test. What the fix
 * actually *is* — the declaration that this Activity handles rotation in place
 * — is exact, device-independent, and fails the moment someone deletes it.
 * The behavioural proof was taken once on hardware as a one-off observation.
 */
@RunWith(AndroidJUnit4::class)
class ControlSurvivesRotationTest {

    @Test
    fun mainActivityHandlesRotationInsteadOfBeingRebuilt() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val info = context.packageManager.getActivityInfo(
            ComponentName(context, MainActivity::class.java), 0
        )
        // Orientation alone is not enough: a rotation also changes the screen
        // size, and an undeclared config change still restarts the Activity.
        val required = ActivityInfo.CONFIG_ORIENTATION or ActivityInfo.CONFIG_SCREEN_SIZE
        assertEquals(
            "MainActivity must declare configChanges for orientation and screenSize. " +
                "Without them a rotation destroys and rebuilds it, and onDestroy, " +
                "surfaceDestroyed and onCreate each call InputController.reset() — " +
                "silently revoking a grant the host still holds, while the session's " +
                "foreground service carries on.",
            required,
            info.configChanges and required
        )
    }
}
