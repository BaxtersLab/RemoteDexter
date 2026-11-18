package com.remotedexter

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.graphics.Rect
import android.util.TypedValue
import android.view.View
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * **The scroll pair is always fully on screen**, held upright and sideways.
 *
 * With two fingers always panning — the operator's rule, recorded in f42210e —
 * these two buttons are the operator's ONLY way to scroll. They are the last row
 * of a panel whose height is pinned by arithmetic (`controls_panel_height`), so
 * any row above that grows pushes them out first, and twice before a row was
 * drawn past the window's edge without anyone noticing (see the comments in
 * `controls_panel.xml` and `dimens.xml`).
 *
 * Until 2026-09-18 nothing asserted this. `dimens.xml` said "ControlRowFitTest
 * and the instrumentation layout tests are what catch it", and none of them looks
 * at the scroll row. The operator then reported the pair missing from the phone.
 *
 * Real rotation, not a synthetic `onConfigurationChanged`: what matters is the
 * window the operator actually sees.
 */
@RunWith(AndroidJUnit4::class)
class ScrollPairOnScreenTest {

    private fun rotate(scenario: ActivityScenario<MainActivity>, requested: Int, want: Int) {
        scenario.onActivity { it.requestedOrientation = requested }
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            var settled = false
            scenario.onActivity { activity ->
                val decor = activity.window.decorView
                val wide = decor.width > decor.height
                settled = activity.resources.configuration.orientation == want &&
                    decor.width > 0 &&
                    wide == (want == Configuration.ORIENTATION_LANDSCAPE)
            }
            if (settled) {
                InstrumentationRegistry.getInstrumentation().waitForIdleSync()
                return
            }
            Thread.sleep(100)
        }
        throw AssertionError("the device never settled in the requested orientation")
    }

    private fun assertFullyOnScreen(activity: MainActivity, how: String) {
        val frame = Rect()
        activity.window.decorView.getWindowVisibleDisplayFrame(frame)
        val floor = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, 48f, activity.resources.displayMetrics
        ).toInt()
        for (id in listOf(R.id.btnScrollUp, R.id.btnScrollDown)) {
            val button = activity.findViewById<View>(id)
            val name = activity.resources.getResourceEntryName(id)
            assertTrue("$name is not shown ($how)", button.isShown)
            assertTrue(
                "$name is ${button.height}px tall, below the 48dp floor of ${floor}px ($how)",
                button.height >= floor
            )
            val seen = Rect()
            assertTrue("$name has no part on screen ($how)", button.getGlobalVisibleRect(seen))
            assertEquals(
                "$name is clipped: ${seen.width()}x${seen.height()} of " +
                    "${button.width}x${button.height}px is visible ($how)",
                button.width to button.height,
                seen.width() to seen.height()
            )
            assertTrue(
                "$name runs past the window: $seen against $frame ($how)",
                seen.bottom <= frame.bottom && seen.right <= frame.right
            )
        }
    }

    @Test
    fun theScrollPairIsFullyOnScreenHeldUpright() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            rotate(
                scenario,
                ActivityInfo.SCREEN_ORIENTATION_PORTRAIT,
                Configuration.ORIENTATION_PORTRAIT
            )
            scenario.onActivity { assertFullyOnScreen(it, "held upright") }
        }
    }

    /**
     * **A row above that grows does not push the pair out.** The panel's height
     * used to be a fixed sum, so anything taller above — a label that wraps, a
     * larger font, a state line — came straight out of the last row.
     */
    @Test
    fun theScrollPairStaysOnScreenWhenARowAboveItGrows() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            rotate(
                scenario,
                ActivityInfo.SCREEN_ORIENTATION_PORTRAIT,
                Configuration.ORIENTATION_PORTRAIT
            )
            scenario.onActivity { activity ->
                // Five lines in the top row's only text: far taller than its
                // 48dp buttons.
                activity.findViewById<android.widget.TextView>(R.id.linkIndicator).text =
                    "a\nb\nc\nd\ne"
            }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { assertFullyOnScreen(it, "held upright, top row grown") }
        }
    }

    @Test
    fun theScrollPairIsFullyOnScreenHeldSideways() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            rotate(
                scenario,
                ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE,
                Configuration.ORIENTATION_LANDSCAPE
            )
            scenario.onActivity { assertFullyOnScreen(it, "held sideways") }
            // Put the device back, so the next test starts upright.
            rotate(
                scenario,
                ActivityInfo.SCREEN_ORIENTATION_PORTRAIT,
                Configuration.ORIENTATION_PORTRAIT
            )
        }
    }
}
