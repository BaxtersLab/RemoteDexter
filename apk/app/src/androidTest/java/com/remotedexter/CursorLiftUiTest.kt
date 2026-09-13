package com.remotedexter

import android.widget.Button
import android.widget.SeekBar
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.math.roundToInt

/**
 * The cursor lift, now that it lives in Settings.
 *
 * It used to sit in the main screen's bottom row, taking a quarter of the width
 * from Enable Control, Connect and Disconnect. A preference set once does not
 * deserve space that session controls need every time, so it moved — and this
 * suite moved with it.
 *
 * The persistence itself is [CursorLift]'s and is proven on the JVM. What needs
 * a device is that the slider is really wired to it and that the main screen's
 * row is genuinely better off.
 */
@RunWith(AndroidJUnit4::class)
class CursorLiftUiTest {

    private fun context() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    @After
    fun clearPreference() {
        CursorLift.save(context(), 0)
    }

    @Test
    fun theSliderLivesInSettingsAndSpansTheUsableRange() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val bar = a.findViewById<SeekBar>(R.id.seekCursorLift)
                assertEquals(CursorLift.MAX_DP, bar.max)
                assertEquals("a fresh install must not lift the cursor", 0, bar.progress)
            }
        }
    }

    /** The slider must show what is stored, not a default. */
    @Test
    fun aStoredCursorLiftIsShownWhenSettingsOpens() {
        CursorLift.save(context(), 48)
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                assertEquals(
                    48,
                    a.findViewById<SeekBar>(R.id.seekCursorLift).progress
                )
            }
        }
    }

    /**
     * An out-of-range stored value is clamped rather than trusted. Preferences
     * survive upgrades and restores from backup, so a value this code never
     * wrote can still turn up in one.
     */
    @Test
    fun anOutOfRangeStoredValueIsClampedRatherThanTrusted() {
        // Written past the ceiling through the shared saver, which clamps.
        CursorLift.save(context(), 99999)
        assertEquals(CursorLift.MAX_DP, CursorLift.load(context()))
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val bar = a.findViewById<SeekBar>(R.id.seekCursorLift)
                assertTrue(
                    "the slider is showing ${bar.progress}, outside its own range",
                    bar.progress in 0..CursorLift.MAX_DP
                )
            }
        }
    }

    /**
     * The point of the move: the session row is now three controls, and each
     * one keeps a dependable 48dp target with the width the slider gave up.
     */
    @Test
    fun everyControlInTheSessionRowKeepsAFullTouchTarget() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val density = a.resources.displayMetrics.density
                val minPx = (48 * density).roundToInt()
                val toggle = a.findViewById<Button>(R.id.btnToggleControl)
                val connect = a.findViewById<Button>(R.id.btnConnect)
                val disconnect = a.findViewById<Button>(R.id.btnDisconnect)
                val settings = a.findViewById<Button>(R.id.btnSettings)

                for ((name, v) in listOf(
                    "btnToggleControl" to toggle,
                    "btnConnect" to connect,
                    "btnDisconnect" to disconnect,
                    "btnSettings" to settings
                )) {
                    assertTrue("$name is not visible", v.visibility == android.view.View.VISIBLE)
                    assertTrue(
                        "$name is ${v.height}px tall, below the ${minPx}px (48dp) minimum",
                        v.height >= minPx - 1
                    )
                    assertTrue("$name has no width", v.width > 0)
                }

                // They share one row and must not overlap each other.
                val order = listOf(toggle, connect, disconnect, settings)
                for (i in 0 until order.size - 1) {
                    val left = order[i]
                    val right = order[i + 1]
                    assertTrue(
                        "controls overlap: one ends at ${left.right}, the next starts at ${right.left}",
                        left.right <= right.left
                    )
                }
            }
        }
    }

    /**
     * The slider is gone from the main screen — that was the whole point, and a
     * stale copy left behind would silently compete with the real one for the
     * same preference.
     */
    @Test
    fun theMainScreenNoLongerCarriesTheSlider() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                assertEquals(
                    "the cursor-lift slider is still on the main screen",
                    null,
                    a.findViewById<SeekBar?>(R.id.seekCursorLift)
                )
            }
        }
    }
}
