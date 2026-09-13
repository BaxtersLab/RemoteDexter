package com.remotedexter

import android.content.res.Configuration
import android.view.View
import android.view.ViewGroup
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The control column, when the phone is held sideways.
 *
 * The operator: *"when i turn it sideways the button pannel takes 50% of the
 * screen (entire right side)"*. It did, and one row is why — ENABLE + CONNECT +
 * DISCONNECT + Settings measure 340dp on a single line, and a column can be no
 * narrower than its widest row. `reflowPanel` gives the two crowded rows a
 * second line in landscape so the column can be 200dp.
 *
 * The risk in doing it that way is not the landscape arrangement, which is
 * visible the moment anyone looks. It is **coming back**: a button that does not
 * return to its own row, or returns to the wrong position, after a rotation.
 * That is what these assert.
 */
@RunWith(AndroidJUnit4::class)
class PanelReflowTest {

    private fun config(activity: MainActivity, orientation: Int): Configuration =
        Configuration().apply {
            setTo(activity.resources.configuration)
            this.orientation = orientation
        }

    private fun parentIdOf(activity: MainActivity, id: Int): Int =
        (activity.findViewById<View>(id).parent as ViewGroup).id

    private fun indexOf(activity: MainActivity, id: Int): Int {
        val v = activity.findViewById<View>(id)
        return (v.parent as ViewGroup).indexOfChild(v)
    }

    /**
     * Sideways, the crowded buttons move to their second rows; upright, they go
     * back to exactly where they started — same parent, same position.
     */
    @Test
    fun rotatingSidewaysAndBackRestoresEveryButtonExactly() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val moved = listOf(
                    R.id.btnClipToHost, R.id.btnClipFromHost,
                    R.id.btnDisconnect, R.id.btnSettings
                )
                val before = moved.associateWith {
                    Pair(parentIdOf(activity, it), indexOf(activity, it))
                }

                activity.onConfigurationChanged(
                    config(activity, Configuration.ORIENTATION_LANDSCAPE)
                )
                assertEquals(
                    "the clipboard buttons must move to the second chord row",
                    R.id.chordRow2, parentIdOf(activity, R.id.btnClipFromHost)
                )
                assertEquals(
                    "Disconnect must move to the second control row",
                    R.id.controlRow2, parentIdOf(activity, R.id.btnDisconnect)
                )
                assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.chordRow2).visibility)
                assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.controlRow2).visibility)

                activity.onConfigurationChanged(
                    config(activity, Configuration.ORIENTATION_PORTRAIT)
                )
                for (id in moved) {
                    assertEquals(
                        "a button did not return to its own row",
                        before[id]!!.first, parentIdOf(activity, id)
                    )
                    assertEquals(
                        "a button returned to the wrong position in its row",
                        before[id]!!.second, indexOf(activity, id)
                    )
                }
                assertEquals(View.GONE, activity.findViewById<View>(R.id.chordRow2).visibility)
                assertEquals(View.GONE, activity.findViewById<View>(R.id.controlRow2).visibility)
            }
        }
    }

    /** Rotating twice must not accumulate. The second trip has to be a no-op. */
    @Test
    fun rotatingRepeatedlyDoesNotDriftTheArrangement() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val before = Pair(
                    parentIdOf(activity, R.id.btnSettings),
                    indexOf(activity, R.id.btnSettings)
                )
                repeat(3) {
                    activity.onConfigurationChanged(
                        config(activity, Configuration.ORIENTATION_LANDSCAPE)
                    )
                    activity.onConfigurationChanged(
                        config(activity, Configuration.ORIENTATION_PORTRAIT)
                    )
                }
                assertEquals(before.first, parentIdOf(activity, R.id.btnSettings))
                assertEquals(before.second, indexOf(activity, R.id.btnSettings))
            }
        }
    }

    /**
     * Proof the reflow is necessary rather than decoration.
     *
     * If those four buttons ever fit inside the column on one line, the second
     * row is dead weight and this whole mechanism should go. They do not: the
     * row is the reason the column was 340dp.
     */
    @Test
    fun theControlRowGenuinelyDoesNotFitTheColumnOnOneLine() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val column = activity.resources.getDimensionPixelSize(R.dimen.controls_panel_width)
                val row = listOf(
                    R.id.btnToggleControl, R.id.btnConnect,
                    R.id.btnDisconnect, R.id.btnSettings
                ).sumOf { activity.findViewById<View>(it).width }
                assertTrue(
                    "the four session controls measured ${row}px and the column is " +
                        "${column}px — if they fit, the second row is unnecessary",
                    row > column
                )
                assertNotEquals("the buttons were never laid out", 0, row)
            }
        }
    }
}
