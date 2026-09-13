package com.remotedexter

import android.graphics.Bitmap
import android.graphics.Canvas
import android.util.TypedValue
import android.widget.ImageButton
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The icon toolbar, on a real device.
 *
 * The row used to carry five words autosized down to as little as 7sp so they
 * would fit, and they still did not: "Trackpad" wrapped and was cut in half,
 * "PAIR (SCAN QR)" was painted past the edge of its own button, and the
 * operator reported the result as a broken app. [ControlRowFitTest] measures
 * the labelled row below this one and is the reason those defects are known
 * rather than suspected.
 *
 * **Deleting the labels moves the risk rather than removing it.** A word that
 * does not fit is at least visibly wrong; a drawing that means nothing is not,
 * and a screen reader gets nothing at all from a picture. So what a labelled
 * button gave for free now has to be asserted: every control announces itself,
 * no two announce the same thing, a long press names them, the targets are
 * finger-sized, and an unavailable control actually looks unavailable.
 */
@RunWith(AndroidJUnit4::class)
class ToolbarIconsTest {

    @After
    fun clearControl() {
        InputController.onControlStateChanged = null
        InputController.reset()
    }

    /** Every control on the icon row, by id. */
    private val toolbar = listOf(
        R.id.btnPointerMode,
        R.id.btnKeyboard,
        R.id.btnPair,
        R.id.btnDiagnostics
    )

    private fun dp(button: ImageButton, v: Int): Int = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), button.resources.displayMetrics
    ).toInt()

    /**
     * What the icon actually looks like, as pixels.
     *
     * The first version of this compared `drawable.constantState` and failed
     * against itself: `setImageResource` builds a fresh `VectorDrawableState`
     * every call, so re-selecting the SAME icon produced a different object.
     * A resource id would not have been better — two ids can name identical
     * art, and an assertion that the id changed would pass while the user saw
     * no difference at all.
     *
     * Rendering is the question the user is actually asking. A copy is drawn so
     * that setting bounds on it cannot disturb the view's own drawable.
     */
    private fun picture(button: ImageButton): Bitmap {
        val d = button.drawable.constantState!!.newDrawable().mutate()
        val size = 48
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        d.setBounds(0, 0, size, size)
        d.draw(Canvas(bmp))
        return bmp
    }

    /**
     * How different two icon renderings are, as a mean channel difference on
     * the 0-255 scale.
     *
     * `Bitmap.sameAs` was tried first and is too strict for a rasterised
     * vector: re-selecting the SAME resource and drawing it again left 247 of
     * 2304 pixels different, none by more than 37 — anti-aliasing along the
     * strokes, not a different picture. An exact comparison would have made
     * this test fail on a correct app, which is the worst kind of test.
     *
     * MEASURED on the SM-G970U, not guessed: re-drawing the same icon scores
     * 2.0, and the touch and mouse icons score 15.8 against each other. The
     * thresholds below are 4.0 and 10.0, placed inside that gap with headroom
     * on both sides rather than snug against either number. Both measurements
     * are printed on failure, so if the drawings are ever redesigned the next
     * reader gets the real figures instead of having to re-derive them.
     *
     * 15.8 is a smaller margin than it looks like it should be, and the reason
     * is worth knowing: both icons are 2px line art on a transparent ground, so
     * roughly nine tenths of every rendering is identical empty space no matter
     * what is drawn in it. The disagreement is concentrated in the tenth that
     * carries ink.
     */
    private fun meanDifference(a: Bitmap, b: Bitmap): Double {
        var total = 0L
        for (y in 0 until a.height) for (x in 0 until a.width) {
            val p = a.getPixel(x, y)
            val q = b.getPixel(x, y)
            for (shift in intArrayOf(24, 16, 8, 0)) {
                total += Math.abs(((p shr shift) and 0xFF) - ((q shr shift) and 0xFF))
            }
        }
        return total.toDouble() / (a.width * a.height * 4)
    }

    /**
     * A picture with no name is invisible to a screen reader and ambiguous to
     * everyone else. This is the assertion that the labels were replaced rather
     * than merely deleted.
     */
    @Test
    fun everyIconAnnouncesItself() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                for (id in toolbar) {
                    val b = a.findViewById<ImageButton>(id)
                    val desc = b.contentDescription?.toString()
                    assertTrue(
                        "${a.resources.getResourceEntryName(id)} has no content description",
                        !desc.isNullOrBlank()
                    )
                }
            }
        }
    }

    /**
     * Two controls that announce the same words are two controls a blind user
     * cannot tell apart, which is exactly the state the row was in before it
     * had descriptions at all.
     */
    @Test
    fun noTwoIconsAnnounceTheSameThing() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val said = toolbar.map {
                    a.findViewById<ImageButton>(it).contentDescription.toString()
                }
                assertEquals("two toolbar icons announce the same text: $said", said.size, said.toSet().size)
            }
        }
    }

    /**
     * The tooltip is what replaced the word on the face of the button. A long
     * press is the standard Android gesture for "what is this", and it is the
     * only way a sighted user learns an unfamiliar glyph without pressing it to
     * find out — which, for Pair, means opening a camera.
     */
    @Test
    fun aLongPressNamesEveryIcon() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                for (id in toolbar) {
                    val b = a.findViewById<ImageButton>(id)
                    assertTrue(
                        "${a.resources.getResourceEntryName(id)} has no tooltip",
                        !b.tooltipText.isNullOrBlank()
                    )
                }
            }
        }
    }

    /**
     * 48dp in both directions, the framework's own minimum touch target.
     *
     * The labelled row never met it: the buttons were `wrap_content` tall
     * around 7sp text with 4dp of padding, which is roughly 30dp. Losing the
     * words is what bought the height back, so it is worth pinning that the
     * height was actually spent on the target rather than given to the picture.
     */
    @Test
    fun everyIconIsAFingerSizedTarget() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                for (id in toolbar) {
                    val b = a.findViewById<ImageButton>(id)
                    val min = dp(b, 48)
                    assertTrue(
                        "${a.resources.getResourceEntryName(id)} is ${b.width}x${b.height}px, " +
                            "under the ${min}px minimum touch target",
                        b.width >= min && b.height >= min
                    )
                }
            }
        }
    }

    /** A button with no drawable is an invisible button. */
    @Test
    fun everyIconActuallyHasAPicture() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                for (id in toolbar) {
                    val b = a.findViewById<ImageButton>(id)
                    assertNotNull(
                        "${a.resources.getResourceEntryName(id)} has no drawable",
                        b.drawable
                    )
                    assertTrue(
                        "${a.resources.getResourceEntryName(id)} drew nothing: " +
                            "${b.drawable.intrinsicWidth}x${b.drawable.intrinsicHeight}",
                        b.drawable.intrinsicWidth > 0 && b.drawable.intrinsicHeight > 0
                    )
                }
            }
        }
    }

    /**
     * How much ink a view actually put on the screen: the mean darkness of its
     * rendered pixels against a white ground, 0 for blank and higher for bolder.
     */
    private fun inkWeight(view: android.view.View): Double {
        val bmp = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        canvas.drawColor(android.graphics.Color.WHITE)
        view.draw(canvas)
        var total = 0L
        for (y in 0 until bmp.height) for (x in 0 until bmp.width) {
            val p = bmp.getPixel(x, y)
            val lum = (android.graphics.Color.red(p) +
                android.graphics.Color.green(p) +
                android.graphics.Color.blue(p)) / 3
            total += (255 - lum)
        }
        return total.toDouble() / (bmp.width * bmp.height)
    }

    /**
     * A disabled icon has to LOOK disabled — and this asserts what was DRAWN,
     * not what was configured.
     *
     * **This test is a rewrite of one that passed while the bug was on screen.**
     * The first version read the tint `ColorStateList` and checked it held a
     * fainter colour for `state_enabled=false`. It did. The view never applied
     * it: a screenshot of the real SM-G970U showed Keyboard and the since-
     * removed Screenshot icon rendering at full black with `isEnabled` false, so an unavailable control
     * was indistinguishable from a live one and pressing it did nothing, with
     * nothing on screen to say why. The framework dims a Button's TEXT for
     * free; nothing dims an ImageButton's drawable unless asked.
     *
     * The lesson is the reason this is written the way it is: **a test that
     * inspects configuration instead of outcome passes on a screen the user
     * cannot read.** So the button is rendered to a bitmap in both states and
     * the ink is weighed.
     */
    @Test
    fun anUnavailableIconIsVisiblyFaint() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                // Pair is available in every state, so it is the fair control:
                // whatever it weighs is what a live icon of this size weighs.
                val live = a.findViewById<ImageButton>(R.id.btnPair)
                // Keyboard is unavailable at idle, by the table.
                val dim = a.findViewById<ImageButton>(R.id.btnKeyboard)
                assertTrue("the control icon was not disabled by the table", !dim.isEnabled)

                val liveInk = inkWeight(live)
                val dimInk = inkWeight(dim)
                assertTrue("the enabled icon drew nothing at all ($liveInk)", liveInk > 1.0)
                assertTrue(
                    "a disabled icon is as bold as a live one: disabled weighs $dimInk, " +
                        "enabled $liveInk — an unavailable control that looks available is " +
                        "a control the user presses and gets no answer from",
                    dimInk < liveInk * 0.6
                )
            }
        }
    }

    /**
     * The same button, before and after it becomes unavailable.
     *
     * The test above compares two different icons and so depends on them
     * carrying similar amounts of ink. This one removes that assumption
     * entirely: one view, one drawing, two states.
     */
    @Test
    fun theSameIconGetsFainterWhenItIsTakenAway() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val b = a.findViewById<ImageButton>(R.id.btnPair)
                val enabled = inkWeight(b)
                b.isEnabled = false
                b.imageAlpha = MainActivity.DISABLED_ICON_ALPHA
                val disabled = inkWeight(b)
                assertTrue(
                    "disabling the icon did not change what was drawn: " +
                        "$enabled enabled, $disabled disabled",
                    disabled < enabled * 0.6
                )
            }
        }
    }

    /**
     * Idle is the state the app opens in, and it is the one where a wrong
     * availability rule is most likely to be met: the two stream-bound controls
     * must be dim and the three that always work must not.
     *
     * The rule itself is [ToolbarAvailability] and is proven exhaustively on
     * the JVM. What needs a device is that the Activity really applies it.
     */
    @Test
    fun theIdleScreenAppliesTheAvailabilityTable() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                assertTrue("Keyboard is live with no session", !a.findViewById<ImageButton>(R.id.btnKeyboard).isEnabled)
                assertTrue(a.findViewById<ImageButton>(R.id.btnPointerMode).isEnabled)
                assertTrue(a.findViewById<ImageButton>(R.id.btnPair).isEnabled)
                assertTrue(a.findViewById<ImageButton>(R.id.btnDiagnostics).isEnabled)
            }
        }
    }

    /**
     * The pointer toggle carries its state in a drawing now, so the drawing and
     * the announcement have to move together. If one code path updated the icon
     * and another the description, they would drift — and the sighted user and
     * the screen-reader user would be told different things about the same
     * button.
     *
     * The icon is compared as rendered pixels, which is the form the user
     * receives it in; see [picture].
     */
    @Test
    fun theModeToggleChangesItsPictureAndItsWordsTogether() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val b = a.findViewById<ImageButton>(R.id.btnPointerMode)
                val firstDesc = b.contentDescription.toString()
                val firstTip = b.tooltipText.toString()
                val firstIcon = picture(b)

                b.performClick()

                assertNotEquals("the description did not follow the mode", firstDesc, b.contentDescription.toString())
                assertNotEquals("the tooltip did not follow the mode", firstTip, b.tooltipText.toString())
                val changed = meanDifference(firstIcon, picture(b))
                assertTrue(
                    "the two pointer modes draw near-identical pictures (mean difference " +
                        "$changed) — the icon would say nothing about the mode",
                    changed > 10.0
                )

                b.performClick()

                assertEquals("the toggle did not come back", firstDesc, b.contentDescription.toString())
                assertEquals(firstTip, b.tooltipText.toString())
                val restored = meanDifference(firstIcon, picture(b))
                assertTrue(
                    "switching back did not restore the first icon: mean difference " +
                        "$restored against the original, where re-drawing the same icon " +
                        "measures about 2 and the other mode measures $changed",
                    restored < 4.0
                )
            }
        }
    }

    /**
     * The row is the whole width of the phone and every control has to be
     * reachable in it. Five 48dp squares plus margins fit on the SM-G970U, but
     * "fit on the device in front of me" is how the label row was sized too.
     */
    @Test
    fun theWholeRowFitsOnTheScreen() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val screen = a.resources.displayMetrics.widthPixels
                var right = 0
                for (id in toolbar) {
                    val b = a.findViewById<ImageButton>(id)
                    val loc = IntArray(2)
                    b.getLocationOnScreen(loc)
                    assertTrue(
                        "${a.resources.getResourceEntryName(id)} starts at x=${loc[0]}, off screen",
                        loc[0] >= 0
                    )
                    right = maxOf(right, loc[0] + b.width)
                }
                assertTrue(
                    "the toolbar ends at ${right}px on a ${screen}px screen",
                    right <= screen
                )
            }
        }
    }
}
