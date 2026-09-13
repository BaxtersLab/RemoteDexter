package com.remotedexter

import android.util.TypedValue
import android.widget.Button
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The lower session row must stay usable now that the cursor-lift slider has
 * taken a third of its width.
 *
 * This is a regression test for a defect `CursorLiftUiTest` did not catch: that
 * suite asserted the row's 48dp touch targets and never asserted the labels
 * still *fit*, so it passed 6/6 while "Enable Control" was sliced in half on
 * the device. A button whose own name is unreadable reads as a broken app, and
 * the operator reported it as a crash.
 *
 * Measuring beats eyeballing: `Layout` knows exactly how tall the text it laid
 * out is, and the view knows how much room it gave it.
 */
@RunWith(AndroidJUnit4::class)
class ControlRowFitTest {

    @After
    fun clearControl() {
        InputController.onControlStateChanged = null
        InputController.reset()
    }

    private fun dpToPx(button: Button, dp: Int): Int = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP, dp.toFloat(), button.resources.displayMetrics
    ).toInt()

    /**
     * Why [button]'s text does not fit, or null when it does.
     *
     * [allowedLines] is the number of lines the label is DESIGNED for — one for
     * a toolbar button, two for Enable Control. It is asserted here rather than
     * left to `android:maxLines` because **autosize silently overrides
     * maxLines**: `btnPair` carried `maxLines="1"` and still laid out two lines,
     * shrinking to 7.7sp to do it. The XML attribute is a request; this is the
     * contract.
     */
    private fun clipping(button: Button, state: String, allowedLines: Int = 1): String? {
        val layout = button.layout ?: return "$state: the button was never laid out"
        val free = button.height - button.compoundPaddingTop - button.compoundPaddingBottom
        if (layout.height > free) {
            return "$state: \"${button.text}\" needs ${layout.height}px over " +
                "${layout.lineCount} line(s) but only ${free}px are free inside a " +
                "${button.height}px-tall button — the label is cut off"
        }
        for (line in 0 until layout.lineCount) {
            if (layout.getEllipsisCount(line) > 0) {
                return "$state: \"${button.text}\" is ellipsised on line $line"
            }
        }
        // Horizontal overflow with NO ellipsis and a single line. This is how
        // "PAIR (SCAN QR)" rendered as "PAIR (SCAN" — autosize bottomed out at
        // its minimum and the remainder was simply painted outside the view.
        // Neither the height check nor the ellipsis check can see it, because
        // nothing about the layout is wrong; it is only too wide.
        val room = button.width - button.compoundPaddingLeft - button.compoundPaddingRight
        for (line in 0 until layout.lineCount) {
            val used = layout.getLineWidth(line)
            if (used > room + 1f) {
                return "$state: \"${button.text}\" needs ${used.toInt()}px on line " +
                    "$line but only ${room}px are free inside a ${button.width}px-wide " +
                    "button — the label is cut off at the edge"
            }
        }
        // Wrapping past the design. The height check above cannot see this in a
        // wrap_content button — the row is simply given the room to be wrong in
        // — and in a fixed-height one it reports a symptom rather than a cause.
        // This is what "CONNECT" rendering as "CONN/ECT" and "PAIR (SCAN/QR)"
        // actually are.
        if (layout.lineCount > allowedLines) {
            return "$state: \"${button.text}\" wrapped onto ${layout.lineCount} " +
                "lines but is designed for $allowedLines — the button is too narrow " +
                "for its own label (autosize shrank it to ${button.textSize}px and " +
                "wrapped anyway)"
        }
        return null
    }

    private fun toggle(activity: MainActivity): Button =
        activity.findViewById(R.id.btnToggleControl)

    @Test
    fun theEnableLabelFitsInsideItsButton() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var problem: String? = "the activity never ran"
            scenario.onActivity { problem = clipping(toggle(it), "Enable") }
            assertNull(problem, problem)
        }
    }

    @Test
    fun theDisableLabelFitsInsideItsButton() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            // Drive the real state change rather than calling setText by hand:
            // the label the operator sees is the one the controller sets.
            scenario.onActivity { InputController.onAck("grant_input") }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            var problem: String? = "the activity never ran"
            scenario.onActivity { problem = clipping(toggle(it), "Disable") }
            assertNull(problem, problem)
        }
    }

    /**
     * Every label in the session row, not just the control button's.
     *
     * This test exists because of a defect it would have caught. Block 9's
     * Connect button was first added to the utility toolbar above, taking it
     * from five buttons to six; on the SM-G970U "Connect" then rendered as
     * "CONN/ECT" and Pair as "PAIR (SCA/N QR)". Nothing failed, because the
     * only fit coverage measured `btnToggleControl` alone. A row is a shared
     * width budget: adding anything to it can break something else, so the
     * assertion has to span the row rather than one member of it.
     */
    @Test
    fun everySessionRowLabelFits() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var problem: String? = "the activity never ran"
            scenario.onActivity { activity ->
                problem = listOf(
                    Triple(R.id.btnToggleControl, "Enable", 1),
                    Triple(R.id.btnConnect, "Connect", 1),
                    Triple(R.id.btnDisconnect, "Disconnect", 1),
                    // Added when the toolbar above lost its labels: Settings is
                    // the fourth thing in this row's width budget and had never
                    // been measured, which is the same gap that let "CONN/ECT"
                    // ship — coverage of a row that stopped at three of its
                    // members.
                    Triple(R.id.btnSettings, "Settings", 1)
                ).firstNotNullOfOrNull { (id, name, lines) ->
                    clipping(activity.findViewById(id), name, lines)
                }
            }
            assertNull(problem, problem)
        }
    }

    /*
     * REMOVED 2026-08-29, and replaced rather than dropped.
     *
     * Two tests lived here — `everyUtilityRowLabelFits` and
     * `thePointerToggleFitsInBothOfItsLabels` — and both measured whether the
     * words on the utility toolbar were being cut off. That row has no words on
     * it any more: it is five icons, so there is no label to clip and the
     * measurement has nothing left to measure. A test kept alive over an
     * absent property passes for the wrong reason, which is worse than no test.
     *
     * The property they were really defending — that every control on that row
     * stays legible and reachable — moved to `ToolbarIconsTest`, in the terms
     * an icon row can be judged by: a content description on every control, no
     * two of them announcing the same thing, a tooltip naming each one, a 48dp
     * touch target (which the labelled row never actually met), a drawable that
     * is really there, a disabled icon that is visibly fainter, and the whole
     * row fitting inside the screen. That last one is the direct descendant of
     * "PAIR (SCAN QR)" being painted past the edge of its own button.
     *
     * Net instrumentation count: -2 here, +9 there.
     */

    /**
     * The chord row's three labels, measured.
     *
     * `"Ctrl+C"` rendering as `"CTRL/+C"` is not hypothetical — it shipped once,
     * on this row's ancestor, and no test saw it. Three labels sharing one
     * phone width is exactly the arrangement that produced it, and a chord
     * button whose own name is broken across two lines reads as a broken app.
     */
    @Test
    fun everyChordLabelFits() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var problem: String? = "the activity never ran"
            scenario.onActivity { activity ->
                problem = listOf(
                    R.id.btnCopyChord to "Ctrl+C",
                    R.id.btnPasteChord to "Ctrl+V",
                    R.id.btnPrintScreen to "PrtScn",
                    // The clipboard bridge took this row from three buttons to
                    // five. A row is a shared width budget and adding to it can
                    // break something that already fitted — which is exactly
                    // how Connect once turned "PAIR (SCAN QR)" into "PAIR (SCAN".
                    R.id.btnClipToHost to "to host",
                    R.id.btnClipFromHost to "from host"
                ).firstNotNullOfOrNull { (id, name) ->
                    clipping(activity.findViewById(id), name)
                }
            }
            assertNull(problem, problem)
        }
    }

    /**
     * The chord buttons stay pressable in every state, ON PURPOSE.
     *
     * They were nearly disabled when unavailable, which is what the dead
     * `PrtScr` icon did — and a disabled view swallows the tap entirely: no
     * ripple, no haptic, the listener never runs. The operator hit exactly
     * that and reported it as "maybe only long tap works". A refusal nobody can
     * see is indistinguishable from a bug.
     *
     * So they always respond, and say which of the two things is missing. The
     * emission itself is gated by `KeyChord.press`, proven on the JVM.
     */
    @Test
    fun theChordAndClipboardButtonsAlwaysAnswerEvenWhenTheyCannotAct() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                for (id in listOf(
                    R.id.btnPasteChord, R.id.btnCopyChord, R.id.btnPrintScreen,
                    R.id.btnClipToHost, R.id.btnClipFromHost
                )) {
                    val b = activity.findViewById<Button>(id)
                    assertTrue(
                        "${activity.resources.getResourceEntryName(id)} is disabled, so a " +
                            "tap on it would do nothing and say nothing",
                        b.isEnabled
                    )
                    assertTrue("it has no click listener", b.hasOnClickListeners())
                }
            }
        }
    }

    /**
     * The control toggle must fit in BOTH of its labels, at the width it now
     * takes rather than a third of the row.
     *
     * "Enable Control" needed two lines and autosizing down to 9sp to fit a
     * space it had been given rather than one it needed. The row now sizes
     * buttons to their text, so the labels are short and the autosizing is
     * gone — which means nothing is left to rescue a label that does not fit,
     * and this is the test that would catch it.
     */
    @Test
    fun theControlToggleFitsInBothOfItsLabels() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var problem: String? = "the activity never ran"
            scenario.onActivity { problem = clipping(toggle(it), "Enable") }
            assertNull(problem, problem)
            scenario.onActivity { InputController.onAck("grant_input") }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { problem = clipping(toggle(it), "Disable") }
            assertNull(problem, problem)
        }
    }

    /**
     * Connect and Disconnect are never both live.
     *
     * They sit side by side, so this is what makes that safe: whichever one is
     * wrong for the current state is inert, and a mis-tap does nothing rather
     * than ending a session. It is also the honest reading of "idle" — with no
     * session and nothing paired, neither button has anything to do.
     */
    @Test
    fun connectAndDisconnectAreNeverBothEnabled() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val connect = activity.findViewById<Button>(R.id.btnConnect)
                val disconnect = activity.findViewById<Button>(R.id.btnDisconnect)
                assertTrue(
                    "Connect and Disconnect are both enabled",
                    !(connect.isEnabled && disconnect.isEnabled)
                )
            }
        }
    }

    /**
     * The prompt's floor, measured rather than assumed: Enable/Disable Control
     * and Disconnect are the session-critical actions and must remain
     * dependable finger targets on the physical SM-G970U.
     */
    @Test
    fun theSessionCriticalButtonsKeepTheirFortyEightDpHeight()  {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val floor = dpToPx(toggle(activity), 48)
                for (id in listOf(
                    R.id.btnToggleControl,
                    R.id.btnConnect,
                    R.id.btnDisconnect
                )) {
                    val button = activity.findViewById<Button>(id)
                    assertTrue(
                        "${activity.resources.getResourceEntryName(id)} is " +
                            "${button.height}px tall, below the ${floor}px (48dp) floor",
                        button.height >= floor
                    )
                }
            }
        }
    }
}
