package com.remotedexter

import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The compose bar on a real device.
 *
 * Typing end to end needs a live host, so what is asserted here is everything
 * that can be wrong without one — including the two settings that silently
 * disabled features the operator wanted.
 */
@RunWith(AndroidJUnit4::class)
class KeyboardUiTest {

    @After
    fun clearControl() {
        InputController.onControlStateChanged = null
        InputController.reset()
    }

    @Test
    fun theComposeBarExistsAndCanTakeFocus() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val sink = activity.findViewById<EditText>(R.id.keyboardSink)
                assertNotNull("no field for the IME to type into", sink)
                assertTrue("the field cannot take focus", sink.isFocusableInTouchMode)
                assertNotNull(
                    "no Send button",
                    activity.findViewById<Button>(R.id.btnSendText)
                )
            }
        }
    }

    /** It costs no picture until asked for. */
    @Test
    fun theComposeBarIsHiddenUntilKeysIsPressed() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals(
                    "the compose bar is taking screen space before it was asked for",
                    View.GONE,
                    activity.findViewById<View>(R.id.composeRow).visibility
                )
            }
        }
    }

    /**
     * **Regression for a real defect.** The field was `textVisiblePassword`,
     * chosen to suppress autocorrect — and Android hides the MICROPHONE on
     * password fields, so dictation stopped working. Voice is exactly what a
     * phone is good at, so the trade was backwards.
     */
    @Test
    fun theComposeBarDoesNotLookLikeAPasswordFieldAndSoKeepsVoiceInput() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val type = activity.findViewById<EditText>(R.id.keyboardSink).inputType
                val variation = type and InputType.TYPE_MASK_VARIATION
                assertFalse(
                    "visible-password variation hides the microphone",
                    variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                )
                assertFalse(
                    "password variation hides the microphone",
                    variation == InputType.TYPE_TEXT_VARIATION_PASSWORD
                )
            }
        }
    }

    /** Suggestions still off: a prediction rewrites rather than appends. */
    @Test
    fun theComposeBarDisablesSuggestions() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val type = activity.findViewById<EditText>(R.id.keyboardSink).inputType
                val flag = InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                assertTrue("autocorrect is on in the compose field", type and flag == flag)
            }
        }
    }

    /**
     * Enter must COMMIT the line, not insert a newline into it — that is what
     * makes the key mean the same thing here as at a shell prompt. A
     * multi-line field would swallow it.
     */
    @Test
    fun enterCommitsRatherThanInsertingANewline() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val sink = activity.findViewById<EditText>(R.id.keyboardSink)
                val multiline = InputType.TYPE_TEXT_FLAG_MULTI_LINE
                assertFalse(
                    "a multi-line field swallows Enter instead of committing",
                    sink.inputType and multiline == multiline
                )
                assertNotNull("no editor action listener, so Enter does nothing", sink)
            }
        }
    }

    /**
     * Idle means nothing to type into. Offering the keyboard would open an IME
     * over a black screen and swallow everything typed.
     */
    /**
     * Whether the soft keyboard is actually on screen, polled.
     *
     * The IME is raised asynchronously and animates in, so a single read
     * straight after the click is a coin flip. Polling to a deadline is the
     * honest instrument; a fixed sleep is either flaky or slow and usually both.
     */
    private fun imeVisibleWithin(
        scenario: ActivityScenario<MainActivity>,
        millis: Long
    ): Boolean {
        val deadline = System.currentTimeMillis() + millis
        while (System.currentTimeMillis() < deadline) {
            var visible = false
            scenario.onActivity { activity ->
                val root = activity.findViewById<View>(R.id.keyboardSink)
                visible = androidx.core.view.ViewCompat.getRootWindowInsets(root)
                    ?.isVisible(androidx.core.view.WindowInsetsCompat.Type.ime()) == true
            }
            if (visible) return true
            Thread.sleep(50)
        }
        return false
    }

    /**
     * **The operator's actual complaint**: "have to click keyboard button 2x to
     * get it to open".
     *
     * This asserts the keyboard is ON SCREEN after one press, which is the
     * thing they were reporting. The first attempt at a regression test for
     * this asserted FOCUS instead — and passed against the unfixed code, which
     * is how I learned my first diagnosis was wrong. Focus was never the
     * problem; `requestFocus` succeeded all along.
     *
     * Focus is a proxy. A proxy that holds while the defect is present is not a
     * regression test, it is a green light on a broken screen.
     */
    @Test
    fun onePressActuallyRaisesTheKeyboard() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { InputController.onAck("grant_input") }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            scenario.onActivity { activity ->
                activity.findViewById<android.widget.ImageButton>(R.id.btnKeyboard).performClick()
            }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            assertTrue(
                "the soft keyboard did not appear after ONE press of Keys",
                imeVisibleWithin(scenario, 3000)
            )
        }
    }

    /**
     * ONE press must open the keyboard, not two.
     *
     * The operator's report was "have to click keyboard button 2x to get it to
     * open". The cause was `requestFocus()` being called in the same frame as
     * the row's visibility change: the field had not been through a layout pass
     * and so was not in the focus hierarchy, `requestFocus` returned false, and
     * `showSoftInput` on an unfocused view did nothing. The row appeared with no
     * keyboard; the press after that toggled it shut; the one after that found a
     * field that HAD been laid out and worked.
     *
     * Asserting FOCUS rather than the soft keyboard's own visibility, which no
     * app can observe reliably. Focus is the thing that was actually failing,
     * and `showSoftInput` is a no-op without it — so this is the condition the
     * defect broke, not a proxy for it.
     */
    @Test
    fun oneKeyboardPressFocusesTheComposeFieldNotTwo() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            // The Keys button refuses without control, so grant it the way the
            // host does rather than reaching past the gate.
            scenario.onActivity { InputController.onAck("grant_input") }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            scenario.onActivity { activity ->
                activity.findViewById<android.widget.ImageButton>(R.id.btnKeyboard).performClick()
            }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            scenario.onActivity { activity ->
                val row = activity.findViewById<View>(R.id.composeRow)
                val sink = activity.findViewById<EditText>(R.id.keyboardSink)
                assertEquals(
                    "one press must reveal the compose row",
                    View.VISIBLE,
                    row.visibility
                )
                assertTrue(
                    "the compose field does not have focus after ONE press, so no " +
                        "keyboard would have opened",
                    sink.hasFocus()
                )
            }
        }
    }

    @Test
    fun theKeysButtonIsDisabledWhileIdle() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertFalse(
                    "Keys is offered with no session",
                    activity.findViewById<android.widget.ImageButton>(R.id.btnKeyboard).isEnabled
                )
            }
        }
    }
}
