package com.remotedexter

import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The paired-host list on a real device.
 *
 * **Nothing here writes to the pairing stores.** `PairedHostTest` carries an
 * explicit note about why: an on-device test of `PairedHostStore`, the registry
 * or `DeviceUnpair` writes to the app's real `SharedPreferences` and would
 * unpair the operator's phone on every gate run, and a test that damages the
 * state it exists to protect is worse than the gap. So the rows are rendered
 * from records made up here, through `renderHostRows`, and the storage layer is
 * proven on the JVM by `PairedHostListTest`.
 *
 * The same applies to the enrollment line. Arming for real would leave an open
 * window on the operator's phone — a side effect with a security meaning, not a
 * tidiness problem — so the line is rendered from a given clock instead.
 */
@RunWith(AndroidJUnit4::class)
class PairedHostListUiTest {

    private val pin = "a".repeat(64)

    private fun record(identity: String, addr: String, port: Int = 8081) =
        PairedHostRecord.of(identity, addr, port, pin)!!

    private val desk = record("DESKidentitykeyvalue=", "192.168.1.9")
    private val dell = record("DELLidentitykeyvalue=", "192.168.1.40", 9001)

    private fun rows(a: SettingsActivity): LinearLayout =
        a.findViewById(R.id.pairedHostList)

    @Test
    fun everyPairedHostGetsARow() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                a.renderHostRows(listOf(desk, dell), desk.identityB64)
                assertEquals(2, rows(a).childCount)
                val first = rows(a).getChildAt(0)
                assertTrue(
                    "the row must name the host by address",
                    first.findViewById<TextView>(R.id.txtHostLabel).text.contains("192.168.1.9")
                )
                assertTrue(
                    "the row must show the fingerprint",
                    first.findViewById<TextView>(R.id.txtHostFingerprint).text
                        .contains(desk.fingerprint())
                )
            }
        }
    }

    @Test
    fun anEmptyListShowsNoRows() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                a.renderHostRows(listOf(desk), desk.identityB64)
                a.renderHostRows(emptyList(), null)
                assertEquals(0, rows(a).childCount)
            }
        }
    }

    /**
     * An empty list is never left unexplained.
     *
     * There used to be TWO explanations and on the device they read as a
     * stutter — a placeholder saying "No host paired. Scan a QR from the main
     * screen." with the same instruction repeated three lines below it. The
     * placeholder went; this asserts the remaining line really does cover the
     * empty case, so removing it did not leave a blank area where guidance
     * used to be.
     */
    @Test
    fun anEmptyListIsStillExplained() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                a.renderHostRows(emptyList(), null)
                a.renderEnrollmentLine(null, 1_000L, hasHosts = false)
                val line = a.findViewById<TextView>(R.id.txtEnrollmentState).text.toString()
                assertTrue("an empty host list explains nothing", line.isNotBlank())
                assertEquals(
                    "the guidance must be visible, not merely set",
                    android.view.View.VISIBLE,
                    a.findViewById<TextView>(R.id.txtEnrollmentState).visibility
                )
            }
        }
    }

    /**
     * The active host has to be distinguishable, because choosing between them
     * is the list's entire job. Two rows that look identical make the choice
     * invisible — and Connect would then go somewhere the user did not pick,
     * with nothing on screen having said so.
     */
    @Test
    fun theHostConnectWillUseLooksDifferentFromTheRest() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                a.renderHostRows(listOf(desk, dell), dell.identityB64)
                val active = rows(a).getChildAt(1).findViewById<TextView>(R.id.txtHostLabel)
                val idle = rows(a).getChildAt(0).findViewById<TextView>(R.id.txtHostLabel)
                assertTrue("the active row is not emphasised", active.typeface?.isBold == true)
                assertTrue("an inactive row is emphasised", idle.typeface?.isBold != true)
                assertTrue(
                    "the active row's text does not say it is in use: ${active.text}",
                    active.text.toString() != dell.label()
                )
            }
        }
    }

    /**
     * A screen reader has to be told which host is in use too. The bold is
     * invisible to it, and "which one is active" is precisely the question
     * this screen exists to answer.
     */
    @Test
    fun theActiveRowSaysSoOutLoud() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                a.renderHostRows(listOf(desk, dell), dell.identityB64)
                val activeDesc = rows(a).getChildAt(1).contentDescription.toString()
                val idleDesc = rows(a).getChildAt(0).contentDescription.toString()
                assertTrue("descriptions do not distinguish the active host",
                    activeDesc != idleDesc)
                for (desc in listOf(activeDesc, idleDesc)) {
                    assertTrue("a row announces nothing", desc.isNotBlank())
                }
            }
        }
    }

    /**
     * Every row's Forget must name its own host. One shared label on a list of
     * destructive buttons is how the wrong pairing gets deleted.
     */
    @Test
    fun eachForgetButtonNamesTheHostItWouldRemove() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                a.renderHostRows(listOf(desk, dell), desk.identityB64)
                val first = rows(a).getChildAt(0)
                    .findViewById<Button>(R.id.btnForgetThisHost).contentDescription.toString()
                val second = rows(a).getChildAt(1)
                    .findViewById<Button>(R.id.btnForgetThisHost).contentDescription.toString()
                assertTrue(first.contains(desk.label()))
                assertTrue(second.contains(dell.label()))
                assertTrue("two Forget buttons announce the same host", first != second)
            }
        }
    }

    /**
     * Re-rendering must REPLACE the rows, not append to them. Settings re-reads
     * on every resume, so a list that grew each time would show the same host
     * three times after two trips to the main screen — and each copy would have
     * its own live Forget button.
     */
    @Test
    fun renderingTwiceDoesNotDuplicateTheList() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                a.renderHostRows(listOf(desk, dell), desk.identityB64)
                a.renderHostRows(listOf(desk, dell), desk.identityB64)
                a.renderHostRows(listOf(desk), desk.identityB64)
                assertEquals(1, rows(a).childCount)
            }
        }
    }

    // ── the enrollment line ───────────────────────────────────────────────

    /**
     * An armed phone says so, and says how long is left. An arm the operator
     * cannot see is one they cannot tell has expired, and the failure that
     * produces — a scan refused for a reason that was true five minutes ago —
     * is the silent refusal Block 5 existed to end.
     */
    @Test
    fun anArmedPhoneSaysSoAndCountsDown() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val t = 1_000_000L
                a.renderEnrollmentLine(t, t, hasHosts = true)
                val armed = a.findViewById<TextView>(R.id.txtEnrollmentState).text.toString()
                a.renderEnrollmentLine(t, t + EnrollmentArming.WINDOW_MS, hasHosts = true)
                val expired = a.findViewById<TextView>(R.id.txtEnrollmentState).text.toString()
                assertTrue("an armed phone says nothing about it", armed.isNotBlank())
                assertTrue(
                    "an expired arm still reads as armed: \"$expired\"",
                    expired != armed
                )
            }
        }
    }

    /**
     * The three states are three different sentences. A fresh install, a closed
     * door and an open one need different actions from the user, and a screen
     * that renders them the same way is a screen that answers no question.
     */
    @Test
    fun theThreeEnrollmentStatesReadDifferently() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                val text = a.findViewById<TextView>(R.id.txtEnrollmentState)
                val t = 2_000_000L
                a.renderEnrollmentLine(null, t, hasHosts = false)
                val fresh = text.text.toString()
                a.renderEnrollmentLine(null, t, hasHosts = true)
                val closed = text.text.toString()
                a.renderEnrollmentLine(t, t, hasHosts = true)
                val open = text.text.toString()
                assertEquals(
                    "the three enrollment states do not read as three states",
                    3,
                    setOf(fresh, closed, open).size
                )
                for (line in listOf(fresh, closed, open)) {
                    assertTrue("an enrollment state says nothing", line.isNotBlank())
                }
            }
        }
    }
}
