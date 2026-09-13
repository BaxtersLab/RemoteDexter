package com.remotedexter

import android.os.Bundle
import android.view.LayoutInflater
import android.widget.Button
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * Settings: the paired hosts, and the cursor lift.
 *
 * Exists because the main screen ran out of room. The cursor-lift slider was
 * taking a quarter of the bottom row from Enable Control, Connect and
 * Disconnect — a preference set once, holding space that session controls
 * needed every time.
 *
 * The host list is here for the opposite reason: it cannot live in a toolbar at
 * all, and this page has the room the main screen never will.
 *
 * ## This screen is where a new host is admitted
 *
 * Not incidental. The scan path refuses an identity this device does not
 * already know, and **Add a host** is the only thing that changes that — for
 * one host, for a few minutes. Putting it here rather than behind a prompt on
 * the scan itself is the operator's decision, and its point is that a QR alone
 * can never add a machine: adding one takes a deliberate act, on a different
 * screen, before the camera is opened. See [EnrollmentArming].
 */
class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        title = getString(R.string.settings)
        wireCursorLift()
        findViewById<Button>(R.id.btnAddHost).setOnClickListener { confirmArm() }
    }

    /**
     * Re-read on every resume rather than only on create.
     *
     * The pairing can change while this screen is in the back stack — a QR
     * scanned on the main screen, or a host revoked at the console and refused
     * on the next connect. A page that showed what was true when it was opened
     * would be quietly lying by the time the user came back to it. The
     * enrollment window is re-read for the same reason and one more: it expires
     * on a clock, so it can go stale while nothing at all happens.
     */
    override fun onResume() {
        super.onResume()
        renderPairedHosts()
        renderEnrollmentState()
    }

    private fun wireCursorLift() {
        val bar = findViewById<SeekBar>(R.id.seekCursorLift)
        val value = findViewById<TextView>(R.id.txtCursorLiftValue)
        bar.max = CursorLift.MAX_DP

        fun show(dp: Int) {
            value.text =
                if (dp <= 0) getString(R.string.cursor_lift_off)
                else getString(R.string.cursor_lift_value, dp)
            bar.contentDescription = value.text
        }

        val current = CursorLift.load(this)
        bar.progress = current
        show(current)

        bar.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(b: SeekBar?, progress: Int, fromUser: Boolean) {
                show(CursorLift.clamp(progress))
            }

            override fun onStartTrackingTouch(b: SeekBar?) = Unit

            // Saved on release, not on every increment: dragging the bar would
            // otherwise write to disk a hundred times for one decision.
            override fun onStopTrackingTouch(b: SeekBar?) {
                CursorLift.save(this@SettingsActivity, b?.progress ?: 0)
            }
        })
    }

    /**
     * Draw the host list from scratch on every render.
     *
     * Rebuilt rather than diffed: the list is a handful of rows, and a diff is
     * a second model of what is on screen that can disagree with the first. The
     * failure that would cause here is a Forget button still wired to a host
     * that is no longer in the record it sits above.
     */
    private fun renderPairedHosts() {
        val registry = PairedHostRegistry(this)
        renderHostRows(registry.all(), registry.active()?.identityB64)
    }

    /**
     * Draw a given list, rather than whatever storage happens to hold.
     *
     * Separated so the rows can be exercised on a device without writing to the
     * app's real `SharedPreferences`. That is not a style preference: an
     * instrumentation test of the pairing stores would unpair the operator's
     * phone on every gate run, which is why `PairedHostTest` carries an
     * explicit note that it has no on-device coverage. A test that damages the
     * state it exists to protect is worse than the gap — so the data comes in
     * as an argument and the storage read stays in the caller above.
     */
    @androidx.annotation.VisibleForTesting
    fun renderHostRows(hosts: List<PairedHostRecord>, activeIdentity: String?) {
        val list = findViewById<LinearLayout>(R.id.pairedHostList)
        // Rebuilt, not appended to: Settings re-reads on every resume, so a
        // list that grew each time would show the same host three times after
        // two trips to the main screen, each copy with its own live Forget.
        list.removeAllViews()

        val inflater = LayoutInflater.from(this)
        for (host in hosts) {
            val row = inflater.inflate(R.layout.item_paired_host, list, false)
            val isActive = host.identityB64 == activeIdentity
            val label = row.findViewById<TextView>(R.id.txtHostLabel)
            label.text =
                if (isActive) getString(R.string.settings_host_active, host.label())
                else host.label()
            // Bold only for the active one. Two hosts that look identical in a
            // list whose whole purpose is choosing between them would make the
            // choice invisible.
            label.setTypeface(null, if (isActive) android.graphics.Typeface.BOLD
            else android.graphics.Typeface.NORMAL)
            row.findViewById<TextView>(R.id.txtHostFingerprint).text =
                getString(R.string.settings_host_fingerprint, host.fingerprint())
            row.contentDescription = getString(
                if (isActive) R.string.settings_host_row_active_description
                else R.string.settings_host_row_description,
                host.label(),
                host.fingerprint()
            )
            row.setOnClickListener {
                PairedHostRegistry(this).setActive(host.identityB64)
                renderPairedHosts()
            }
            val forget = row.findViewById<Button>(R.id.btnForgetThisHost)
            forget.contentDescription =
                getString(R.string.settings_forget_one_description, host.label())
            forget.setOnClickListener { confirmForget(host) }
            list.addView(row)
        }
    }

    /**
     * Say whether the next scan may add a machine, and for how long.
     *
     * Stated on screen rather than left implicit. An arm the operator cannot
     * see is one they cannot tell has expired, and the failure it produces —
     * a scan refused for a reason that was true five minutes ago — is exactly
     * the kind of silent refusal Block 5 existed to end.
     */
    private fun renderEnrollmentState() {
        renderEnrollmentLine(
            EnrollmentArmingStore(this).armedAt(),
            System.currentTimeMillis(),
            PairedHostRegistry(this).all().isNotEmpty()
        )
    }

    /**
     * The same line, from given values. Testable on a device without arming
     * anything for real — an instrumentation test that left an open enrollment
     * window on the operator's phone would be a side effect with a security
     * meaning, not a tidiness problem.
     */
    @androidx.annotation.VisibleForTesting
    fun renderEnrollmentLine(armedAt: Long?, now: Long, hasHosts: Boolean) {
        val text = findViewById<TextView>(R.id.txtEnrollmentState)
        text.text = when {
            EnrollmentArming.isArmed(armedAt, now) -> {
                // Rounded UP: a line that says "1 minute" with 20 seconds left
                // sends the operator to a camera that will refuse them.
                val minutes = Math.ceil(
                    EnrollmentArming.remainingMs(armedAt, now) / 60000.0
                ).toInt()
                getString(R.string.settings_enrollment_armed, minutes)
            }
            !hasHosts -> getString(R.string.settings_enrollment_first)
            else -> getString(R.string.settings_enrollment_closed)
        }
    }

    /**
     * Arming asks first, and the question names the risk.
     *
     * The dialog is not a formality: pressing this is the single act that lets
     * an unknown identity through, and the one thing the user can check that
     * the phone cannot is whether the machine they are about to scan is theirs.
     */
    private fun confirmArm() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.settings_add_host_title)
            .setMessage(R.string.settings_add_host_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.settings_add_host_confirm) { _, _ ->
                EnrollmentArmingStore(this).arm()
                renderEnrollmentState()
            }
            .show()
    }

    /**
     * Forgetting is a considered act, so it asks first — and what it asks
     * depends on what is left.
     *
     * With other hosts still paired, this device's own identity has to stay
     * alive for them, so forgetting one host is forgetting our own note rather
     * than withdrawing permission: that host may still accept this phone until
     * it is revoked there. Saying "unpaired" would be untrue. With nothing left,
     * the identity goes too and the old wording is exactly right.
     *
     * The rule lives in [ForgetHostPolicy] and is tested; this reads it.
     */
    private fun confirmForget(host: PairedHostRecord) {
        val registry = PairedHostRegistry(this)
        val remaining = registry.all().count { it.identityB64 != host.identityB64 }
        val scope = ForgetHostPolicy.scopeFor(remaining)
        val warn = ForgetHostPolicy.mustWarnHostStillKnowsUs(scope)

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.settings_forget_host)
            .setMessage(
                if (warn) getString(R.string.settings_forget_body_others_remain, host.label())
                else getString(R.string.settings_forget_body)
            )
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.settings_forget_host) { _, _ ->
                val message = when (scope) {
                    ForgetHostPolicy.Scope.ThisHostOnly -> {
                        registry.forget(host.identityB64)
                        getString(R.string.settings_forgot_one)
                    }
                    ForgetHostPolicy.Scope.HostAndDeviceIdentity -> {
                        // Drops this device's Noise identity as well, which is
                        // the half the host keys on. Nothing is left that could
                        // still be using it.
                        val complete = DeviceUnpair.forgetEverything(this)
                        if (complete) getString(R.string.settings_forgotten)
                        else getString(R.string.settings_forget_incomplete)
                    }
                }
                renderPairedHosts()
                renderEnrollmentState()
                android.widget.Toast.makeText(this, message, android.widget.Toast.LENGTH_LONG)
                    .show()
            }
            .show()
    }
}
