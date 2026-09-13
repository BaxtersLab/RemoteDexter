package com.remotedexter

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.remotedexter.bootstrap18.HostIdentityTrust

/**
 * Reads [RdxLog] back on the device.
 *
 * Pairing refusals are invisible in the UI by design — every gate in
 * [com.remotedexter.bootstrap18.SessionStarter] logs and returns rather than
 * throwing, because throwing would collapse seven distinct reasons into one
 * generic scanner error. That makes the log the only account of what happened,
 * and this screen is how it gets read when no cable is attached.
 *
 * Built in code rather than XML deliberately: a diagnostics screen that depends
 * on resource resolution can fail for the same reasons you would be opening it
 * to investigate.
 */
class DiagnosticsActivity : AppCompatActivity() {

    private lateinit var body: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The log buffer holds host addresses and key fingerprints.
        SecureWindow.apply(this)
        RdxLog.init(applicationContext)

        body = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextIsSelectable(true)
            movementMethod = ScrollingMovementMethod()
            setPadding(dp(12), dp(12), dp(12), dp(12))
        }

        val scroller = ScrollView(this).apply {
            addView(body, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        }

        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(4), dp(8), dp(8))
            addView(button("Refresh") { refresh() })
            addView(button("Copy") { copyReport() })
            addView(button("Share") { shareReport() })
            addView(button("Clear") { clearLog() })
            addView(button("Unpair") { forgetPairedHost() })
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(scroller, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
            addView(buttons, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        }

        setContentView(root)
        title = "Diagnostics"
        refresh()
    }

    /** Re-read the buffer. The log grows while this screen is open. */
    private fun refresh() {
        val text = report()
        body.text = text
        RdxLog.d(TAG, "diagnostics refreshed (${text.length} chars)")
    }

    /**
     * The log, or an explicit note when it is empty.
     *
     * An empty buffer is itself a finding — it means the scanner threw before
     * reaching [com.remotedexter.bootstrap18.SessionStarter], i.e. the payload
     * never parsed — so it must not be mistaken for the screen being broken.
     */
    private fun report(): String {
        val snapshot = RdxLog.snapshot()
        return if (snapshot.isBlank()) {
            "Log is empty.\n\n" +
                "Nothing has been recorded this run. If a pairing attempt showed " +
                "\"Invalid QR\" and this log is empty, the payload failed to parse " +
                "before any security gate ran."
        } else {
            snapshot
        }
    }

    private fun copyReport() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("RemoteDexter diagnostics", report()))
        Toast.makeText(this, "Log copied", Toast.LENGTH_SHORT).show()
    }

    /**
     * Hand the log to any app that accepts text.
     *
     * The log deliberately contains no session token — [SessionStarter] records
     * only a short fingerprint, and the scanner logs JSON *key names* rather
     * than values — so sharing it does not leak a working credential. Keep it
     * that way: anything added to the log is something the user may forward to a
     * third party.
     */
    private fun shareReport() {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "RemoteDexter diagnostics")
            putExtra(Intent.EXTRA_TEXT, report())
        }
        startActivity(Intent.createChooser(send, "Share diagnostics"))
    }

    private fun clearLog() {
        RdxLog.clear()
        RdxLog.i(TAG, "log cleared by user")
        refresh()
        Toast.makeText(this, "Log cleared", Toast.LENGTH_SHORT).show()
    }

    /**
     * Forget the paired host, so the next invitation is trusted on first use.
     *
     * [SessionStarter] tells the user to "forget the paired host in Session
     * Permissions" when an invitation arrives from a different host identity —
     * but nothing called [HostIdentityTrust.forget] from any UI, so that remedy
     * did not exist and a legitimate re-key could only be cleared over `adb`.
     * This is that control.
     *
     * It confirms first, deliberately. [HostIdentityTrust] documents the reset
     * as "a user decision, not an inference", and that is precisely the point:
     * an identity change is what the gate exists to catch, so clearing it must
     * be a considered act rather than a reflex when a scan fails.
     */
    private fun forgetPairedHost() {
        val trust = HostIdentityTrust(this)
        val current = trust.trustedIdentity()
        if (current == null) {
            RdxLog.i(TAG, "unpair requested, but no host is currently paired")
            refresh()
            Toast.makeText(this, "No paired host", Toast.LENGTH_SHORT).show()
            return
        }
        // A public key prefix — identifies which host without filling the dialog.
        val shown = current.take(16)
        AlertDialog.Builder(this)
            .setTitle("Forget paired host?")
            .setMessage(
                "Currently trusted host:\n$shown…\n\n" +
                    "The next invitation will be trusted on first use. Do this " +
                    "only if the host was legitimately re-keyed — for example " +
                    "after host_app was reinstalled or moved to a different " +
                    "folder.\n\n" +
                    "If you did not expect the host identity to change, cancel. " +
                    "A changed identity is exactly what the security gate is for."
            )
            .setNegativeButton("Cancel") { _, _ ->
                RdxLog.i(TAG, "unpair cancelled by user")
            }
            .setPositiveButton("Forget") { _, _ ->
                // The whole pairing, not just the pin. Clearing the pin alone
                // left this device's identity enrolled at the host, so an
                // "unpaired" phone would still be admitted on a token-less
                // reconnect. See DeviceUnpair.
                val complete = DeviceUnpair.forgetEverything(this)
                RdxLog.i(TAG, "paired host forgotten by user (was $shown…)")
                refresh()
                Toast.makeText(
                    this,
                    if (complete) "Unpaired"
                    else "Host forgotten, but this device's identity could not be " +
                        "removed — revoke it at the host",
                    Toast.LENGTH_LONG
                ).show()
            }
            .show()
    }

    private fun button(label: String, onClick: () -> Unit): Button =
        Button(this).apply {
            text = label
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
                .apply { marginEnd = dp(4) }
        }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    private companion object {
        const val TAG = "DiagnosticsActivity"
    }
}
