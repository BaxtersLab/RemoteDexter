package com.remotedexter.bootstrap18

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.remotedexter.FailureReason
import com.remotedexter.RdxLog
import com.remotedexter.SessionState
import com.remotedexter.SessionStateHolder
import org.json.JSONObject

/**
 * Scans a pairing QR and hands the invite to [SessionStarter].
 *
 * Failure reporting is the point of this class. QR symbols are Reed–Solomon
 * protected, so a scan yields either the exact encoded bytes or nothing at all —
 * there is no such thing as a partially-decoded QR. That splits the failures
 * cleanly:
 *
 * - nothing decoded → the user cancelled or the camera never got a lock
 * - decoded, then threw → the payload is not an invite this build understands
 *
 * The shipped 3.0.0 build logged **nothing** here and showed only the toast
 * "Invalid QR". That single opaque message covered scanning the wrong QR
 * entirely, and a genuine schema mismatch, and it cost a full day of
 * investigation to tell those apart. Everything below exists so the next
 * failure names itself.
 */
class QrScanActivity : AppCompatActivity() {

    private val barcodeLauncher = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (contents == null) {
            RdxLog.i(TAG, "scan returned no contents (cancelled or no lock)")
            Toast.makeText(this, "Cancelled", Toast.LENGTH_LONG).show()
            finish()
            return@registerForActivityResult
        }

        RdxLog.i(TAG, "scanned ${contents.length} chars")

        try {
            // A relay invite is decoded first and routed to its own starter.
            // `InvitePayload` is built around `lan_ip` and `port`, and a v5
            // invite has neither — turning one into a payload would mean
            // inventing an address nothing is listening on.
            val decoded = InviteDecoder.decode(contents)
            if (decoded is Decoded.V5) {
                SessionStarter.startFromRelayInvite(decoded.invite, this)
                finish()
                return@registerForActivityResult
            }
            val invite = InvitePayload.fromJson(JSONObject(contents))
            SessionStarter.startFromInvite(invite, this)
            finish()
        } catch (e: InviteDecodeException) {
            reportUnusableScan(contents, e)
            val detail = ScanFailureReport.userDetail(e)
            SessionStateHolder.set(SessionState.Failed(e.reason, detail))
            Toast.makeText(this, "${e.reason.label()} — $detail", Toast.LENGTH_LONG)
                .show()
            finish()
        } catch (e: Exception) {
            reportUnusableScan(contents, e)
            // NOT e.message. Android's org.json appends the whole input to a
            // tokenizer error, so a misread invite would put a live token on
            // screen and into the shareable diagnostics log.
            val detail = ScanFailureReport.userDetail(e)
            SessionStateHolder.set(SessionState.Failed(FailureReason.InviteParse, detail))
            Toast.makeText(this, "Pairing code unreadable — $detail", Toast.LENGTH_LONG)
                .show()
            finish()
        }
    }

    /**
     * Log enough to identify *why* a scan was unusable, without logging secrets.
     *
     * Every decision about what may appear lives in [ScanFailureReport], which
     * is a pure function and is tested. This method only writes what that
     * returns — deliberately, because the previous version made the judgement
     * inline and got it wrong twice. It logged the parser's own message, and
     * Android's `org.json` appends the ENTIRE input to a tokenizer error. And
     * it echoed a 60-character prefix of any non-JSON payload, reasoning that
     * non-JSON cannot hold a token; a corrupted or truncated invite is not
     * valid JSON and holds the token in full.
     *
     * The throwable is NOT handed to the logger either. `RdxLog` renders a
     * stack trace beginning with the exception's `toString()`, which is the
     * message this exists to keep out.
     */
    private fun reportUnusableScan(contents: String, e: Exception) {
        for (line in ScanFailureReport.describe(contents, e)) {
            RdxLog.e(TAG, line)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RdxLog.init(applicationContext)

        barcodeLauncher.launch(
            ScanOptions()
                // The viewfinder is showing a QR that encodes a live one-use
                // token, so the scan runs in a window this app owns and can
                // mark FLAG_SECURE. zxing's stock CaptureActivity cannot be
                // flagged from here.
                .setCaptureActivity(com.remotedexter.SecureCaptureActivity::class.java)
                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setPrompt("Scan QR code")
                .setBeepEnabled(false)
                .setOrientationLocked(false)
        )
    }

    private companion object {
        const val TAG = "QrScanActivity"
    }
}
