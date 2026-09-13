package com.remotedexter

import android.os.Bundle
import com.journeyapps.barcodescanner.CaptureActivity

/**
 * zxing's scanner window, with [SecureWindow] applied.
 *
 * The QR being scanned encodes a one-use pairing token, so the viewfinder is
 * showing a credential for as long as the scan takes. zxing contributes its own
 * `CaptureActivity` through manifest merge and this app cannot add a flag to a
 * window it does not own — so it owns one. `ScanOptions.setCaptureActivity`
 * points the launcher here; nothing else about the scan changes.
 */
class SecureCaptureActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        SecureWindow.apply(this)
        super.onCreate(savedInstanceState)
    }
}
