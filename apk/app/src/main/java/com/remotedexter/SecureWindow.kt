package com.remotedexter

import android.app.Activity
import android.view.WindowManager

/**
 * Marks a window as excluded from screenshots, screen recording and non-secure
 * displays.
 *
 * WHAT `FLAG_SECURE` ACTUALLY BUYS, so nobody reads more into it. It stops
 * OTHER apps on this phone — anything holding a MediaProjection, an accessibility
 * capture, or a cast to an insecure display — from reading the window's pixels,
 * and it keeps the window out of the recents thumbnail. It is not encryption, it
 * does not defend against a rooted device or a physical camera pointed at the
 * screen, and it does nothing about what the HOST does with its own screen.
 *
 * WHAT IT COSTS, stated because a user will notice: the owner cannot screenshot
 * these screens either, and they go black when the phone is cast or recorded.
 * That is the trade this app takes on the three windows that show either the
 * host's desktop or pairing material. It is applied unconditionally rather than
 * behind a setting: a toggle for this is a product decision the operator has not
 * been asked for, and a protection that can be switched off tends to be off.
 */
object SecureWindow {

    /**
     * The windows that must be secure, by simple class name.
     *
     * Kept as data so the regression test can iterate it rather than restate
     * it — a list and an assertion that disagree is how a new activity gets
     * added and quietly misses the flag.
     */
    val REQUIRED = listOf(
        // Shows the host's desktop, pixel for pixel.
        "MainActivity",
        // Shows the RdxLog buffer: host addresses, key fingerprints, and scan
        // diagnostics. Redacted, but not nothing.
        "DiagnosticsActivity",
        // The camera preview during pairing. The QR in front of the lens
        // ENCODES A LIVE ONE-USE TOKEN, so a screen recorder running during a
        // scan could read the invite straight off the viewfinder. This is
        // zxing's capture window, subclassed only to carry this flag — putting
        // it on QrScanActivity instead would have protected a window that
        // draws nothing.
        "SecureCaptureActivity",
    )

    fun apply(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
}
