package com.remotedexter

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every window that shows host pixels or pairing material sets `FLAG_SECURE`.
 *
 * WHAT THIS PROVES AND WHAT IT DOES NOT. It reads source text. It cannot show
 * that Android honours the flag, or that a screen recorder really gets black
 * frames — that needs two apps and a handset, and it is recorded as unverified
 * rather than implied. What it does catch is the way this protection actually
 * gets lost: someone adds an activity that shows the desktop, or moves the
 * `apply` call below `setContentView`, and nothing anywhere objects.
 *
 * The list is [SecureWindow.REQUIRED], not a copy of it. A test that restates
 * its subject stops testing it the moment the two disagree.
 */
class SecureWindowTest {

    private fun sourceOf(className: String): File {
        val roots = listOf(
            File("src/main/java/com/remotedexter/$className.kt"),
            File("src/main/java/com/remotedexter/bootstrap18/$className.kt")
        )
        return roots.firstOrNull { it.exists() }
            ?: throw AssertionError(
                "SecureWindow.REQUIRED names $className, but no source file exists for it"
            )
    }

    @Test
    fun every_required_window_applies_the_flag() {
        assertTrue("the required list must not be empty", SecureWindow.REQUIRED.isNotEmpty())
        for (name in SecureWindow.REQUIRED) {
            val text = sourceOf(name).readText()
            assertTrue(
                "$name is listed as a secure window but never calls SecureWindow.apply",
                text.contains("SecureWindow.apply(this)")
            )
        }
    }

    /**
     * The flag is set before the window has content.
     *
     * `FLAG_SECURE` must be in place before the first frame is composed;
     * applying it after `setContentView` leaves a window that was briefly
     * capturable, and the code reads as if it were protected throughout.
     */
    @Test
    fun the_flag_is_applied_before_any_content_is_set() {
        val text = sourceOf("MainActivity").readText()
        val flagAt = text.indexOf("SecureWindow.apply(this)")
        val contentAt = text.indexOf("setContentView(")
        assertTrue("MainActivity must call SecureWindow.apply", flagAt >= 0)
        assertTrue("MainActivity must call setContentView", contentAt >= 0)
        assertTrue(
            "the flag must be set before the window gets content",
            flagAt < contentAt
        )
    }

    /**
     * The secure scanner window is REACHED, not merely present.
     *
     * This is the half a source-scan usually misses. `SecureCaptureActivity`
     * could exist, compile, be declared in the manifest and set the flag, and
     * still never run — zxing launches its own `CaptureActivity` unless
     * `ScanOptions.setCaptureActivity` says otherwise. A protection that is
     * never entered looks identical to one that works.
     */
    @Test
    fun the_scanner_actually_launches_the_secure_capture_window() {
        val scan = File("src/main/java/com/remotedexter/bootstrap18/QrScanActivity.kt").readText()
        assertTrue(
            "ScanOptions must point at SecureCaptureActivity or zxing uses its own window",
            scan.contains("setCaptureActivity(") && scan.contains("SecureCaptureActivity")
        )
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertTrue(
            "SecureCaptureActivity must be declared or launching it throws",
            manifest.contains("""android:name=".SecureCaptureActivity"""")
        )
        assertTrue(
            "the scanner window must not be exported",
            manifest.substringAfter(""".SecureCaptureActivity"""")
                .substringBefore("/>")
                .contains("""android:exported="false"""")
        )
    }
}
