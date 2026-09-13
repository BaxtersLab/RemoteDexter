package com.remotedexter

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Every build must be able to say which build it is.
 *
 * ## Why this is a test and not a note in the build file
 *
 * The build file already carried the rule — *"Do not reuse 3.0.0. Bump this for
 * every artifact that leaves the box"* — written after three separately
 * published builds all called themselves `3.0.0 / versionCode 1` and installing
 * the wrong one produced an "Invalid QR" pairing failure that cost two test
 * rounds.
 *
 * The rule was then broken anyway. Five days of work shipped as
 * `3.0.12 / versionCode 13`, and on 2026-08-31 the Windows box reported that the
 * APK on the transfer drive and the APK already on the phone reported identical
 * versions, distinguishable only by `lastUpdateTime`.
 *
 * A rule that depends on remembering has now failed twice. `buildStamp()` in
 * `app/build.gradle` appends the commit to the version name so the build
 * identifies itself whether or not anyone remembered; this is what fails if
 * someone removes it.
 *
 * Reads the version through `PackageManager`, not `BuildConfig`, so it asserts
 * on what an *installed* package reports — the same field `adb dumpsys` and the
 * drive's readers see.
 */
@RunWith(AndroidJUnit4::class)
class VersionStampTest {

    private fun versionName(): String {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        @Suppress("DEPRECATION")
        return ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName.orEmpty()
    }

    /** The version has to carry a build identifier, not just a release number. */
    @Test
    fun theVersionNameIdentifiesTheBuildItCameFrom() {
        val v = versionName()
        assertTrue("the package reported no version at all", v.isNotEmpty())
        assertTrue(
            "versionName '$v' carries no build stamp — two different builds can " +
                "report this same string, which is exactly the confusion that cost " +
                "two test rounds",
            v.contains('+')
        )
        val stamp = v.substringAfter('+')
        assertTrue("versionName '$v' has an empty build stamp", stamp.isNotBlank())
        assertTrue(
            "the build stamp '$stamp' is too short to identify anything",
            stamp.length >= 7
        )
    }

    /**
     * And the release number itself must have moved past the versions that are
     * already out there under other content.
     */
    @Test
    fun theReleaseNumberIsPastTheOnesAlreadyPublished() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        @Suppress("DEPRECATION")
        val code = ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionCode
        assertTrue(
            "versionCode $code is not past 13, which three days of separate work " +
                "already shipped under",
            code >= 14
        )
    }
}
