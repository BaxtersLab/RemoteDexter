package com.remotedexter

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The native library really loads on this device's ABI.
 *
 * This is the one claim that genuinely differs between the two runners and
 * cannot be faked on either: `rd-test-34` is x86_64, the SM-G970U is
 * arm64-v8a. The APK ships arm64-v8a, armeabi-v7a and x86_64, and until Block 5
 * a device outside that set surfaced as a crash or a screen that never changed
 * rather than a named state.
 *
 * `FailureReason.UnsupportedAbi` is the named state; this proves the happy path
 * it is the alternative to.
 */
@RunWith(AndroidJUnit4::class)
class NativeAbiTest {

    @Test
    fun theNativeLibraryLoadsForThisDevicesAbi() {
        val abis = android.os.Build.SUPPORTED_ABIS.joinToString(",")
        assertTrue(
            "libremotedexter.so did not load for ABI set [$abis]",
            RDRust.isAvailable()
        )
    }

    /**
     * The ABI this device actually runs is one the APK ships. If it were not,
     * the assertion above would already have failed — this names which one it
     * was, so a run on new hardware records its coverage rather than merely
     * passing.
     */
    @Test
    fun thisDeviceRunsAShippedAbi() {
        val shipped = setOf("arm64-v8a", "armeabi-v7a", "x86_64")
        val primary = android.os.Build.SUPPORTED_ABIS.first()
        assertTrue(
            "this device's primary ABI $primary is not one the APK ships",
            primary in shipped
        )
        println("ABI_COVERAGE primary=$primary loaded=${RDRust.isAvailable()}")
    }
}
