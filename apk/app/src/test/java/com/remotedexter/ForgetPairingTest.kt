package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ForgetPairingTest {

    @Test
    fun bothSidesAreClearedAndTheIdentityGoesFirst() {
        val order = mutableListOf<String>()
        val ok = ForgetPairing.forget(
            forgetIdentity = { order.add("identity"); true },
            forgetHostPin = { order.add("pin") }
        )
        assertTrue(ok)
        assertEquals(
            "the identity is what the host recognises, so it must go first",
            listOf("identity", "pin"),
            order
        )
    }

    /// A caller must not tell the owner they are unpaired when the host would
    /// still recognise this phone.
    @Test
    fun aFailedIdentityClearIsReportedEvenThoughThePinIsStillCleared() {
        var pinCleared = false
        val ok = ForgetPairing.forget(
            forgetIdentity = { false },
            forgetHostPin = { pinCleared = true }
        )
        assertFalse("forgetting must not claim success it did not achieve", ok)
        assertTrue("clearing the pin still forces a fresh QR", pinCleared)
    }

    @Test
    fun aNativeCrashDoesNotLeaveThePinBehind() {
        var pinCleared = false
        val ok = ForgetPairing.forget(
            forgetIdentity = { throw UnsatisfiedLinkError("no native library") },
            forgetHostPin = { pinCleared = true }
        )
        assertFalse(ok)
        assertTrue(
            "a native failure must not also strand the host pin",
            pinCleared
        )
    }
}
