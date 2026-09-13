package com.remotedexter

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ControlDenialPolicyTest {

    @Test
    fun deniedInputClearsTheClaimedGrant() {
        assertTrue(ControlDenialPolicy.losesGrant("input_event"))
    }

    @Test
    fun deniedRevokeKeepsTheClaimedGrant() {
        assertFalse(ControlDenialPolicy.losesGrant("revoke_input"))
    }

    @Test
    fun aSecondDisableIsBlockedWhileTheFirstIsPending() {
        assertFalse(ControlRequestPolicy.canRequestDisable(controlEnabled = true, pending = true))
    }

    @Test
    fun oneDisableIsAllowedForAnEnabledSettledGrant() {
        assertTrue(ControlRequestPolicy.canRequestDisable(controlEnabled = true, pending = false))
    }

    @Test
    fun disablingReleasesTheDragBeforeRevokingInput() {
        val calls = mutableListOf<String>()

        ControlDisableSequence.execute(
            releaseDragIfHeld = { calls += "MouseButton Up" },
            sendRevoke = { calls += "revoke_input" }
        )

        assertEquals(listOf("MouseButton Up", "revoke_input"), calls)
    }
}