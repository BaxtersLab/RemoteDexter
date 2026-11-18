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

    /**
     * RD-TEXT-1. A run refused for its CONTENT leaves the host's grant in
     * place; the phone must not switch to Viewing Only over an accented letter.
     */
    @Test
    fun aRefusalOfTheTextKeepsTheGrant() {
        assertFalse(ControlDenialPolicy.losesGrant("input_event", "unsupported_character"))
        assertFalse(ControlDenialPolicy.losesGrant("input_event", "text_too_long"))
    }

    /** Every other input refusal still means control is gone. */
    @Test
    fun aRefusalOfTheTypistStillLosesTheGrant() {
        assertTrue(ControlDenialPolicy.losesGrant("input_event", "host desktop is locked"))
        assertTrue(ControlDenialPolicy.losesGrant("input_event", "input not granted"))
        assertTrue(ControlDenialPolicy.losesGrant("grant_input", "unsupported_character"))
    }

    /** Only a queued run may clear the compose field. */
    @Test
    fun onlyAQueuedRunClearsTheComposeField() {
        assertTrue(TextSend.Queued.clearsField)
        assertFalse(TextSend.NotQueued.clearsField)
        assertFalse(TextSend.Refused(KeyboardInput.Action.TooLong(2001, 2000)).clearsField)
        assertFalse(TextSend.Refused(KeyboardInput.Action.TooLargeToSend(4097, 4096)).clearsField)
        assertFalse(TextSend.Refused(KeyboardInput.Action.Drop("control not granted")).clearsField)
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