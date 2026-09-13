package com.remotedexter

import com.remotedexter.IdleStatus.Line
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The idle line. It used to read "Not connected" whether or not a host was
 * remembered, so two states needing different actions looked identical.
 */
class IdleStatusTest {

    @Test
    fun withNoPairingTheUserIsToldToPair() {
        assertEquals(Line.NeedsPairing, IdleStatus.describe(null))
    }

    @Test
    fun withAPairingTheHostIsNamed() {
        assertEquals(
            Line.Paired("192.168.132.200:8082"),
            IdleStatus.describe("192.168.132.200:8082")
        )
    }

    /**
     * "Paired with " followed by nothing is worse than saying there is no
     * pairing: it invites the user to press a button that will fail.
     */
    @Test
    fun aRecordThatCannotNameItsHostIsNotOfferedAsOne() {
        assertEquals(Line.NeedsPairing, IdleStatus.describe(""))
        assertEquals(Line.NeedsPairing, IdleStatus.describe("   "))
    }
}
