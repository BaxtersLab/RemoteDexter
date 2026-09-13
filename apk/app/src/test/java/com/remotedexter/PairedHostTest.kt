package com.remotedexter

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The rules that decide whether a stored pairing may be used to open a socket.
 *
 * Every refusal here is one that would otherwise surface as a connection
 * failure on a background thread, after the phone had already dialled an
 * address it should not have kept.
 */
class PairedHostTest {

    private val goodPin = "ab".repeat(32)

    @Test
    fun aWellFormedRecordIsAccepted() {
        val host = PairedHost.of("192.168.1.40", 8082, goodPin)
        assertNotNull(host)
        assertEquals("192.168.1.40", host!!.addr)
        assertEquals(8082, host.port)
        assertEquals(32, host.pinBytes().size)
    }

    @Test
    fun aPinOfTheWrongLengthIsRefused() {
        // 31 bytes. Long enough to look right at a glance, and the native side
        // would refuse it — but only after a socket was opened.
        assertNull(PairedHost.of("192.168.1.40", 8082, "ab".repeat(31)))
        assertNull(PairedHost.of("192.168.1.40", 8082, "ab".repeat(33)))
        assertNull(PairedHost.of("192.168.1.40", 8082, ""))
    }

    @Test
    fun aPinThatIsNotHexIsRefused() {
        assertNull(PairedHost.of("192.168.1.40", 8082, "zz".repeat(32)))
    }

    /**
     * Port 0 is not "unset" to a socket API — it means "let the OS choose",
     * which as a destination is meaningless rather than merely wrong. It is
     * also exactly what `getInt` returns for a key that was never written, so
     * a partially-written record must not read back as usable.
     */
    @Test
    fun portZeroAndOutOfRangePortsAreRefused() {
        assertNull(PairedHost.of("192.168.1.40", 0, goodPin))
        assertNull(PairedHost.of("192.168.1.40", -1, goodPin))
        assertNull(PairedHost.of("192.168.1.40", 65536, goodPin))
        assertNotNull(PairedHost.of("192.168.1.40", 65535, goodPin))
    }

    @Test
    fun aBlankAddressIsRefused() {
        assertNull(PairedHost.of("", 8082, goodPin))
        assertNull(PairedHost.of("   ", 8082, goodPin))
    }

    /** An invite's hex may arrive upper-case; the same host must not read as two. */
    @Test
    fun aPinIsNormalisedSoOneHostIsOneRecord() {
        val upper = PairedHost.of("192.168.1.40", 8082, goodPin.uppercase())
        val lower = PairedHost.of("192.168.1.40", 8082, goodPin)
        assertEquals(lower, upper)
    }

    @Test
    fun hexDecodesToTheBytesItNames() {
        assertArrayEquals(
            byteArrayOf(0x00, 0x0f, 0xf0.toByte(), 0xff.toByte()),
            PairedHost.decodeHex("000ff0ff")
        )
    }

    /**
     * An odd-length string must not decode by dropping the last digit. A pin
     * silently one nibble short would compare against the wrong key.
     */
    @Test
    fun oddLengthHexIsRefusedRatherThanTruncated() {
        assertNull(PairedHost.decodeHex("abc"))
    }
}
