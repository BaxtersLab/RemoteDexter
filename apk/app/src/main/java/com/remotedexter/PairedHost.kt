package com.remotedexter

/**
 * Where to reconnect, and what to pin when we get there.
 *
 * ## Why this has to exist
 *
 * Block 9 promises that after one QR enrollment the phone can reconnect to a
 * started host without a new QR. The host half of that was built first: it
 * enrolls the device's Noise static key and accepts a token-less connection
 * from a key it knows. But the client had nowhere to reconnect *to*. The
 * address, the port and the host's 32-byte Noise pin all arrived inside the
 * invite and were discarded with it, so the only surviving trace of a pairing
 * was [com.remotedexter.bootstrap18.HostIdentityTrust] — which holds the
 * Ed25519 *identity* key used to check an invite's signature, and cannot open a
 * socket or pin a handshake.
 *
 * The result was a feature that passed its host tests and could not be
 * performed by the product. This is the missing half.
 *
 * ## What is stored, and what is not
 *
 * Only public, non-secret values: an address, a port, and a public key. There
 * is deliberately **no token** here. A pairing token is one-use and expiring;
 * storing one would be keeping a spent credential around, and a stored
 * credential that still worked would be a far worse thing to have on a phone
 * than none at all. The reconnect authenticates with the device's own Noise
 * key, which never leaves the native identity file.
 *
 * ## The address is a hint, not a guarantee
 *
 * A LAN address is a DHCP lease. It can move, and when it does this record
 * points at nothing — or at whatever machine inherited the address. That second
 * case is why [pinHex] is stored alongside it and is not optional: connecting
 * on a stale address reaches a stranger, and the pin is what turns that into a
 * clean refusal instead of a session with the wrong host. A reconnect that
 * fails on a moved host is expected, and the remedy is a fresh QR.
 */
data class PairedHost(
    val addr: String,
    val port: Int,
    /** The host's Noise static public key, hex, exactly 64 characters. */
    val pinHex: String
) {
    /** The pin as the 32 raw bytes the native side requires. */
    fun pinBytes(): ByteArray = decodeHex(pinHex)!!

    companion object {
        /** A Noise static X25519 key, in hex. */
        private const val PIN_HEX_LENGTH = 64

        /**
         * Build a record, or refuse.
         *
         * Pure and public so the rules are tested directly rather than through
         * `SharedPreferences`. Every refusal below is a value that would reach
         * `startPairedSession` and be rejected there — but rejected on a
         * background thread, as a connection failure, after a socket had
         * already been opened to an address we should never have kept.
         */
        fun of(addr: String, port: Int, pinHex: String): PairedHost? {
            if (addr.isBlank()) return null
            // Port 0 means "any port" to the OS, never a destination.
            if (port !in 1..65535) return null
            val pin = pinHex.trim().lowercase()
            if (pin.length != PIN_HEX_LENGTH) return null
            if (decodeHex(pin) == null) return null
            return PairedHost(addr.trim(), port, pin)
        }

        /**
         * Hex to bytes, or null.
         *
         * Written out rather than reaching for a parser that treats "0x", a
         * sign, or whitespace as acceptable. A pin is 64 hex digits and
         * anything else is a refusal — being liberal here would mean accepting
         * a mangled pin and comparing the host against the wrong key.
         */
        fun decodeHex(text: String): ByteArray? {
            if (text.length % 2 != 0) return null
            val out = ByteArray(text.length / 2)
            for (i in out.indices) {
                val hi = Character.digit(text[i * 2], 16)
                val lo = Character.digit(text[i * 2 + 1], 16)
                if (hi < 0 || lo < 0) return null
                out[i] = ((hi shl 4) or lo).toByte()
            }
            return out
        }
    }
}
