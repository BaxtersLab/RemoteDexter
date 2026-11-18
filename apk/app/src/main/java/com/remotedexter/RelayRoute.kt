package com.remotedexter

/**
 * How to reach a paired host THROUGH THE RELAY, and what to pin on arrival.
 *
 * ## Why this exists
 *
 * A relay pairing used to leave nothing behind. The relay issued the host a
 * random session id every time the host registered, so the id this device
 * paired against was dead after the host's next restart, and a stored route
 * would have been a row that could never work. The relay now gives an enrolled
 * host the SAME id every time it registers, for as long as the relay runs — so
 * the id kept from the pairing still names the host after the host restarts,
 * and a paired phone can come back without a QR.
 *
 * ## What still ends it
 *
 * A restart of the RELAY. It derives ids through a key it keeps only in memory,
 * so every stored route goes stale when it restarts, and a reconnect is then
 * refused in exactly the words a host that is not running gets — the relay says
 * the same thing for both, on purpose, so a stranger cannot probe which ids
 * are real. The remedy for both is on the host: start it, or scan a fresh code.
 *
 * ## The session id is a credential against the relay
 *
 * Not a secret from the relay, which issued it — but a stranger holding one can
 * occupy the host's join slot. So it is:
 *
 * - **never rendered.** [toString] redacts it, because a data class prints every
 *   field and a record is exactly the kind of value that ends up in a log line;
 * - **never a label.** What the operator sees is the relay's address;
 * - **never in an Intent.** A reconnect reads it from storage inside the
 *   process;
 * - **stored beside the rest of the pairing**, app-private and excluded from
 *   backup and device transfer like every other preference file here. The
 *   device's own Noise PRIVATE key is kept the same way, and it is worth far
 *   more than an id that the relay rate-limits and forgets on its next restart.
 *
 * @property relayAddr where the relay listens. Never blank; never contains
 *   whitespace.
 * @property relayPort 1..65535.
 * @property session the id the relay gave the host. Base64url only.
 * @property pinHex the host's Noise static key, exactly as [PairedHost.pinHex]:
 *   64 lowercase hex characters. Going through a relay changes nothing about who
 *   the host has to prove itself to be.
 */
data class RelayRoute(
    val relayAddr: String,
    val relayPort: Int,
    val session: String,
    val pinHex: String
) {
    /** The pin as the 32 raw bytes the native side requires. */
    fun pinBytes(): ByteArray = PairedHost.decodeHex(pinHex)!!

    /** What the operator is shown. The relay, never the session. */
    fun label(): String = "relay $relayAddr:$relayPort"

    /**
     * Redacted. The generated `toString` would print [session], and a record
     * holding this is exactly what gets interpolated into a log message.
     */
    override fun toString(): String =
        "RelayRoute(relay=$relayAddr:$relayPort, session=<redacted>, pin=$pinHex)"

    companion object {
        /**
         * The longest session id accepted. The relay issues 22 characters; this
         * is a bound, not a format check, so a relay that changes its id length
         * does not strand every phone paired through it.
         */
        const val MAX_SESSION_CHARS = 128

        /**
         * Build a route, or refuse.
         *
         * Every value here ends up in one tab-separated line in storage, so a
         * tab or a newline inside any of them would not be "a strange address"
         * — it would split the line into different fields and be read back as a
         * different record, or none. They are refused here rather than escaped
         * later.
         */
        fun of(relayAddr: String, relayPort: Int, session: String, pinHex: String): RelayRoute? {
            val addr = relayAddr.trim()
            if (addr.isEmpty() || addr.any { it.isWhitespace() || it.isISOControl() }) return null
            if (relayPort !in 1..65535) return null
            if (!isSessionShaped(session)) return null
            val pin = PairedHost.normalisedPin(pinHex) ?: return null
            return RelayRoute(addr, relayPort, session, pin)
        }

        /**
         * Base64url characters only, and not too many of them.
         *
         * Checked by character rather than by a regular expression so the
         * refusal is exact: nothing that could split a stored line, nothing that
         * could be read as markup in a label, and nothing empty.
         */
        fun isSessionShaped(session: String): Boolean =
            session.isNotEmpty() &&
                session.length <= MAX_SESSION_CHARS &&
                session.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
    }
}
