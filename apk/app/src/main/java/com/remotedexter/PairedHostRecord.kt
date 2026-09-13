package com.remotedexter

/**
 * One host this device is paired with, whole.
 *
 * ## Why the two halves had to be joined
 *
 * A pairing was stored as two independent values in two `SharedPreferences`
 * files: the Ed25519 **identity** in `HostIdentityTrust`, which is what an
 * invite's signature is checked against, and the address, port and Noise
 * **pin** in `PairedHostStore`, which is where to connect and what to pin on
 * arrival. Nothing tied them together, and nothing needed to — with one host
 * there was only one possible pairing they could belong to.
 *
 * With several, that stops being true, and the failure it allows is the worst
 * kind: host A's identity sitting beside host B's address would mean verifying
 * an invite against one machine and then opening a socket to another. So the
 * two halves are one record, written and dropped together, and there is no way
 * to express half of one.
 *
 * @property identityB64 the host's Ed25519 identity key, base64. This is the
 *   value an invite's signature is verified against and the value that decides
 *   whether a host is one we know.
 * @property host where to reconnect and what to pin when we get there.
 */
data class PairedHostRecord(
    val identityB64: String,
    val host: PairedHost
) {
    /**
     * A short, human-comparable form of the host's identity.
     *
     * A PREFIX rather than the suffix the plan's wording suggests, and
     * deliberately: the identity-mismatch sheet already shows
     * `expectedFingerprint`/`receivedFingerprint` as the first 16 characters of
     * this same key. A list that showed the tail would give the operator two
     * different-looking strings for the same host at the exact moment they are
     * trying to work out whether it IS the same host.
     */
    fun fingerprint(): String = identityB64.take(FINGERPRINT_CHARS)

    /** What to call this host on screen. The address is what the operator recognises. */
    fun label(): String = "${host.addr}:${host.port}"

    companion object {
        const val FINGERPRINT_CHARS = 12

        /**
         * Build a record, or refuse.
         *
         * The address, port and pin rules belong to [PairedHost] and are not
         * repeated here. The identity is required to be non-blank and nothing
         * more: it is checked properly where it matters, by actually verifying
         * an invite signature against it, and a second half-check here would be
         * a second opinion that could disagree with the real one.
         */
        fun of(identityB64: String, addr: String, port: Int, pinHex: String): PairedHostRecord? {
            val identity = identityB64.trim()
            if (identity.isEmpty()) return null
            val host = PairedHost.of(addr, port, pinHex) ?: return null
            return PairedHostRecord(identity, host)
        }
    }
}

/**
 * The stored form of the host list.
 *
 * One record per line, four tab-separated fields. Base64 and hex contain
 * neither tabs nor newlines, so the encoding is unambiguous without escaping —
 * and a format that needs no escaping cannot be broken by a value that forgot
 * to escape itself.
 *
 * Pure, so the persisted format is a tested contract rather than something only
 * observable through `SharedPreferences` on a device.
 */
object PairedHostCodec {

    private const val FIELD = '\t'
    private const val LINE = '\n'

    fun encode(records: List<PairedHostRecord>): String = records.joinToString("$LINE") {
        listOf(it.identityB64, it.host.addr, it.host.port.toString(), it.host.pinHex)
            .joinToString("$FIELD")
    }

    /**
     * Read the list back, **dropping anything that no longer parses**.
     *
     * Fails closed, exactly as `PairedHostStore.stored()` did for one host and
     * for the same reason: preferences survive app upgrades, downgrades and
     * restores from backup, so "we wrote it, therefore it is well-formed" is an
     * assumption about a file this code did not necessarily write. A malformed
     * line is treated as absent, which costs the user a QR scan. Keeping it
     * would cost them a socket opened to an address that failed validation.
     *
     * One bad line does not discard the others. A single corrupt record must
     * not unpair every host on the phone.
     */
    fun decode(text: String?): List<PairedHostRecord> {
        if (text.isNullOrEmpty()) return emptyList()
        val out = ArrayList<PairedHostRecord>()
        for (line in text.split(LINE)) {
            if (line.isBlank()) continue
            val f = line.split(FIELD)
            if (f.size != 4) continue
            val port = f[2].toIntOrNull() ?: continue
            val record = PairedHostRecord.of(f[0], f[1], port, f[3]) ?: continue
            // A repeated identity is not two hosts. It is one host recorded
            // twice, and the two copies can disagree about the address — so the
            // first wins and the duplicate is dropped, rather than leaving the
            // list to decide by iteration order which one a connect uses.
            if (out.none { it.identityB64 == record.identityB64 }) out.add(record)
        }
        return out
    }
}
