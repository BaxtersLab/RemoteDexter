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
 * ## Two routes to one host
 *
 * A host can be paired on the LAN, through the relay, or both. Each route is
 * optional; a record always has at least one, which the factories enforce and
 * the codec relies on. When both are present they MUST pin the same key — two
 * routes to one identity that disagreed about the host's Noise key would mean
 * one of them reaches a different machine, and [mergedWith] drops the older
 * route rather than keep that.
 *
 * Racing the two routes is a later phase. Until then Connect takes the route
 * this device LAST PAIRED BY ([preferRelay]), which is predictable and changes
 * nothing for anyone who only ever pairs one way.
 *
 * @property identityB64 the host's Ed25519 identity key, base64. This is the
 *   value an invite's signature is verified against and the value that decides
 *   whether a host is one we know.
 * @property lan where to reconnect on the local network, and what to pin; null
 *   for a host paired only through the relay.
 * @property relay how to reconnect through the relay, and what to pin; null for
 *   a host paired only on the LAN.
 * @property preferRelay whether Connect uses [relay] when both routes exist.
 */
data class PairedHostRecord(
    val identityB64: String,
    val lan: PairedHost?,
    val relay: RelayRoute? = null,
    val preferRelay: Boolean = false
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

    /**
     * What to call this host on screen: the route Connect will actually take.
     *
     * **Never the relay session id.** This string goes to the Settings list, to
     * TalkBack, to the connecting state and to the log.
     */
    fun label(): String = when (val route = reconnectRoute()) {
        is Reconnect.Lan -> "${route.host.addr}:${route.host.port}"
        is Reconnect.ViaRelay -> route.route.label()
    }

    /**
     * The short name the idle line uses: the LAN ADDRESS alone, exactly as it
     * always was, or the relay's label. Separate from [label] because that one
     * carries the port, and the idle line of every LAN-paired phone must read as
     * it did before relay routes existed. Never the session id.
     */
    fun idleLabel(): String = when (val route = reconnectRoute()) {
        is Reconnect.Lan -> route.host.addr
        is Reconnect.ViaRelay -> route.route.label()
    }

    /** The host's pin, whichever route carries it. The routes agree by construction. */
    fun pinHex(): String = lan?.pinHex ?: relay!!.pinHex

    /** Which route Connect takes. */
    sealed class Reconnect {
        data class Lan(val host: PairedHost) : Reconnect()
        data class ViaRelay(val route: RelayRoute) : Reconnect()
    }

    /**
     * The route Connect takes: the relay if this device last paired through it
     * and still has it, otherwise the LAN, otherwise the relay.
     */
    fun reconnectRoute(): Reconnect {
        val r = relay
        val l = lan
        return when {
            r != null && (preferRelay || l == null) -> Reconnect.ViaRelay(r)
            l != null -> Reconnect.Lan(l)
            // Unreachable through the factories, which never build a record with
            // neither route. Stated rather than assumed.
            else -> error("a paired-host record with no route")
        }
    }

    /**
     * This record updated by a NEWER pairing of the same host.
     *
     * The newer pairing's route replaces the same kind of route here. The other
     * kind is KEPT, so pairing a LAN-paired host through the relay does not
     * cost it its LAN route — unless the two pin different keys, in which case
     * the older route is dropped: a route that pins a key the host no longer
     * holds reaches a machine that is not this host. Connect then prefers the
     * route just paired by.
     *
     * A newer pairing of a DIFFERENT identity is returned unchanged; merging
     * two hosts is exactly the failure this type exists to prevent.
     */
    fun mergedWith(newer: PairedHostRecord): PairedHostRecord {
        if (newer.identityB64 != identityB64) return newer
        val pin = newer.pinHex()
        val lan = newer.lan ?: lan?.takeIf { it.pinHex == pin }
        val relay = newer.relay ?: relay?.takeIf { it.pinHex == pin }
        return PairedHostRecord(
            identityB64,
            lan,
            relay,
            // The route just paired by, when the newer record names one.
            preferRelay = when {
                newer.relay != null && newer.lan == null -> true
                newer.lan != null && newer.relay == null -> false
                else -> newer.preferRelay
            }
        )
    }

    companion object {
        const val FINGERPRINT_CHARS = 12

        /**
         * A host paired on the LAN, or a refusal.
         *
         * The address, port and pin rules belong to [PairedHost] and are not
         * repeated here. The identity is required to be non-blank and nothing
         * more: it is checked properly where it matters, by actually verifying
         * an invite signature against it, and a second half-check here would be
         * a second opinion that could disagree with the real one. It must not
         * contain a character that would split the stored line.
         */
        fun of(identityB64: String, addr: String, port: Int, pinHex: String): PairedHostRecord? {
            val identity = cleanIdentity(identityB64) ?: return null
            val host = PairedHost.of(addr, port, pinHex) ?: return null
            return PairedHostRecord(identity, host)
        }

        /** A host paired through the relay, or a refusal. The rules are [RelayRoute]'s. */
        fun viaRelay(
            identityB64: String,
            relayAddr: String,
            relayPort: Int,
            session: String,
            pinHex: String
        ): PairedHostRecord? {
            val identity = cleanIdentity(identityB64) ?: return null
            val route = RelayRoute.of(relayAddr, relayPort, session, pinHex) ?: return null
            return PairedHostRecord(identity, lan = null, relay = route, preferRelay = true)
        }

        /**
         * Both routes, or a refusal — including when they pin different keys.
         * Used by the codec to rebuild a record stored as two lines.
         */
        internal fun both(
            identityB64: String,
            lan: PairedHost,
            relay: RelayRoute,
            preferRelay: Boolean
        ): PairedHostRecord? {
            val identity = cleanIdentity(identityB64) ?: return null
            if (lan.pinHex != relay.pinHex) return null
            return PairedHostRecord(identity, lan, relay, preferRelay)
        }

        private fun cleanIdentity(identityB64: String): String? {
            val identity = identityB64.trim()
            if (identity.isEmpty()) return null
            if (identity.any { it.isISOControl() }) return null
            return identity
        }
    }
}

/**
 * The stored form of the host list.
 *
 * One route per line, tab-separated. Base64, base64url, hex and addresses
 * contain neither tabs nor newlines — and the factories refuse any value that
 * does — so the encoding is unambiguous without escaping, and a format that
 * needs no escaping cannot be broken by a value that forgot to escape itself.
 *
 * ## Two line shapes, and why the LAN one never changes
 *
 * ```
 * <identity> TAB <addr> TAB <port> TAB <pin>                                     LAN
 * relay TAB <identity> TAB <relayAddr> TAB <relayPort> TAB <session> TAB <pin> TAB <preferred|standby>
 * ```
 *
 * The LAN line is byte-for-byte what every released build writes, and every
 * released build reads a line only if it has exactly four fields. So:
 *
 * - **an upgrade** reads the released lines as LAN routes, unchanged;
 * - **a downgrade** to a released build drops the relay lines and KEEPS the LAN
 *   ones — a host paired both ways loses only the route the old build could not
 *   have used. All 3.0.13 builds share one versionCode, so installing an older
 *   one over this is an ordinary update, not a hypothetical.
 *
 * A host paired both ways is therefore two lines, not one longer line. One
 * longer line would be dropped whole by an older build, LAN route and all.
 *
 * Pure, so the persisted format is a tested contract rather than something only
 * observable through `SharedPreferences` on a device.
 */
object PairedHostCodec {

    private const val FIELD = '\t'
    private const val LINE = '\n'
    private const val RELAY_MARK = "relay"
    private const val PREFERRED = "preferred"
    private const val STANDBY = "standby"

    fun encode(records: List<PairedHostRecord>): String {
        val lines = ArrayList<String>()
        for (r in records) {
            r.lan?.let {
                lines += listOf(r.identityB64, it.addr, it.port.toString(), it.pinHex)
                    .joinToString("$FIELD")
            }
            r.relay?.let {
                lines += listOf(
                    RELAY_MARK,
                    r.identityB64,
                    it.relayAddr,
                    it.relayPort.toString(),
                    it.session,
                    it.pinHex,
                    if (r.preferRelay) PREFERRED else STANDBY
                ).joinToString("$FIELD")
            }
        }
        return lines.joinToString("$LINE")
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
     * not unpair every host on the phone — and a corrupt RELAY line must not
     * cost a host its LAN route.
     */
    fun decode(text: String?): List<PairedHostRecord> {
        if (text.isNullOrEmpty()) return emptyList()
        // Identity order is first appearance, so the list keeps the order hosts
        // were added in, whichever of a host's lines comes first.
        val order = ArrayList<String>()
        val lans = HashMap<String, PairedHost>()
        val relays = HashMap<String, Pair<RelayRoute, Boolean>>()
        for (line in text.split(LINE)) {
            if (line.isBlank()) continue
            val f = line.split(FIELD)
            when {
                f.size == 4 -> {
                    val port = f[2].toIntOrNull() ?: continue
                    val record = PairedHostRecord.of(f[0], f[1], port, f[3]) ?: continue
                    // A repeated identity is not two hosts. It is one host recorded
                    // twice, and the two copies can disagree about the address — so
                    // the first wins and the duplicate is dropped, rather than
                    // leaving the list to decide by iteration order which one a
                    // connect uses.
                    if (lans.containsKey(record.identityB64)) continue
                    lans[record.identityB64] = record.lan!!
                    if (record.identityB64 !in order) order += record.identityB64
                }
                f.size == 7 && f[0] == RELAY_MARK -> {
                    val port = f[3].toIntOrNull() ?: continue
                    val preferred = when (f[6]) {
                        PREFERRED -> true
                        STANDBY -> false
                        else -> continue
                    }
                    val record = PairedHostRecord.viaRelay(f[1], f[2], port, f[4], f[5]) ?: continue
                    if (relays.containsKey(record.identityB64)) continue
                    relays[record.identityB64] = record.relay!! to preferred
                    if (record.identityB64 !in order) order += record.identityB64
                }
                // Any other shape is from a build this one does not understand,
                // or is damage. Absent, like every other unreadable line.
                else -> continue
            }
        }
        val out = ArrayList<PairedHostRecord>()
        for (identity in order) {
            val lan = lans[identity]
            val relay = relays[identity]
            val record = when {
                lan != null && relay != null ->
                    // Two routes that pin different keys cannot both be this
                    // host. The LAN route is the one every build can read, so it
                    // is the one kept; the relay route is treated as damage.
                    PairedHostRecord.both(identity, lan, relay.first, relay.second)
                        ?: PairedHostRecord(identity, lan)
                lan != null -> PairedHostRecord(identity, lan)
                relay != null -> PairedHostRecord(identity, null, relay.first, preferRelay = true)
                else -> null
            }
            if (record != null) out += record
        }
        return out
    }
}
