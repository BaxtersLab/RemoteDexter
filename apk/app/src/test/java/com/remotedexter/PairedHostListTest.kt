package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The stored form of the host list, and the rule for how much a Forget takes.
 *
 * The persisted format is tested directly rather than through
 * `SharedPreferences`, because it is a contract: a build that writes it and a
 * later build that reads it are different programs, and the only thing joining
 * them is this encoding.
 */
class PairedHostListTest {

    private val pinA = "a".repeat(64)
    private val pinB = "b".repeat(64)

    private fun record(identity: String, addr: String, port: Int = 8081, pin: String = pinA) =
        PairedHostRecord.of(identity, addr, port, pin)!!

    // ── the record ────────────────────────────────────────────────────────

    /**
     * The address rules belong to [PairedHost] and are not duplicated, so this
     * checks that a record really does refuse when its host half does — a
     * record that accepted a port of 0 would put "let the OS choose" where a
     * destination belongs.
     */
    @Test
    fun aRecordIsOnlyAsValidAsItsHostHalf() {
        assertNull(PairedHostRecord.of("id", "192.168.1.9", 0, pinA))
        assertNull(PairedHostRecord.of("id", "", 8081, pinA))
        assertNull(PairedHostRecord.of("id", "192.168.1.9", 8081, "abc"))
        assertNotNull(PairedHostRecord.of("id", "192.168.1.9", 8081, pinA))
    }

    /** An identity is what decides whether a host is known. Blank decides nothing. */
    @Test
    fun aRecordWithoutAnIdentityIsRefused() {
        assertNull(PairedHostRecord.of("", "192.168.1.9", 8081, pinA))
        assertNull(PairedHostRecord.of("   ", "192.168.1.9", 8081, pinA))
    }

    /**
     * The fingerprint shown in the list is a PREFIX of the same key the
     * identity-mismatch sheet prints. Two different-looking strings for one
     * host, shown at the moment the operator is trying to decide whether it is
     * the same host, would be the worst possible time to be inconsistent.
     */
    @Test
    fun theFingerprintIsAPrefixOfWhatTheMismatchSheetShows() {
        val identity = "ABCDEFGHIJKLMNOPQRSTUVWX="
        val r = record(identity, "192.168.1.9")
        assertEquals(identity.take(PairedHostRecord.FINGERPRINT_CHARS), r.fingerprint())
        assertTrue(
            "the sheet's 16-character form must start with what the list shows",
            identity.take(16).startsWith(r.fingerprint())
        )
    }

    // ── the codec ─────────────────────────────────────────────────────────

    @Test
    fun aListSurvivesARoundTrip() {
        val records = listOf(
            record("id-one", "192.168.1.9", 8081, pinA),
            record("id-two", "10.0.0.4", 9000, pinB)
        )
        assertEquals(records, PairedHostCodec.decode(PairedHostCodec.encode(records)))
    }

    @Test
    fun anEmptyOrAbsentListDecodesToNothing() {
        assertEquals(emptyList<PairedHostRecord>(), PairedHostCodec.decode(null))
        assertEquals(emptyList<PairedHostRecord>(), PairedHostCodec.decode(""))
        assertEquals(emptyList<PairedHostRecord>(), PairedHostCodec.encode(emptyList()).let {
            PairedHostCodec.decode(it)
        })
    }

    /**
     * **One corrupt record must not unpair every host on the phone.**
     *
     * Preferences survive upgrades, downgrades and restores from backup, so a
     * line that no longer parses is a real possibility rather than a
     * hypothetical. Dropping the line costs the user one QR scan; dropping the
     * file would cost them all of them.
     */
    @Test
    fun oneUnreadableLineDoesNotTakeTheOthersWithIt() {
        val good = record("id-one", "192.168.1.9")
        val text = listOf(
            "this line has too few fields",
            PairedHostCodec.encode(listOf(good)),
            "id-three\t192.168.1.20\tnot-a-port\t$pinA",
            "id-four\t192.168.1.21\t8081\tshort-pin"
        ).joinToString("\n")
        assertEquals(listOf(good), PairedHostCodec.decode(text))
    }

    /**
     * A repeated identity is one host written twice, not two hosts — and the
     * copies can disagree about the address. The first wins, rather than
     * leaving iteration order to decide which address a connect uses.
     */
    @Test
    fun aRepeatedIdentityIsOneHost() {
        val first = record("same", "192.168.1.9")
        val second = record("same", "10.9.9.9")
        val decoded = PairedHostCodec.decode(PairedHostCodec.encode(listOf(first, second)))
        assertEquals(listOf(first), decoded)
    }

    /**
     * The encoding needs no escaping because its fields cannot contain its
     * delimiters — base64 and hex have neither tabs nor newlines, and the
     * address is validated before it is stored. Asserted rather than assumed,
     * since a format that silently needs escaping breaks on the one value
     * nobody tried.
     */
    @Test
    fun nothingStorableCanContainTheDelimiters() {
        val encoded = PairedHostCodec.encode(
            listOf(record("id-one", "192.168.1.9"), record("id-two", "10.0.0.4"))
        )
        assertEquals(2, encoded.split("\n").size)
        for (line in encoded.split("\n")) {
            assertEquals("every line must hold exactly four fields", 4, line.split("\t").size)
        }
    }

    // ── how much a Forget takes ───────────────────────────────────────────

    /**
     * The device's own Noise identity is ONE key shared by every pairing. Drop
     * it while other hosts remain and forgetting one host silently unpairs the
     * phone from all of them — the records survive, so the app keeps offering
     * to reconnect to hosts that will now refuse.
     */
    @Test
    fun forgettingOneOfSeveralKeepsTheDeviceIdentity() {
        assertEquals(ForgetHostPolicy.Scope.ThisHostOnly, ForgetHostPolicy.scopeFor(1))
        assertEquals(ForgetHostPolicy.Scope.ThisHostOnly, ForgetHostPolicy.scopeFor(4))
    }

    /**
     * And the opposite slip: keep the identity when nothing remains, and a
     * phone the user was told is unpaired is still enrolled at the last host,
     * which would still let it in.
     */
    @Test
    fun forgettingTheLastHostTakesTheDeviceIdentityToo() {
        assertEquals(ForgetHostPolicy.Scope.HostAndDeviceIdentity, ForgetHostPolicy.scopeFor(0))
        assertEquals(
            "a count below zero cannot happen and must not be the permissive case",
            ForgetHostPolicy.Scope.HostAndDeviceIdentity,
            ForgetHostPolicy.scopeFor(-1)
        )
    }

    /**
     * The app cannot revoke itself at the host — only the host's own Revoke
     * does that. So whenever the device identity is kept, the user is forgetting
     * their own note rather than withdrawing permission, and telling them
     * "unpaired" would be untrue.
     */
    @Test
    fun keepingTheIdentityMeansTheUserIsToldTheHostMayStillKnowThem() {
        assertTrue(
            ForgetHostPolicy.mustWarnHostStillKnowsUs(ForgetHostPolicy.Scope.ThisHostOnly)
        )
        assertTrue(
            !ForgetHostPolicy.mustWarnHostStillKnowsUs(
                ForgetHostPolicy.Scope.HostAndDeviceIdentity
            )
        )
    }
}
