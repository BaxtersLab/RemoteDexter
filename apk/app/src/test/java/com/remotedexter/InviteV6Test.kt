package com.remotedexter

import com.remotedexter.bootstrap18.Decoded
import com.remotedexter.bootstrap18.InviteDecoder
import com.remotedexter.bootstrap18.InviteSignatureVerifier
import com.remotedexter.bootstrap18.InviteV4
import com.remotedexter.bootstrap18.InviteV5
import com.remotedexter.bootstrap18.InviteV6
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The Android half of pairing v6 — a host serving BOTH routes at once —
 * including the cross-language canonical-byte agreement.
 *
 * v6 always carries both routes. What must never happen: a v6 read under v4's
 * or v5's rules, a route swapped in transit, or a v6 that lost a route being
 * read as the route it kept.
 */
class InviteV6Test {

    private fun priv(seed: Byte) = Ed25519PrivateKeyParameters(ByteArray(32) { seed }, 0)

    private fun identityB64(k: Ed25519PrivateKeyParameters): String =
        Base64.getEncoder().encodeToString(k.generatePublicKey().encoded)

    private fun sign(k: Ed25519PrivateKeyParameters, msg: ByteArray): String {
        val s = Ed25519Signer().apply { init(true, k) }
        s.update(msg, 0, msg.size)
        return Base64.getEncoder().encodeToString(s.generateSignature())
    }

    private fun verify(identB64: String, msg: ByteArray, sigB64: String): Boolean = try {
        val pub = Ed25519PublicKeyParameters(Base64.getDecoder().decode(identB64), 0)
        val v = Ed25519Signer().apply { init(false, pub) }
        v.update(msg, 0, msg.size)
        v.verifySignature(Base64.getDecoder().decode(sigB64))
    } catch (e: Exception) {
        false
    }

    private fun invite(
        addr: String = "192.168.1.20",
        relayAddr: String = "203.0.113.9",
        caps: List<String> = listOf("view", "control")
    ): InviteV6 {
        val k = priv(11)
        val unsigned = InviteV6(
            kind = InviteDecoder.INVITE_KIND, version = 6, protocol = "rdv3",
            addr = addr, port = 8082,
            relayAddr = relayAddr, relayPort = 9443, session = "Zm9vYmFyYmF6cXV4MDAwMA",
            token = "1f".repeat(32), nonce = "9c".repeat(16), expiresAt = 1787000060L,
            capabilities = caps, hostPubkey = "ab".repeat(32),
            hostIdentityPubkey = identityB64(k), signature = ""
        )
        return unsigned.copy(signature = sign(k, InviteDecoder.canonicalBytesV6(unsigned)))
    }

    private fun jsonObject(i: InviteV6): JSONObject = JSONObject(
        mapOf(
            "kind" to i.kind, "version" to i.version, "protocol" to i.protocol,
            "addr" to i.addr, "port" to i.port,
            "relay_addr" to i.relayAddr, "relay_port" to i.relayPort, "session" to i.session,
            "token" to i.token, "nonce" to i.nonce, "expires_at" to i.expiresAt,
            "capabilities" to i.capabilities, "host_pubkey" to i.hostPubkey,
            "host_identity_pubkey" to i.hostIdentityPubkey, "signature" to i.signature
        )
    )

    @Test
    fun a_v6_invite_decodes_with_both_routes_and_its_signature_verifies() {
        val d = InviteDecoder.decode(jsonObject(invite()).toString())
        assertTrue("expected V6, got " + d, d is Decoded.V6)
        val i = (d as Decoded.V6).invite
        assertEquals("192.168.1.20", i.addr)
        assertEquals(8082, i.port)
        assertEquals("203.0.113.9", i.relayAddr)
        assertEquals(9443, i.relayPort)
        assertEquals("Zm9vYmFyYmF6cXV4MDAwMA", i.session)
        assertTrue(InviteSignatureVerifier.isValidV6(i))
    }

    /**
     * **The cross-version substitution.** A v6 signature must not verify under
     * v4's or v5's encoding — otherwise one route could be lifted out of a v6
     * code and presented as a code that names only that route.
     */
    /**
     * `isValidV6` answers for version 6 only — even for a signature that is
     * genuinely valid over v6's layout with another number in it. Added
     * 2026-09-17: dropping the version check broke nothing.
     */
    @Test
    fun the_v6_verifier_refuses_any_other_version_even_when_validly_signed() {
        val k = priv(11)
        for (other in listOf(4, 5, 7)) {
            val unsigned = invite().copy(version = other, signature = "")
            val signed = unsigned.copy(signature = sign(k, InviteDecoder.canonicalBytesV6(unsigned)))
            assertTrue(
                "the signature under test must itself be valid",
                verify(signed.hostIdentityPubkey, InviteDecoder.canonicalBytesV6(signed), signed.signature)
            )
            assertFalse("isValidV6 accepted version $other", InviteSignatureVerifier.isValidV6(signed))
        }
    }

    @Test
    fun a_v6_invite_cannot_be_verified_under_v4_or_v5_rules() {
        val i = invite()
        val asV4 = InviteV4(
            kind = i.kind, version = 6, protocol = i.protocol, addr = i.addr, port = i.port,
            token = i.token, nonce = i.nonce, expiresAt = i.expiresAt,
            capabilities = i.capabilities, hostPubkey = i.hostPubkey,
            hostIdentityPubkey = i.hostIdentityPubkey, signature = i.signature
        )
        val asV5 = InviteV5(
            kind = i.kind, version = 6, protocol = i.protocol, relayAddr = i.relayAddr,
            relayPort = i.relayPort, session = i.session, token = i.token, nonce = i.nonce,
            expiresAt = i.expiresAt, capabilities = i.capabilities, hostPubkey = i.hostPubkey,
            hostIdentityPubkey = i.hostIdentityPubkey, signature = i.signature
        )
        assertFalse(
            "a v6 signature verified under v4's encoding",
            verify(i.hostIdentityPubkey, InviteDecoder.canonicalBytesV4(asV4), i.signature)
        )
        assertFalse(
            "a v6 signature verified under v5's encoding",
            verify(i.hostIdentityPubkey, InviteDecoder.canonicalBytesV5(asV5), i.signature)
        )
        assertFalse(
            "a v6 invite relabelled as v5 verified",
            InviteSignatureVerifier.isValidV6(i.copy(version = 5))
        )
    }

    /** Both routes, and each part of each route, are inside the signature. */
    @Test
    fun both_routes_are_signed() {
        val i = invite()
        for ((what, tampered) in listOf(
            "addr" to i.copy(addr = "192.168.1.99"),
            "port" to i.copy(port = 8083),
            "relay_addr" to i.copy(relayAddr = "198.51.100.4"),
            "relay_port" to i.copy(relayPort = 1234),
            "session" to i.copy(session = "BBBBBBBBBBBBBBBBBBBBBB")
        )) {
            assertFalse(
                "a v6 invite with a changed $what still verified",
                InviteSignatureVerifier.isValidV6(tampered)
            )
        }
    }

    /**
     * **A v6 that lost a route is refused, not read as the route it kept.**
     * v6 always carries both; a code with one missing is damaged or forged, and
     * reading it anyway would connect by a route the host never signed alone.
     */
    @Test
    fun a_v6_missing_either_route_is_malformed() {
        for (field in listOf("addr", "port", "relay_addr", "relay_port", "session")) {
            val obj = jsonObject(invite())
            obj.remove(field)
            val d = InviteDecoder.decode(obj.toString())
            assertTrue("removing $field gave $d", d is Decoded.Malformed)
            assertEquals(field, (d as Decoded.Malformed).field)
        }
    }

    @Test
    fun capabilities_cannot_be_widened_in_transit() {
        val widened = invite().copy(capabilities = listOf("view", "control", "admin"))
        assertFalse(InviteSignatureVerifier.isValidV6(widened))
    }

    /** A field carrying the separator makes the signed bytes ambiguous. */
    @Test
    fun a_route_field_carrying_the_separator_is_refused() {
        for ((field, i) in listOf(
            "addr" to invite(addr = "192.168.1.20\n8082"),
            "relay_addr" to invite(relayAddr = "203.0.113.9\n9443"),
            // Added 2026-09-17: dropping `session` from the check went unnoticed.
            "session" to invite().copy(session = "Zm9v\nYmFy")
        )) {
            val d = InviteDecoder.decode(jsonObject(i).toString())
            assertTrue("expected SeparatorInField, got $d", d is Decoded.SeparatorInField)
            assertEquals(field, (d as Decoded.SeparatorInField).field)
        }
    }

    /**
     * A QR that is not a pairing invite is named as such, not reported as a bad
     * signature. Added 2026-09-17 with the Rust twin, when dropping the v6 kind
     * check broke nothing on either side.
     */
    @Test
    fun a_v6_qr_that_is_not_a_pairing_invite_is_named_as_such() {
        val d = InviteDecoder.decode(jsonObject(invite().copy(kind = "something-else")).toString())
        assertTrue("expected WrongKind, got $d", d is Decoded.WrongKind)
        assertEquals("something-else", (d as Decoded.WrongKind).found)
    }

    /**
     * Generates the Kotlin half of contract/signed_invite_v6.json with fixed
     * inputs — the v4 Kotlin vector's LAN route and the v5 Kotlin vector's relay
     * route, under the same key. Rust verifies the recorded output; this asserts
     * Kotlin still produces exactly what was recorded, byte for byte.
     */
    @Test
    fun kotlin_reproduces_the_shared_canonical_bytes() {
        val k = priv(23)
        val i = InviteV6(
            kind = InviteDecoder.INVITE_KIND, version = 6, protocol = "rdv3",
            addr = "10.0.0.7", port = 9100,
            relayAddr = "198.51.100.4", relayPort = 7443,
            session = "c2Vzc2lvbmlkZm9ya290bA", token = "3c".repeat(32),
            nonce = "5e".repeat(16), expiresAt = 1787111222L, capabilities = listOf("view"),
            hostPubkey = "cd".repeat(32), hostIdentityPubkey = identityB64(k), signature = ""
        )
        val canonical = InviteDecoder.canonicalBytesV6(i)
        val sig = sign(k, canonical)

        println("KOTLIN_VECTOR canonical_utf8=" + String(canonical, Charsets.UTF_8))
        println("KOTLIN_VECTOR host_identity_pubkey=" + identityB64(k))
        println("KOTLIN_VECTOR signature=" + sig)

        val expected = "remotedexter-pair@6@rdv3@10.0.0.7@9100@198.51.100.4@7443@" +
            "c2Vzc2lvbmlkZm9ya290bA@" + "3c".repeat(32) + "@" + "5e".repeat(16) +
            "@1787111222@view@" + "cd".repeat(32)
        assertEquals(expected.replace("@", NEWLINE), String(canonical, Charsets.UTF_8))
        assertTrue(verify(identityB64(k), canonical, sig))
    }

    /** The other direction: Kotlin verifies the vector RUST generated. */
    @Test
    fun kotlin_verifies_the_rust_generated_vector() {
        val fixture = java.io.File("../../contract/signed_invite_v6.json")
        assertTrue("fixture not found at " + fixture.absolutePath, fixture.exists())
        val v = JSONObject(fixture.readText()).getJSONObject("rust_generated")

        val i = fromJson(v)
        assertEquals(
            "Kotlin and Rust disagree on the v6 canonical encoding",
            v.getString("canonical_utf8"),
            String(InviteDecoder.canonicalBytesV6(i), Charsets.UTF_8)
        )
        assertTrue(
            "the signature Rust produced must verify here",
            InviteSignatureVerifier.isValidV6(i)
        )
    }

    /** Every negative control in the fixture must fail to verify here too. */
    @Test
    fun kotlin_rejects_every_negative_control_in_the_fixture() {
        val fixture = java.io.File("../../contract/signed_invite_v6.json")
        val negatives = JSONObject(fixture.readText()).getJSONArray("negative")
        assertTrue("the fixture carries no negative controls", negatives.length() > 0)
        for (n in 0 until negatives.length()) {
            val c = negatives.getJSONObject(n)
            assertFalse(
                "negative control " + c.getString("name") + " VERIFIED - it must not",
                InviteSignatureVerifier.isValidV6(fromJson(c))
            )
        }
    }

    private fun fromJson(v: JSONObject): InviteV6 {
        val capsArr = v.getJSONArray("capabilities")
        val caps = ArrayList<String>(capsArr.length())
        for (n in 0 until capsArr.length()) caps.add(capsArr.getString(n))
        return InviteV6(
            kind = v.getString("kind"), version = v.getInt("version"),
            protocol = v.getString("protocol"),
            addr = v.getString("addr"), port = v.getInt("port"),
            relayAddr = v.getString("relay_addr"), relayPort = v.getInt("relay_port"),
            session = v.getString("session"),
            token = v.getString("token"), nonce = v.getString("nonce"),
            expiresAt = v.getLong("expires_at"), capabilities = caps,
            hostPubkey = v.getString("host_pubkey"),
            hostIdentityPubkey = v.getString("host_identity_pubkey"),
            signature = v.getString("signature")
        )
    }

    companion object {
        private const val NEWLINE = "\n"
    }
}
