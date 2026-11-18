package com.remotedexter

import com.remotedexter.bootstrap18.Decoded
import com.remotedexter.bootstrap18.InviteDecoder
import com.remotedexter.bootstrap18.InviteSignatureVerifier
import com.remotedexter.bootstrap18.InviteV4
import com.remotedexter.bootstrap18.InviteV5
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The Android half of pairing v5 — the RELAY route — including the
 * cross-language canonical-byte agreement.
 *
 * v5 is not a successor to v4. Both are current: a bound host emits v4, a host
 * that dialled out to a relay emits v5. What must never happen is one being
 * read under the other's rules, and that has its own test here.
 */
class InviteV5Test {

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
        relayAddr: String = "203.0.113.9",
        relayPort: Int = 9443,
        session: String = "Zm9vYmFyYmF6cXV4MDAwMA",
        expiresAt: Long = 1787000060L,
        caps: List<String> = listOf("view", "control")
    ): InviteV5 {
        val k = priv(11)
        val unsigned = InviteV5(
            kind = InviteDecoder.INVITE_KIND, version = 5, protocol = "rdv3",
            relayAddr = relayAddr, relayPort = relayPort, session = session,
            token = "1f".repeat(32), nonce = "9c".repeat(16), expiresAt = expiresAt,
            capabilities = caps, hostPubkey = "ab".repeat(32),
            hostIdentityPubkey = identityB64(k), signature = ""
        )
        return unsigned.copy(signature = sign(k, InviteDecoder.canonicalBytesV5(unsigned)))
    }

    private fun json(i: InviteV5): String = JSONObject(
        mapOf(
            "kind" to i.kind, "version" to i.version, "protocol" to i.protocol,
            "relay_addr" to i.relayAddr, "relay_port" to i.relayPort, "session" to i.session,
            "token" to i.token, "nonce" to i.nonce, "expires_at" to i.expiresAt,
            "capabilities" to i.capabilities, "host_pubkey" to i.hostPubkey,
            "host_identity_pubkey" to i.hostIdentityPubkey, "signature" to i.signature
        )
    ).toString()

    @Test
    fun a_v5_invite_decodes_and_its_signature_verifies() {
        val d = InviteDecoder.decode(json(invite()))
        assertTrue("expected V5, got " + d, d is Decoded.V5)
        val i = (d as Decoded.V5).invite
        assertEquals("203.0.113.9", i.relayAddr)
        assertEquals(9443, i.relayPort)
        assertEquals("Zm9vYmFyYmF6cXV4MDAwMA", i.session)
        assertTrue(InviteSignatureVerifier.isValidV5(i))
    }

    /**
     * **The cross-version substitution.** A v5 invite read under v4's encoding
     * must not verify. `version` is inside the signed bytes and the encodings
     * have different shapes, so neither can be read as the other.
     */
    @Test
    fun a_v5_invite_cannot_be_verified_under_v4_rules() {
        val i = invite()
        val asV4 = InviteV4(
            kind = i.kind, version = 4, protocol = i.protocol,
            addr = i.relayAddr, port = i.relayPort, token = i.token, nonce = i.nonce,
            expiresAt = i.expiresAt, capabilities = i.capabilities,
            hostPubkey = i.hostPubkey, hostIdentityPubkey = i.hostIdentityPubkey,
            signature = i.signature
        )
        assertNotEquals(
            String(InviteDecoder.canonicalBytesV5(i), Charsets.UTF_8),
            String(InviteDecoder.canonicalBytesV4(asV4), Charsets.UTF_8)
        )
        assertFalse(
            "a v5 signature verified under v4 rules",
            verify(i.hostIdentityPubkey, InviteDecoder.canonicalBytesV4(asV4), i.signature)
        )
    }

    /** The session id decides which host the relay splices to. */
    @Test
    fun the_session_id_is_signed() {
        val tampered = invite().copy(session = "BBBBBBBBBBBBBBBBBBBBBB")
        assertFalse(InviteSignatureVerifier.isValidV5(tampered))
    }

    @Test
    fun the_relay_endpoint_is_signed() {
        assertFalse(InviteSignatureVerifier.isValidV5(invite().copy(relayAddr = "198.51.100.4")))
        assertFalse(InviteSignatureVerifier.isValidV5(invite().copy(relayPort = 1234)))
    }

    @Test
    fun capabilities_cannot_be_widened_in_transit() {
        val widened = invite().copy(capabilities = listOf("view", "control", "admin"))
        assertFalse(InviteSignatureVerifier.isValidV5(widened))
    }

    /** A field carrying the separator makes the signed bytes ambiguous. */
    @Test
    fun a_field_carrying_the_separator_is_refused() {
        val d = InviteDecoder.decode(json(invite(relayAddr = "203.0.113.9\n9443")))
        assertTrue("expected SeparatorInField, got " + d, d is Decoded.SeparatorInField)
        assertEquals("relay_addr", (d as Decoded.SeparatorInField).field)
    }

    @Test
    fun an_unknown_version_is_still_refused_by_number() {
        // 7, not 6: v6 is the both-routes invite now.
        val text = json(invite()).replace("\"version\":5", "\"version\":7")
        val d = InviteDecoder.decode(text)
        assertTrue("expected UnsupportedVersion, got " + d, d is Decoded.UnsupportedVersion)
        assertEquals(7, (d as Decoded.UnsupportedVersion).found)
    }

    /**
     * Generates the Kotlin half of contract/signed_invite_v5.json with fixed
     * inputs. Rust verifies the recorded output; this asserts Kotlin still
     * produces exactly what was recorded, byte for byte.
     */
    @Test
    fun kotlin_reproduces_the_shared_canonical_bytes() {
        val k = priv(23)
        val i = InviteV5(
            kind = InviteDecoder.INVITE_KIND, version = 5, protocol = "rdv3",
            relayAddr = "198.51.100.4", relayPort = 7443,
            session = "c2Vzc2lvbmlkZm9ya290bA", token = "3c".repeat(32),
            nonce = "5e".repeat(16), expiresAt = 1787111222L, capabilities = listOf("view"),
            hostPubkey = "cd".repeat(32), hostIdentityPubkey = identityB64(k), signature = ""
        )
        val canonical = InviteDecoder.canonicalBytesV5(i)
        val sig = sign(k, canonical)

        println("KOTLIN_VECTOR canonical_utf8=" + String(canonical, Charsets.UTF_8))
        println("KOTLIN_VECTOR host_identity_pubkey=" + identityB64(k))
        println("KOTLIN_VECTOR signature=" + sig)

        val expected = "remotedexter-pair@5@rdv3@198.51.100.4@7443@c2Vzc2lvbmlkZm9ya290bA@" +
            "3c".repeat(32) + "@" + "5e".repeat(16) + "@1787111222@view@" + "cd".repeat(32)
        assertEquals(expected.replace("@", NEWLINE), String(canonical, Charsets.UTF_8))
        assertTrue(verify(identityB64(k), canonical, sig))
    }

    /**
     * The other direction: Kotlin verifies the vector RUST generated.
     *
     * Without this, both sides could be self-consistently wrong in the same way
     * and every other test here would still pass.
     */
    @Test
    fun kotlin_verifies_the_rust_generated_vector() {
        val fixture = java.io.File("../../contract/signed_invite_v5.json")
        assertTrue("fixture not found at " + fixture.absolutePath, fixture.exists())
        val v = JSONObject(fixture.readText()).getJSONObject("rust_generated")

        val i = fromJson(v)
        val canonical = InviteDecoder.canonicalBytesV5(i)
        assertEquals(
            "Kotlin and Rust disagree on the v5 canonical encoding",
            v.getString("canonical_utf8"),
            String(canonical, Charsets.UTF_8)
        )
        assertTrue(
            "the signature Rust produced must verify here",
            InviteSignatureVerifier.isValidV5(i)
        )
    }

    /** Every negative control in the fixture must fail to verify here too. */
    @Test
    fun kotlin_rejects_every_negative_control_in_the_fixture() {
        val fixture = java.io.File("../../contract/signed_invite_v5.json")
        val negatives = JSONObject(fixture.readText()).getJSONArray("negative")
        assertTrue("the fixture carries no negative controls", negatives.length() > 0)
        for (n in 0 until negatives.length()) {
            val c = negatives.getJSONObject(n)
            assertFalse(
                "negative control " + c.getString("name") + " VERIFIED - it must not",
                InviteSignatureVerifier.isValidV5(fromJson(c))
            )
        }
    }

    private fun fromJson(v: JSONObject): InviteV5 {
        val capsArr = v.getJSONArray("capabilities")
        val caps = ArrayList<String>(capsArr.length())
        for (n in 0 until capsArr.length()) caps.add(capsArr.getString(n))
        return InviteV5(
            kind = v.getString("kind"), version = v.getInt("version"),
            protocol = v.getString("protocol"), relayAddr = v.getString("relay_addr"),
            relayPort = v.getInt("relay_port"), session = v.getString("session"),
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
