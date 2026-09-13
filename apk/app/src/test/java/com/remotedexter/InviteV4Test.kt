package com.remotedexter

import com.remotedexter.bootstrap18.Decoded
import com.remotedexter.bootstrap18.InviteDecoder
import com.remotedexter.bootstrap18.InvitePayload
import com.remotedexter.bootstrap18.InviteSignatureVerifier
import com.remotedexter.bootstrap18.InviteV3
import com.remotedexter.bootstrap18.InviteV4
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
 * The Android half of pairing v4: decoding, the trust boundary, and the
 * cross-language canonical-byte agreement.
 *
 * These run on the JVM with no emulator because every one is pure logic - and
 * because these branches ARE the security boundary for pairing, so they must be
 * cheap enough to run on every change.
 */
class InviteV4Test {

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

    private fun validInviteJson(
        expiresAt: Long = 1787000060L,
        caps: List<String> = listOf("view", "control")
    ): String {
        val k = priv(11)
        val i = InviteV4(
            kind = InviteDecoder.INVITE_KIND, version = 4, protocol = "rdv3",
            addr = "192.168.1.20", port = 8082, token = "1f".repeat(32),
            nonce = "9c".repeat(16), expiresAt = expiresAt, capabilities = caps,
            hostPubkey = "ab".repeat(32), hostIdentityPubkey = identityB64(k), signature = ""
        )
        val sig = sign(k, InviteDecoder.canonicalBytesV4(i))
        return JSONObject(
            mapOf(
                "kind" to i.kind, "version" to i.version, "protocol" to i.protocol,
                "addr" to i.addr, "port" to i.port, "token" to i.token, "nonce" to i.nonce,
                "expires_at" to i.expiresAt, "capabilities" to i.capabilities,
                "host_pubkey" to i.hostPubkey, "host_identity_pubkey" to i.hostIdentityPubkey,
                "signature" to sig
            )
        ).toString()
    }

    @Test
    fun a_v4_invite_decodes_and_its_signature_verifies() {
        val d = InviteDecoder.decode(validInviteJson())
        assertTrue("expected V4, got " + d, d is Decoded.V4)
        val i = (d as Decoded.V4).invite
        assertEquals("192.168.1.20", i.addr)
        assertEquals(8082, i.port)
        assertEquals(listOf("view", "control"), i.capabilities)
        assertTrue(verify(i.hostIdentityPubkey, InviteDecoder.canonicalBytesV4(i), i.signature))
    }

    @Test
    fun shipping_scanner_path_accepts_and_verifies_a_v4_invite() {
        val payload = InvitePayload.fromJson(JSONObject(validInviteJson()))
        assertEquals("192.168.1.20", payload.lan_ip)
        assertEquals("1f".repeat(32), payload.session_token)
        assertEquals(1787000060L, payload.expires_at)
        assertEquals(listOf("view", "control"), payload.capabilities)
        assertTrue(InviteSignatureVerifier.isValid(payload))
    }

    @Test
    fun the_installer_download_qr_is_refused_by_name() {
        val installer = JSONObject(
            mapOf("kind" to "remotedexter-install", "version" to 4, "url" to "https://example.invalid/app.apk")
        ).toString()
        val d = InviteDecoder.decode(installer)
        assertTrue("expected WrongKind, got " + d, d is Decoded.WrongKind)
        assertEquals("remotedexter-install", (d as Decoded.WrongKind).found)
    }

    @Test
    fun a_plain_url_qr_is_not_json_and_says_so() {
        assertTrue(InviteDecoder.decode("https://example.invalid/app.apk") is Decoded.NotJson)
        assertTrue(InviteDecoder.decode("") is Decoded.NotJson)
    }

    @Test
    fun tampering_with_any_signed_field_breaks_verification() {
        val good = (InviteDecoder.decode(validInviteJson()) as Decoded.V4).invite
        val tampered = listOf(
            good.copy(addr = "10.66.66.66"),
            good.copy(port = 9999),
            good.copy(expiresAt = good.expiresAt + 86400),
            good.copy(capabilities = good.capabilities + "admin"),
            good.copy(hostPubkey = "cc".repeat(32)),
            good.copy(token = "00".repeat(32))
        )
        for (t in tampered) {
            assertFalse(
                "a tampered invite still verified: " + t,
                verify(t.hostIdentityPubkey, InviteDecoder.canonicalBytesV4(t), t.signature)
            )
        }
    }

    @Test
    fun expiry_is_enforced_against_the_signed_timestamp() {
        val d = InviteDecoder.decode(validInviteJson(expiresAt = 1000L)) as Decoded.V4
        assertFalse(InviteDecoder.isExpired(d.invite, 999L))
        assertTrue(InviteDecoder.isExpired(d.invite, 1000L))
        assertTrue(InviteDecoder.isExpired(d.invite, 1001L))
    }

    @Test
    fun a_re_signed_invite_from_another_identity_is_caught_by_trust_not_signature() {
        val attacker = priv(99)
        val good = (InviteDecoder.decode(validInviteJson()) as Decoded.V4).invite
        val swapped = good.copy(hostIdentityPubkey = identityB64(attacker))
        val resigned = swapped.copy(signature = sign(attacker, InviteDecoder.canonicalBytesV4(swapped)))
        assertTrue(
            "an attacker signing their own invite produces a VALID signature",
            verify(resigned.hostIdentityPubkey, InviteDecoder.canonicalBytesV4(resigned), resigned.signature)
        )
        assertEquals(
            com.remotedexter.bootstrap18.InviteTrustResult.RejectedIdentityChanged,
            com.remotedexter.bootstrap18.InviteTrustPolicy.evaluate(
                resigned.hostIdentityPubkey, true, setOf(good.hostIdentityPubkey)
            )
        )
    }

    @Test
    fun a_v3_invite_decodes_under_v3_rules_and_is_not_promoted() {
        val k = priv(11)
        val v3 = InviteV3(
            addr = "192.168.1.20", port = 8082, token = "deadbeef", nonce = "abc123",
            protocol = "rdv3", wanIp = "203.0.113.7", hostPubkey = "dd".repeat(32),
            hostIdentityPubkey = identityB64(k), signature = ""
        )
        val sig = sign(k, InviteDecoder.canonicalBytesV3(v3))
        val json = JSONObject(
            mapOf(
                "version" to 3, "lan_ip" to v3.addr, "wan_ip" to v3.wanIp, "port" to v3.port,
                "session_token" to v3.token, "nonce" to v3.nonce, "protocol" to v3.protocol,
                "host_pubkey" to v3.hostPubkey, "host_identity_pubkey" to v3.hostIdentityPubkey,
                "signature" to sig
            )
        ).toString()

        val d = InviteDecoder.decode(json)
        assertTrue("expected V3, got " + d, d is Decoded.V3)
        val got = (d as Decoded.V3).invite
        assertTrue(verify(got.hostIdentityPubkey, InviteDecoder.canonicalBytesV3(got), sig))

        val asV4 = InviteV4(
            kind = InviteDecoder.INVITE_KIND, version = 4, protocol = got.protocol,
            addr = got.addr, port = got.port, token = got.token, nonce = got.nonce,
            expiresAt = 0, capabilities = emptyList(), hostPubkey = got.hostPubkey,
            hostIdentityPubkey = got.hostIdentityPubkey, signature = sig
        )
        assertFalse(
            "v3 and v4 canonical bytes must not be interchangeable",
            verify(asV4.hostIdentityPubkey, InviteDecoder.canonicalBytesV4(asV4), sig)
        )
    }

    @Test
    fun a_v3_invite_still_reads_the_pre_rename_host_ip_key() {
        val json = JSONObject(
            mapOf(
                "version" to 3, "host_ip" to "192.168.1.20", "port" to 8082,
                "session_token" to "t", "host_pubkey" to "x",
                "host_identity_pubkey" to "y", "signature" to "z"
            )
        ).toString()
        val d = InviteDecoder.decode(json)
        assertTrue("expected V3, got " + d, d is Decoded.V3)
        assertEquals("192.168.1.20", (d as Decoded.V3).invite.addr)
    }

    @Test
    fun an_unsupported_version_is_refused_by_number() {
        assertEquals(2, (InviteDecoder.decode(JSONObject(mapOf("version" to 2)).toString()) as Decoded.UnsupportedVersion).found)
        assertEquals(9, (InviteDecoder.decode(JSONObject(mapOf("version" to 9)).toString()) as Decoded.UnsupportedVersion).found)
    }

    @Test
    fun a_missing_required_field_is_named_and_nothing_throws() {
        val full = JSONObject(validInviteJson())
        for (field in listOf("token", "host_pubkey", "signature", "expires_at", "capabilities")) {
            val o = JSONObject(full.toString())
            o.remove(field)
            val d = InviteDecoder.decode(o.toString())
            assertTrue("removing " + field + " gave " + d, d is Decoded.Malformed)
            assertEquals(field, (d as Decoded.Malformed).field)
        }
        for (junk in listOf("null", "[]", "{}", " ", "not json at all")) {
            InviteDecoder.decode(junk)
        }
    }

    /**
     * Generates the Kotlin half of contract/signed_invite_v4.json with fixed
     * inputs. Rust verifies the recorded output; this asserts Kotlin still
     * produces exactly what was recorded, byte for byte.
     */
    @Test
    fun kotlin_reproduces_the_shared_canonical_bytes() {
        val k = priv(23)
        val i = InviteV4(
            kind = InviteDecoder.INVITE_KIND, version = 4, protocol = "rdv3",
            addr = "10.0.0.7", port = 9100, token = "3c".repeat(32), nonce = "5e".repeat(16),
            expiresAt = 1787111222L, capabilities = listOf("view"),
            hostPubkey = "cd".repeat(32), hostIdentityPubkey = identityB64(k), signature = ""
        )
        val canonical = InviteDecoder.canonicalBytesV4(i)
        val sig = sign(k, canonical)

        println("KOTLIN_VECTOR canonical_utf8=" + String(canonical, Charsets.UTF_8))
        println("KOTLIN_VECTOR host_identity_pubkey=" + identityB64(k))
        println("KOTLIN_VECTOR signature=" + sig)

        val expected = "remotedexter-pair@4@rdv3@10.0.0.7@9100@" + "3c".repeat(32) +
            "@" + "5e".repeat(16) + "@1787111222@view@" + "cd".repeat(32)
        assertEquals(expected.replace("@", NEWLINE), String(canonical, Charsets.UTF_8))
        assertTrue(verify(identityB64(k), canonical, sig))
    }

    /**
     * The other direction: Kotlin verifies the vector RUST generated.
     *
     * Without this, both sides could be self-consistently wrong in the same
     * way and every other test here would still pass.
     */
    @Test
    fun kotlin_verifies_the_rust_generated_vector() {
        val fixture = java.io.File("../../contract/signed_invite_v4.json")
        assertTrue("fixture not found at " + fixture.absolutePath, fixture.exists())
        val root = JSONObject(fixture.readText())
        val v = root.getJSONObject("rust_generated")

        val capsArr = v.getJSONArray("capabilities")
        val caps = ArrayList<String>(capsArr.length())
        for (n in 0 until capsArr.length()) caps.add(capsArr.getString(n))

        val i = InviteV4(
            kind = v.getString("kind"), version = v.getInt("version"),
            protocol = v.getString("protocol"), addr = v.getString("addr"),
            port = v.getInt("port"), token = v.getString("token"),
            nonce = v.getString("nonce"), expiresAt = v.getLong("expires_at"),
            capabilities = caps, hostPubkey = v.getString("host_pubkey"),
            hostIdentityPubkey = v.getString("host_identity_pubkey"),
            signature = v.getString("signature")
        )
        val canonical = InviteDecoder.canonicalBytesV4(i)
        assertEquals(
            "Kotlin and Rust disagree on the canonical encoding",
            v.getString("canonical_utf8"),
            String(canonical, Charsets.UTF_8)
        )
        assertTrue(
            "the signature Rust produced must verify here",
            verify(i.hostIdentityPubkey, canonical, i.signature)
        )
    }

    /** Every negative control in the fixture must fail to verify here too. */
    @Test
    fun kotlin_rejects_every_negative_control_in_the_fixture() {
        val fixture = java.io.File("../../contract/signed_invite_v4.json")
        val negatives = JSONObject(fixture.readText()).getJSONArray("negative")
        for (n in 0 until negatives.length()) {
            val c = negatives.getJSONObject(n)
            val capsArr = c.getJSONArray("capabilities")
            val caps = ArrayList<String>(capsArr.length())
            for (m in 0 until capsArr.length()) caps.add(capsArr.getString(m))
            val i = InviteV4(
                kind = c.getString("kind"), version = c.getInt("version"),
                protocol = c.getString("protocol"), addr = c.getString("addr"),
                port = c.getInt("port"), token = c.getString("token"),
                nonce = c.getString("nonce"), expiresAt = c.getLong("expires_at"),
                capabilities = caps, hostPubkey = c.getString("host_pubkey"),
                hostIdentityPubkey = c.getString("host_identity_pubkey"),
                signature = c.getString("signature")
            )
            assertFalse(
                "negative control " + c.getString("name") + " VERIFIED - it must not",
                verify(i.hostIdentityPubkey, InviteDecoder.canonicalBytesV4(i), i.signature)
            )
        }
    }

    companion object {
        private const val NEWLINE = "\n"
    }
}
