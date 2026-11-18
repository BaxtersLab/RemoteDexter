package com.remotedexter

import com.remotedexter.bootstrap18.InviteDecodeException
import com.remotedexter.bootstrap18.ScanFailureReport
import org.json.JSONException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a failed pairing scan is allowed to write down.
 *
 * READ THIS BEFORE ADDING A TEST HERE. These tests never ask the JSON parser to
 * produce the dangerous message, because **the JVM `org.json` on the test
 * classpath does not produce it**: its `syntaxError` appends only a position,
 * while Android's appends `" at character N of " + in` — the whole input. A
 * test that fed malformed JSON to the real parser and then checked the output
 * for a token would pass here and prove nothing about a phone.
 *
 * So the exception is CONSTRUCTED with a message that already contains a token,
 * exactly as the device's parser would have written it, and the requirement is
 * that the redactor does not pass it on. That property holds whatever any
 * platform's parser decides to say.
 */
class ScanFailureReportTest {

    /**
     * A stand-in for a 256-bit hex token. Never a real one — and BUILT rather
     * than pasted, deliberately.
     *
     * Written first as a literal, it was flagged by the repository's secret
     * scanner, which was right to: `val token = "<64 hex>"` is exactly the
     * shape of a credential, and a scanner that ignored it here would ignore
     * the real thing somewhere else. Nothing in this file should have to be
     * eyeballed to decide whether it is live.
     */
    private val token = (0 until 64)
        .map { "0123456789abcdef"[(it * 7 + 3) % 16] }
        .joinToString("")

    /** A real invite, in the host's field order, with one byte lost to a misread. */
    private val truncatedInvite =
        """{"kind":"remotedexter-pair","version":4,"protocol":"rdv3",""" +
            """"addr":"192.168.1.50","port":8082,"token":"$token","nonce":"aa"""

    /** The message Android's tokenizer really builds for that input. */
    private fun androidStyleTokenizerError(payload: String) =
        JSONException("Unterminated string at character 105 of $payload")

    @Test
    fun a_parser_message_quoting_the_payload_never_reaches_the_log() {
        val e = androidStyleTokenizerError(truncatedInvite)
        val lines = ScanFailureReport.describe(truncatedInvite, e)
        val joined = lines.joinToString("\n")
        assertFalse(
            "the token must not appear in the shareable log:\n$joined",
            joined.contains(token)
        )
        // Not merely the whole token — no run of it at all.
        assertFalse(joined.contains(token.take(16)))
        assertTrue(
            "the reader still has to learn what went wrong: $joined",
            joined.contains("JSONException")
        )
    }

    @Test
    fun a_parser_message_quoting_the_payload_never_reaches_the_screen() {
        val detail = ScanFailureReport.userDetail(androidStyleTokenizerError(truncatedInvite))
        assertFalse(detail.contains(token))
        assertFalse(detail.contains(token.take(16)))
        assertTrue(detail.contains("JSONException"))
    }

    /**
     * The case the old code got backwards.
     *
     * It echoed 60 characters of any payload that failed to parse, justified by
     * "not JSON, therefore not an invite, therefore no token". A truncated
     * invite is all three of not-JSON, an invite, and carrying a live token.
     */
    @Test
    fun a_corrupted_invite_is_not_echoed_even_though_it_is_not_valid_json() {
        val lines = ScanFailureReport.describe(
            truncatedInvite,
            androidStyleTokenizerError(truncatedInvite)
        ).joinToString("\n")
        assertFalse(lines.contains(token))
        assertFalse(
            "no fragment of the payload may be echoed once it looks like an invite",
            lines.contains("192.168.1.50")
        )
        assertTrue(lines.contains("not echoed here"))
    }

    /**
     * And the case the echo exists for, which must keep working.
     *
     * Scanning the installer's download QR is a real mistake with a real
     * symptom, and "starts with https://" is what tells it apart from a schema
     * problem. Removing the echo entirely would have been safe and useless.
     */
    @Test
    fun a_scanned_download_url_is_still_echoed_because_it_holds_no_secret() {
        val url = "https://github.com/BaxtersLab/RemoteDexter"
        val lines = ScanFailureReport.describe(url, JSONException("not a JSON object"))
            .joinToString("\n")
        assertTrue("the diagnostic must survive: $lines", lines.contains(url))
    }

    @Test
    fun valid_json_logs_key_names_and_never_values() {
        val payload = """{"port":8082,"session_token":"$token","lan_ip":"192.168.1.50"}"""
        val lines = ScanFailureReport.describe(payload, IllegalStateException("boom"))
            .joinToString("\n")
        assertTrue(lines.contains("session_token"))   // the KEY
        assertFalse(lines.contains(token))            // never the VALUE
        assertFalse(lines.contains("192.168.1.50"))
    }

    /**
     * This app's own decode messages are built from field names and the
     * payload's `kind`, so they may be shown — but `kind` is attacker-supplied
     * text of unbounded length, so it is clipped.
     */
    @Test
    fun our_own_decode_messages_pass_through_but_are_bounded() {
        val short = InviteDecodeException(FailureReason.InviteParse, "pairing code is missing port")
        assertEquals("pairing code is missing port", ScanFailureReport.userDetail(short))

        val long = InviteDecodeException(FailureReason.QrNotPairingCode, "x".repeat(500))
        val detail = ScanFailureReport.userDetail(long)
        assertTrue(detail.length <= ScanFailureReport.MAX_ECHO + 1)
        assertTrue(detail.endsWith("…"))
    }

    /**
     * Both spellings, because this runs on text of unknown provenance: the
     * client calls it `session_token` and the host calls it `token`, and
     * assuming one schema is how the other gets missed.
     */
    @Test
    fun both_the_host_and_client_names_for_the_credential_are_recognised() {
        assertTrue(ScanFailureReport.mayCarrySecret("""{"token":"abc"""))
        assertTrue(ScanFailureReport.mayCarrySecret("""{"session_token":"abc"""))
        assertTrue(ScanFailureReport.mayCarrySecret("""{"SESSION_TOKEN":"abc"""))
        assertTrue(ScanFailureReport.mayCarrySecret("""{"signature":"abc"""))
        assertTrue(ScanFailureReport.mayCarrySecret("""{"host_pubkey":"abc"""))
        assertFalse(ScanFailureReport.mayCarrySecret("https://github.com/BaxtersLab/RemoteDexter"))
    }
}
