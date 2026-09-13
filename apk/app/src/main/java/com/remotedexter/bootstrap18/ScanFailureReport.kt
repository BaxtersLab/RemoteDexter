package com.remotedexter.bootstrap18

/**
 * Turns a failed pairing scan into text that is safe to write into a log the
 * user is invited to copy out of the app and send to somebody.
 *
 * WHY THIS EXISTS, precisely. `RdxLog` keeps an in-memory buffer that
 * `DiagnosticsActivity` shows and the user can share, so anything logged on
 * this path is not merely a logcat line — it is a document with a destination.
 * The invite carries `token`, a one-use bearer credential, so a working token
 * must never reach it.
 *
 * The specific defect this replaces: the scan path logged, toasted and stored
 * `e.message` from whatever exception the parse threw. **Android's `org.json`
 * appends the ENTIRE input to its tokenizer errors** — `JSONTokener.toString()`
 * returns `" at character N of " + in` — so a QR read with one bit wrong, which
 * is an ordinary event and the reason people re-scan, produces
 * `JSONException: Unterminated string at character 105 of {…"token":"<a real
 * token>"…}`. That message went into the shareable buffer, into a Toast, and
 * into `SessionState.Failed`.
 *
 * Note for anyone tempted to prove this against the platform: **the JVM
 * `org.json` used by unit tests does NOT do that.** Its `syntaxError` appends
 * only a position. A test that fed real malformed JSON to the real parser and
 * then checked the log would pass on the desktop and prove nothing about the
 * device. So the tests here hand the redactor a message that already contains a
 * token and require it not to come out — a property that holds whatever the
 * platform's parser writes.
 */
object ScanFailureReport {

    /** Longest payload-derived fragment allowed into any output. */
    const val MAX_ECHO = 60

    /**
     * Key names whose presence means the text is, or is trying to be, an
     * invite — and therefore may carry a credential somewhere inside it.
     *
     * `session_token` is the client-side name and `token` the host-side one;
     * both are listed because this runs on text of unknown provenance, which is
     * exactly when assuming one schema is how something gets missed.
     */
    private val SECRET_BEARING_KEYS =
        listOf("session_token", "token", "signature", "host_pubkey", "host_identity_pubkey")

    /**
     * True if `text` looks like it could contain invite material.
     *
     * Deliberately a substring test and not a parse: this is asked about text
     * that has ALREADY failed to parse, so anything structural is unavailable,
     * and the safe reading of "I cannot tell what this is" is "assume it has a
     * secret in it".
     */
    fun mayCarrySecret(text: String): Boolean {
        val lower = text.lowercase()
        return SECRET_BEARING_KEYS.any { lower.contains(it) }
    }

    /**
     * The user-facing detail for a Toast or [com.remotedexter.SessionState].
     *
     * [InviteDecodeException] messages are built by this app from FIELD NAMES
     * plus the payload's `kind` and `version` — never from a credential — so
     * they pass through, bounded, because they are the half of this that
     * actually helps somebody fix their problem. Every other exception is
     * reduced to its class name: the message came from a parser and may quote
     * the input.
     */
    fun userDetail(e: Exception): String = when (e) {
        is InviteDecodeException -> clip(e.message ?: "unparseable")
        else -> "unreadable pairing code (${e.javaClass.simpleName})"
    }

    /**
     * The lines to log for a scan that could not be used.
     *
     * Returned as a list rather than logged here so the decision is testable
     * without a logger, an Android runtime or a captured stream.
     */
    fun describe(contents: String, e: Exception): List<String> {
        val lines = mutableListOf<String>()
        lines += "invite rejected: ${e.javaClass.simpleName}: ${userDetail(e)}"

        val keys = jsonKeys(contents)
        if (keys != null) {
            // Valid JSON: key NAMES are the whole diagnostic signal, because a
            // schema mismatch shows up as a missing or renamed key, and no key
            // name is a secret.
            lines += "payload parsed as JSON; keys present = $keys"
            lines += "required by this build: port, session_token " +
                "(address may be lan_ip or host_ip)"
            return lines
        }

        // Not parseable as JSON. The old code logged a 60-character prefix here
        // and justified it with "not JSON, so it holds no token". That is the
        // wrong way round: a TRUNCATED OR CORRUPTED INVITE is not valid JSON
        // and still contains the token in full. The prefix is only logged when
        // the text carries no invite key at all — which is the case the prefix
        // exists to serve, telling "scanned the download QR" (a bare URL) apart
        // from a schema problem.
        lines += if (mayCarrySecret(contents)) {
            "payload is not valid JSON but contains pairing-invite fields — " +
                "not echoed here, because a corrupted invite still holds a live " +
                "token. ${contents.length} chars. This usually means a partial " +
                "or misread scan: try again."
        } else {
            "payload is not JSON — starts with: \"${clip(contents)}\". " +
                "A bare URL here means an installer/download QR was scanned " +
                "instead of a pairing invite."
        }
        return lines
    }

    /** Sorted key names, or null if `text` is not a JSON object. */
    private fun jsonKeys(text: String): List<String>? = try {
        org.json.JSONObject(text).keys().asSequence().toList().sorted()
    } catch (_: Exception) {
        null
    }

    /**
     * Bound a fragment and mark it when it was cut.
     *
     * Applied to this app's own exception messages too: `WrongKind` echoes the
     * payload's `kind`, which is attacker-supplied text of unbounded length.
     */
    private fun clip(s: String): String =
        if (s.length <= MAX_ECHO) s else s.take(MAX_ECHO) + "…"
}
