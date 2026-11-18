package com.remotedexter

import org.json.JSONObject

enum class PointerCoordinateSpace { DESKTOP_PIXELS, NORMALIZED_V1 }

data class PointerPosition(val x: Int, val y: Int, val space: PointerCoordinateSpace)

/**
 * Builds the Agent2 `input_event` commands this client sends to the host.
 *
 * Split out of [InputController] for one reason: **it is the seam between two
 * languages, and nothing else in the build checks both sides of it.** The host
 * parses these strings with `serde_json::from_value::<InputControlMessage>`
 * (`host_app/src/main.rs`), against an enum defined in
 * `module10/src/message.rs`. A field renamed on either side compiles perfectly
 * on both and fails only at runtime, on a device, as "control does nothing".
 *
 * The exact strings produced here are pinned by
 * `contract/android_input_wire_v1.json`, which the Kotlin tests and a Rust test
 * in `module10/tests/android_wire_contract.rs` both assert against. Either side
 * drifting turns that side's suite red.
 *
 * ### Shape rules that are easy to get wrong
 *
 * * `InputControlMessage` is an **externally tagged** serde enum: the variant
 *   name is the sole key and its fields are the value object.
 * * **Every field must be present**, including ones the mode ignores.
 *   `MouseMove` in `Relative` mode still requires `abs_x`/`abs_y` — serde has no
 *   default for them and rejects the object outright if they are missing.
 * * Without a `coordinate_space` marker, `abs_x`/`abs_y` are host desktop pixels.
 *   Negotiated `normalized_v1` positions span 0..65535 across the shared surface.
 * * Buttons are **0 = left, 1 = right, 2 = middle**; anything else is
 *   `Malformed` host-side.
 */
object InputJson {

    fun streamStart(windowId: Long): String =
        """{"type":"stream_start","window":$windowId,"input_coordinates":"normalized_v1"}"""

    fun acknowledgedCoordinates(ack: JSONObject): PointerCoordinateSpace? =
        if (!ack.has("input_coordinates")) {
            PointerCoordinateSpace.DESKTOP_PIXELS
        } else if (ack.opt("input_coordinates") == "normalized_v1") {
            PointerCoordinateSpace.NORMALIZED_V1
        } else {
            null
        }

    /** A relative ("trackpad") cursor delta. */
    fun moveRelative(windowId: Long, dx: Int, dy: Int): String =
        """{"type":"input_event","window":$windowId,"event":{"MouseMove":{"mode":"Relative","dx":$dx,"dy":$dy,"abs_x":0,"abs_y":0}}}"""

    /**
     * An absolute cursor position in [space]. The default preserves the legacy wire contract.
     *
     * This is what the cursor-offset feature sends: the client works out which
     * desktop pixel the user means — fingertip, lifted by the slider's offset,
     * inverted through the exact rectangle the frame was drawn into — and names
     * it. With normalized_v1, the host converts 0..65535 surface coordinates to
     * native pixels before its ordinary authorization and injection.
     *
     * `dx`/`dy` are still present and still zero. They are meaningless in
     * `Absolute` mode and serde still rejects the object without them.
     *
     * [absX]/[absY] must already be clamped to the selected coordinate space: they land in a `u32`
     * host-side, so a negative value is not merely wrong, it fails to parse.
     * `DesktopCoordinateMapper` is what guarantees that, and
     * `mouse_move_absolute_negative_coordinate` in the shared fixture is what
     * proves the host would refuse it.
     */
    fun moveAbsolute(
        windowId: Long,
        absX: Int,
        absY: Int,
        space: PointerCoordinateSpace = PointerCoordinateSpace.DESKTOP_PIXELS
    ): String {
        val marker = when (space) {
            PointerCoordinateSpace.DESKTOP_PIXELS -> ""
            PointerCoordinateSpace.NORMALIZED_V1 -> ""","coordinate_space":"normalized_v1""""
        }
        return """{"type":"input_event","window":$windowId$marker,"event":{"MouseMove":{"mode":"Absolute","dx":0,"dy":0,"abs_x":$absX,"abs_y":$absY}}}"""
    }

    /** A mouse button transition. [action] is exactly "Down" or "Up". */
    fun button(windowId: Long, button: Int, action: String): String =
        """{"type":"input_event","window":$windowId,"event":{"MouseButton":{"button":$button,"action":"$action"}}}"""

    /** Ask the host for the input-control grant. */
    /**
     * Type a run of text on the host.
     *
     * Sends TEXT, not scan codes, and that is deliberate. A scan code names a
     * physical key position; which character that position produces depends on
     * the keyboard layout in force on the HOST. The phone cannot know it — an
     * IME produces characters — so the mapping lives host-side in
     * `module10::keymap` and the wire carries what the user actually typed.
     *
     * Built with a real JSON encoder rather than string interpolation like the
     * builders above. Those interpolate numbers, which cannot contain a quote;
     * this carries arbitrary user text, and a password containing `"` or `\`
     * would otherwise produce malformed JSON that the host refuses — a bug that
     * appears only for the users with the strongest passwords.
     *
     * [textId] names the run so the host's answer can be matched to it
     * (RD-TEXT-1): the host echoes it, with how many characters it typed, and
     * [PendingTexts] puts a refused paragraph back in the compose field. A host
     * that predates it ignores the field.
     */
    fun text(windowId: Long, text: String, textId: Long): String {
        val event = JSONObject().put("TextInput", JSONObject().put("text", text))
        return JSONObject()
            .put("type", "input_event")
            .put("window", windowId)
            .put("text_id", textId)
            .put("event", event)
            .toString()
    }

    /** What the host said about one text run, when its reply names the run. */
    data class TextReply(val id: Long, val typed: Int, val at: Int?, val max: Int?)

    /**
     * Read a host reply's text-run fields, or null for a reply about anything
     * else — a pointer move's ack, or any reply from a host that predates
     * `text_id`. A malformed id is treated as absent: guessing which run it
     * meant could restore the wrong text.
     */
    fun textReply(reply: JSONObject): TextReply? {
        // Strict: an integer, not a string `optLong` would happily coerce. The
        // host sends a number; anything else is not a reply this phone wrote.
        val id = when (val raw = reply.opt("text_id")) {
            is Int -> raw.toLong()
            is Long -> raw
            else -> return null
        }
        if (id <= 0L) return null
        val typed = reply.optInt("typed", 0).coerceAtLeast(0)
        val at = if (reply.has("at")) reply.optInt("at", -1).takeIf { it >= 0 } else null
        val max = if (reply.has("max")) reply.optInt("max", -1).takeIf { it > 0 } else null
        return TextReply(id, typed, at, max)
    }

    /**
     * One key press or release, by physical position.
     *
     * For the keys a text stream cannot express: Backspace does not appear in
     * an IME's text at all (deleting produces no character), and neither do the
     * arrows. Characters go through [text]; this is for the rest.
     *
     * `scanCode` is a **Set 1** code, which is what the host's
     * `set1_to_evdev` expects — not an Android keycode and not an evdev code.
     */
    fun key(windowId: Long, scanCode: Int, action: String, modifiers: Int): String =
        """{"type":"input_event","window":$windowId,"event":{"KeyEvent":{"scan_code":$scanCode,"action":"$action","modifiers":$modifiers}}}"""

    /**
     * A wheel scroll, in whole notches.
     *
     * `Lines` rather than `Pixels`: the host reads `Lines` as detents and
     * multiplies up to hi-res itself, and a detent is what a two-finger swipe
     * has actually decided on by the time it gets here. Sending pixels would
     * mean inventing a hi-res figure from a gesture that was already quantised,
     * which is a precision this path does not have.
     *
     * The message type has existed since Block 7 and the host has always
     * handled it. This builder is the half that was missing.
     */
    fun scroll(windowId: Long, dx: Int, dy: Int): String =
        """{"type":"input_event","window":$windowId,"event":{"MouseScroll":{"dx":$dx,"dy":$dy,"mode":"Lines"}}}"""

    /**
     * Send text to the host's clipboard.
     *
     * The text is escaped by [org.json.JSONObject], not by hand. Clipboard
     * content is arbitrary text this app did not choose, which is exactly the
     * input that finds the case a hand-rolled escaper missed — and the failure
     * mode there is a malformed command reaching a machine under control.
     */
    fun clipboardPush(windowId: Long, text: String): String =
        org.json.JSONObject()
            .put("type", "clipboard_push")
            .put("window", windowId)
            .put("text", text)
            .toString()

    /** Ask the host for its clipboard. */
    fun clipboardPull(windowId: Long): String =
        """{"type":"clipboard_pull","window":$windowId}"""

    fun grantInput(): String = """{"type":"grant_input"}"""

    /** Hand the input-control grant back. */
    fun revokeInput(): String = """{"type":"revoke_input"}"""
}
