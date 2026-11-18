package com.remotedexter

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

/**
 * The Kotlin half of the cross-language wire contract.
 *
 * `modules/module10/tests/android_wire_contract.rs` asserts the host's serde
 * derives accept exactly these commands. This asserts [InputJson] produces
 * them. Neither test imports the other side; the shared fixture is the contract,
 * so a rename on either side turns that side red instead of failing silently on
 * a device as "control does nothing".
 */
class InputJsonContractTest {

    @Test
    fun normalizedPointerCommandsMatchTheSharedHostContract() {
        val contract = JSONObject(File("../../contract/android_pointer_normalized_v1.json").readText())
        assertTrue(JSONObject(InputJson.streamStart(7)).similar(contract.getJSONObject("stream_start")))
        val space = InputJson.acknowledgedCoordinates(contract.getJSONObject("stream_ack"))
        assertEquals(PointerCoordinateSpace.NORMALIZED_V1, space)
        val moves = contract.getJSONArray("moves")
        for (i in 0 until moves.length()) {
            val command = moves.getJSONObject(i).getJSONObject("command")
            val axes = command.getJSONObject("event").getJSONObject("MouseMove")
            val produced = InputJson.moveAbsolute(
                command.getLong("window"), axes.getInt("abs_x"), axes.getInt("abs_y"),
                space!!
            )
            assertTrue("normalized command $i", JSONObject(produced).similar(command))
        }
    }

    @Test
    fun missingAcknowledgementUsesLegacyPixelsButMalformedModesAreRefused() {
        assertEquals(
            PointerCoordinateSpace.DESKTOP_PIXELS,
            InputJson.acknowledgedCoordinates(JSONObject("""{"type":"ack","for":"stream_start"}"""))
        )
        for (value in listOf(JSONObject.NULL, 1, true, "unknown", JSONObject(), listOf("normalized_v1"))) {
            assertNull(InputJson.acknowledgedCoordinates(JSONObject().put("input_coordinates", value)))
        }
    }

    @Test
    fun mappedCoordinateSpaceSurvivesUntilSerialization() {
        val normalized = PointerPosition(49151, 49151, PointerCoordinateSpace.NORMALIZED_V1)
        val legacy = PointerPosition(1439, 809, PointerCoordinateSpace.DESKTOP_PIXELS)
        for (point in listOf(normalized, legacy, normalized)) {
            val command = JSONObject(InputJson.moveAbsolute(7, point.x, point.y, point.space))
            assertEquals(
                point.space == PointerCoordinateSpace.NORMALIZED_V1,
                command.has("coordinate_space")
            )
            assertEquals(point.x, command.getJSONObject("event").getJSONObject("MouseMove").getInt("abs_x"))
        }
    }

    private fun contract(): JSONObject {
        // Gradle runs unit tests with the module directory (apk/app) as cwd.
        val f = File("../../contract/android_input_wire_v1.json")
        assertTrue(
            "shared contract not found at ${f.absolutePath} — the Rust side reads the same file",
            f.isFile
        )
        return JSONObject(f.readText())
    }

    @Test
    fun inputJsonProducesExactlyTheContractedCommands() {
        val cases = contract().getJSONArray("valid")
        assertTrue("fixture has no valid cases — a vacuous pass", cases.length() > 0)

        for (i in 0 until cases.length()) {
            val case = cases.getJSONObject(i)
            val name = case.getString("name")
            val window = case.getLong("window")
            val args = case.getJSONArray("args")

            val produced = when (val builder = case.getString("builder")) {
                "moveRelative" ->
                    InputJson.moveRelative(window, args.getInt(0), args.getInt(1))
                "moveAbsolute" ->
                    InputJson.moveAbsolute(window, args.getInt(0), args.getInt(1))
                "button" ->
                    InputJson.button(window, args.getInt(0), args.getString(1))
                "text" ->
                    InputJson.text(window, args.getString(0), args.getLong(1))
                "key" ->
                    InputJson.key(window, args.getInt(0), args.getString(1), args.getInt(2))
                "scroll" ->
                    InputJson.scroll(window, args.getInt(0), args.getInt(1))
                else -> throw AssertionError("$name: unknown builder '$builder'")
            }

            // Structural comparison, so the test pins the shape rather than the
            // key order — key order is not part of the contract, the shape is.
            assertTrue(
                "$name: InputJson emitted\n  $produced\nbut the contract says\n  ${case.getJSONObject("command")}",
                JSONObject(produced).similar(case.getJSONObject("command"))
            )
        }
    }

    @Test
    fun relativeMovesStillCarryTheAbsFieldsTheHostDemands() {
        // The single most likely drift: abs_x/abs_y look ignorable in Relative
        // mode, but serde has no default for them and rejects the whole object.
        // The Rust suite has this as a negative control; this is the same rule
        // asserted from the producing side.
        val event = JSONObject(InputJson.moveRelative(1L, 5, 5))
            .getJSONObject("event")
            .getJSONObject("MouseMove")
        assertTrue("abs_x dropped from a Relative move", event.has("abs_x"))
        assertTrue("abs_y dropped from a Relative move", event.has("abs_y"))
    }

    @Test
    fun theDesktopSurfaceIdSurvivesAsALong() {
        // i64::MAX. A u64 sentinel here round-tripped through Android's signed
        // optLong as -1 and broke streaming entirely once already.
        val json = JSONObject(InputJson.moveRelative(Long.MAX_VALUE, 1, 0))
        assertEquals(Long.MAX_VALUE, json.getLong("window"))
    }

    // ── RD-TEXT-1: the paragraph limits, pinned from the phone's side ────────

    /** The phone refuses locally by the same number the host enforces. */
    @Test
    fun thePhonesTextCeilingIsTheContractedOne() {
        val limits = contract().getJSONObject("limits")
        assertEquals(limits.getInt("max_text_chars"), KeyboardInput.MAX_TEXT_CHARS)
    }

    /**
     * The phone measures its command against the envelope the native client
     * frames input in. The host's suite pins the same number against
     * `wire::Kind::InputV1`; a mismatch would let the phone clear its field
     * for a command the client then drops.
     */
    @Test
    fun thePhonesByteCeilingIsTheContractedInputEnvelope() {
        val limits = contract().getJSONObject("limits")
        assertEquals(limits.getInt("input_v1_max_payload"), KeyboardInput.MAX_INPUT_COMMAND_BYTES)
    }

    /** The byte check measures the command the builder really produces. */
    @Test
    fun theMeasuredSizeIsTheBuiltCommandsSize() {
        val text = "say \"hi\" \\ now"
        assertEquals(
            InputJson.text(Long.MAX_VALUE, text, Long.MAX_VALUE).toByteArray(Charsets.UTF_8).size,
            KeyboardInput.encodedCommandBytes(Long.MAX_VALUE, text)
        )
    }

    /** The reasons that keep the grant are the host's own reason strings. */
    @Test
    fun theTextContentRefusalsAreTheContractedOnes() {
        val listed = contract().getJSONObject("limits").getJSONArray("text_content_refusals")
        val contracted = (0 until listed.length()).map { listed.getString(it) }.toSet()
        assertEquals(contracted, TextReturn.ABOUT_THE_TEXT)
    }

    @Test
    fun aHostTextReplyIsReadField() {
        val reply = JSONObject(
            """{"type":"error","for":"input_event","reason":"unsupported_character","text_id":9,"typed":0,"at":1900}"""
        )
        assertEquals(InputJson.TextReply(id = 9, typed = 0, at = 1900, max = null), InputJson.textReply(reply))
        val ack = JSONObject("""{"type":"ack","for":"input_event","injected":4,"text_id":3,"typed":2}""")
        assertEquals(InputJson.TextReply(id = 3, typed = 2, at = null, max = null), InputJson.textReply(ack))
    }

    /**
     * Replies that do not name a run — a pointer move's ack, any reply from a
     * host that predates text_id — and ids this phone never writes are not
     * guessed at: restoring the wrong text is worse than restoring none.
     */
    @Test
    fun aReplyThatDoesNotNameARunIsNotReadAsOne() {
        assertNull(InputJson.textReply(JSONObject("""{"type":"ack","for":"input_event","injected":1}""")))
        assertNull(InputJson.textReply(JSONObject("""{"type":"error","for":"input_event","text_id":"7"}""")))
        assertNull(InputJson.textReply(JSONObject("""{"type":"error","for":"input_event","text_id":0}""")))
        assertNull(InputJson.textReply(JSONObject("""{"type":"error","for":"input_event","text_id":-4}""")))
    }

    @Test
    fun grantAndRevokeAreBareTypedCommands() {
        assertEquals("grant_input", JSONObject(InputJson.grantInput()).getString("type"))
        assertEquals("revoke_input", JSONObject(InputJson.revokeInput()).getString("type"))
    }
}
