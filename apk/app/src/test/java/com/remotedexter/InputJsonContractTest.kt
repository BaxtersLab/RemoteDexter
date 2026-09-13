package com.remotedexter

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
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
                    InputJson.text(window, args.getString(0))
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

    @Test
    fun grantAndRevokeAreBareTypedCommands() {
        assertEquals("grant_input", JSONObject(InputJson.grantInput()).getString("type"))
        assertEquals("revoke_input", JSONObject(InputJson.revokeInput()).getString("type"))
    }
}
