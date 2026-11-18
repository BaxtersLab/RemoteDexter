package com.remotedexter

import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The host's pairing QR, scanned by the decoder the phone actually uses.
 *
 * The host does not always draw the QR library's own encoding: where one
 * byte-mode segment makes a smaller code, it draws that instead (the library's
 * segment optimizer had put some invites a whole version or more too large). A
 * smaller code the phone cannot read would be a regression that no host test
 * could see, so `contract/qr_modules_v1.json` carries the exact module grids the
 * host draws, and this test renders each one as a camera frame would see it —
 * quiet zone included — and reads it with ZXing's `QRCodeReader`, the reader
 * behind the app's scan screen.
 *
 * The Rust half (`crates/pairing/tests/qr_vectors.rs`) proves the fixture is
 * exactly what the host draws. Neither side imports the other.
 */
class QrModulesTest {

    private val fixture by lazy {
        JSONObject(java.io.File("../../contract/qr_modules_v1.json").readText())
    }

    private fun cases(): List<JSONObject> {
        val arr = fixture.getJSONArray("cases")
        return (0 until arr.length()).map { arr.getJSONObject(it) }
    }

    /** The grid as greyscale pixels, with a 4-module quiet zone, [scale] px per module. */
    private fun render(rows: List<String>, scale: Int): Triple<Int, Int, IntArray> {
        val quiet = 4
        val side = (rows.size + 2 * quiet) * scale
        val white = 0xFFFFFFFF.toInt()
        val black = 0xFF000000.toInt()
        val px = IntArray(side * side) { white }
        rows.forEachIndexed { y, row ->
            row.forEachIndexed { x, c ->
                if (c == '1') {
                    for (dy in 0 until scale) for (dx in 0 until scale) {
                        px[((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx] = black
                    }
                }
            }
        }
        return Triple(side, side, px)
    }

    @Test
    fun every_grid_the_host_draws_scans_back_to_its_text() {
        val all = cases()
        assertTrue("the fixture has no cases", all.isNotEmpty())
        for (case in all) {
            val name = case.getString("name")
            val rowsJson = case.getJSONArray("rows")
            val rows = (0 until rowsJson.length()).map { rowsJson.getString(it) }
            assertEquals("$name: symbol_size", case.getInt("symbol_size"), rows.size)
            // 4 px/module: the host shows ~4.2-4.5 at its 440 px render.
            val (w, h, px) = render(rows, scale = 4)
            val bitmap = BinaryBitmap(HybridBinarizer(RGBLuminanceSource(w, h, px)))
            val text = QRCodeReader().decode(bitmap).text
            assertEquals("$name: ZXing read something else", case.getString("text"), text)
        }
    }

    /** A fixture with only one encoding would prove nothing about the other. */
    @Test
    fun the_fixture_covers_both_encodings_the_host_can_draw() {
        val paths = cases().map { it.getString("path") }.toSet()
        assertEquals(setOf("byte", "mixed"), paths)
    }
}
