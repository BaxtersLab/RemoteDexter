package com.remotedexter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RD-TEXT-1: a paragraph the host refuses or stops goes back into the compose
 * field instead of being lost.
 */
class PendingTextsTest {

    private val para = "First sentence. Second sentence, with a comma. Third."

    @Test
    fun aRefusedRunGivesEverythingBack() {
        val ledger = PendingTexts()
        val id = ledger.register(para)
        assertEquals(PendingTexts.Returned(para, 0, para.length, null), ledger.refused(id, 0, null))
        assertEquals("answered once, held no longer", 0, ledger.size())
    }

    /** A run stopped part-way gives back exactly the part that did not land. */
    @Test
    fun aRunStoppedPartwayGivesBackTheRest() {
        val ledger = PendingTexts()
        val id = ledger.register(para)
        val back = ledger.refused(id, 16, null)!!
        assertEquals("Second sentence, with a comma. Third.", back.untyped)
        assertEquals(16, back.typed)
    }

    /**
     * The host counts characters, the phone's strings count UTF-16 units. An
     * emoji before the stop must not shift the split by one.
     */
    @Test
    fun theSplitIsInCharactersNotUtf16Units() {
        val ledger = PendingTexts()
        val text = "a😀bc"
        val id = ledger.register(text)
        assertEquals("bc", ledger.refused(id, 2, null)!!.untyped)
    }

    /**
     * The host names a position, never the character: the phone reads it from
     * its own copy, by characters.
     */
    @Test
    fun theUntypableCharacterIsNamedFromThePhonesCopy() {
        val ledger = PendingTexts()
        val text = "😀 café"
        val id = ledger.register(text)
        val back = ledger.refused(id, 0, 5)!!
        assertEquals("é", back.untypable)
        assertEquals(text, back.untyped)
    }

    /** A position past the composed text (Go's own Enter) names nothing. */
    @Test
    fun aPositionOutsideTheTextNamesNothing() {
        val ledger = PendingTexts()
        val id = ledger.register("abc")
        assertNull(ledger.refused(id, 0, 3)!!.untypable)
    }

    /** Typed past the composed text means only Go's Enter was missing. */
    @Test
    fun typedPastTheTextLeavesNothingToRestore() {
        val ledger = PendingTexts()
        val id = ledger.register("abc")
        val back = ledger.refused(id, 99, null)!!
        assertEquals("", back.untyped)
        assertEquals(3, back.typed)
    }

    @Test
    fun anAcknowledgedRunIsSettled() {
        val ledger = PendingTexts()
        val id = ledger.register(para)
        assertTrue(ledger.settle(id))
        assertNull("nothing to restore after an ack", ledger.refused(id, 0, null))
    }

    /** Text that never left the phone is not waited for. */
    @Test
    fun aRunThatWasNotQueuedIsForgotten() {
        val ledger = PendingTexts()
        val id = ledger.register(para)
        ledger.forget(id)
        assertEquals(0, ledger.size())
        assertFalse(ledger.settle(id))
    }

    /** An unknown id — answered, evicted, or from another session — restores nothing. */
    @Test
    fun anUnknownIdRestoresNothing() {
        assertNull(PendingTexts().refused(42, 0, null))
    }

    /**
     * A host that never echoes ids never settles anything. The ledger must
     * stay bounded, dropping the oldest.
     */
    @Test
    fun theLedgerIsBoundedAndDropsTheOldest() {
        val ledger = PendingTexts(capacity = 3)
        val ids = (1..5).map { ledger.register("run $it") }
        assertEquals(3, ledger.size())
        assertNull(ledger.refused(ids[0], 0, null))
        assertNull(ledger.refused(ids[1], 0, null))
        assertEquals("run 5", ledger.refused(ids[4], 0, null)!!.untyped)
    }

    @Test
    fun idsAreDistinctAndPositive() {
        val ledger = PendingTexts()
        val a = ledger.register("x")
        val b = ledger.register("x")
        assertTrue(a > 0 && b > a)
    }

    @Test
    fun aClearedLedgerRestoresNothing() {
        val ledger = PendingTexts()
        val id = ledger.register(para)
        ledger.clear()
        assertNull(ledger.refused(id, 0, null))
    }

    // ── What the compose bar says ─────────────────────────────────────────

    private fun returned(untyped: String, typed: Int, composed: Int, untypable: String? = null) =
        PendingTexts.Returned(untyped, typed, composed, untypable)

    @Test
    fun eachRefusalGetsItsOwnSentence() {
        assertEquals(
            TextReturn.Kind.Untypable("“é” (U+00E9)"),
            TextReturn.kind("unsupported_character", returned("café", 0, 4, "é"), null)
        )
        assertEquals(
            TextReturn.Kind.TooLong(256),
            TextReturn.kind("text_too_long", returned("x", 0, 1), 256)
        )
        assertEquals(
            TextReturn.Kind.StoppedPartway(10, 50, "host desktop is locked"),
            TextReturn.kind("host desktop is locked", returned("rest", 10, 50), null)
        )
        assertEquals(
            TextReturn.Kind.EnterNotPressed("host desktop is locked"),
            TextReturn.kind("host desktop is locked", returned("", 50, 50), null)
        )
        assertEquals(
            TextReturn.Kind.NotTyped("input not granted"),
            TextReturn.kind("input not granted", returned("all", 0, 3), null)
        )
    }

    /** An invisible character is named by its code point, not by empty quotes. */
    @Test
    fun anInvisibleCharacterIsNamedByItsCodePoint() {
        assertEquals("U+00A0", TextReturn.label(" "))
        assertEquals("U+0001", TextReturn.label("\u0001"))
        assertEquals("U+200B", TextReturn.label("​"))
        assertEquals("“😀” (U+1F600)", TextReturn.label("😀"))
    }
}
