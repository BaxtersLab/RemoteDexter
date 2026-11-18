package com.remotedexter

/**
 * Text sent to the host and not yet answered for, by id (RD-TEXT-1).
 *
 * # Why the phone keeps a copy
 *
 * The compose field clears the moment a paragraph is queued, which is right:
 * the next thing typed must not be appended to text already on its way. But
 * the host can still refuse the run — a character it cannot type, a lock screen
 * that came up, a grant withdrawn half-way through — and its answer arrives
 * after the field is empty. Without a copy, that answer could only say what
 * was LOST. With one, the untyped part goes back into the field.
 *
 * Each text command carries a `text_id`; the host echoes it, with how many
 * characters it typed, in whatever reply it gives that run. An `ack` settles
 * the entry; a refusal hands back the part that did not reach the desktop.
 *
 * # Bounded
 *
 * A host that predates `text_id` never echoes one, so nothing would ever be
 * settled. The ledger holds at most [capacity] entries and drops the oldest:
 * against an old host it degrades to "no restore", never to a leak.
 *
 * The text itself is held only here and only until answered. It is never
 * logged: it is whatever the operator typed, passwords included.
 */
class PendingTexts(private val capacity: Int = DEFAULT_CAPACITY) {

    init {
        require(capacity > 0) { "a ledger that holds nothing restores nothing" }
    }

    /** What a refused or interrupted run gives back to the compose field. */
    data class Returned(
        /** The part of the composed text that did not reach the host. */
        val untyped: String,
        /** Characters of the composed text that did. */
        val typed: Int,
        /** Characters in the text as composed, without the Enter Go adds. */
        val composed: Int,
        /** The character the host said it could not type, when it said. */
        val untypable: String?
    )

    private var nextId = 1L
    private val inFlight = LinkedHashMap<Long, String>()

    /** Hold [composed] — the field's text, without Go's Enter — and name it. */
    @Synchronized
    fun register(composed: String): Long {
        while (inFlight.size >= capacity) {
            inFlight.remove(inFlight.keys.first())
        }
        val id = nextId++
        inFlight[id] = composed
        return id
    }

    /** The run never left the phone: there is nothing to wait for. */
    @Synchronized
    fun forget(id: Long) {
        inFlight.remove(id)
    }

    /** The host typed all of it. True if [id] was being held. */
    @Synchronized
    fun settle(id: Long): Boolean = inFlight.remove(id) != null

    /**
     * The host refused or stopped run [id] after [typed] characters.
     *
     * [at] is the position of a character the host could not type, counted in
     * characters of the text it received; the phone names the character from
     * its own copy, so the host never has to echo user text.
     *
     * Null when [id] is unknown — already answered, or evicted — because then
     * there is nothing truthful to restore.
     */
    @Synchronized
    fun refused(id: Long, typed: Int, at: Int?): Returned? {
        val text = inFlight.remove(id) ?: return null
        val composed = KeyboardInput.characterCount(text)
        val done = typed.coerceIn(0, composed)
        val untyped = text.substring(text.offsetByCodePoints(0, done))
        val untypable = at?.takeIf { it in 0 until composed }?.let {
            String(Character.toChars(text.codePointAt(text.offsetByCodePoints(0, it))))
        }
        return Returned(untyped, done, composed, untypable)
    }

    /** The session ended: no answer for any of these is coming. */
    @Synchronized
    fun clear() {
        inFlight.clear()
    }

    /** Entries held — for tests. */
    @Synchronized
    fun size(): Int = inFlight.size

    companion object {
        /** Far more than anyone has in flight; small enough to be no cost. */
        const val DEFAULT_CAPACITY = 16
    }
}

/**
 * What the compose bar should say about returned text, decided without Android
 * types so every case can be asserted on the JVM. The activity turns each
 * [Kind] into its string resource.
 */
object TextReturn {

    /**
     * Host reasons that are about the TEXT a run carried, not about who may
     * type. The host keeps the grant for these. Pinned against the host by
     * `limits.text_content_refusals` in the shared contract.
     */
    val ABOUT_THE_TEXT: Set<String> = setOf("unsupported_character", "text_too_long")

    sealed class Kind {
        /** Nothing typed: the host cannot type [label]. */
        data class Untypable(val label: String) : Kind()

        /** Nothing typed: over the host's ceiling, [max] when it said. */
        data class TooLong(val max: Int?) : Kind()

        /** [typed] of [composed] characters went in before [reason]. */
        data class StoppedPartway(val typed: Int, val composed: Int, val reason: String) : Kind()

        /** All the text went in, but Go's Enter did not. */
        data class EnterNotPressed(val reason: String) : Kind()

        /** Nothing typed, for [reason] — usually control or the lock screen. */
        data class NotTyped(val reason: String) : Kind()
    }

    fun kind(reason: String, returned: PendingTexts.Returned, max: Int?): Kind = when {
        returned.untypable != null -> Kind.Untypable(label(returned.untypable))
        reason == "text_too_long" -> Kind.TooLong(max)
        returned.typed > 0 && returned.untyped.isEmpty() -> Kind.EnterNotPressed(reason)
        returned.typed > 0 -> Kind.StoppedPartway(returned.typed, returned.composed, reason)
        else -> Kind.NotTyped(reason)
    }

    /**
     * A character as the operator can recognise it. An invisible one — a
     * control character, a non-breaking space — gets its code point instead,
     * because quotation marks around nothing tell nobody anything.
     */
    fun label(ch: String): String {
        val cp = ch.codePointAt(0)
        val code = "U+%04X".format(cp)
        val invisible = Character.isISOControl(cp) || Character.isSpaceChar(cp) ||
            Character.getType(cp) == Character.FORMAT.toInt()
        return if (invisible) code else "“$ch” ($code)"
    }
}
