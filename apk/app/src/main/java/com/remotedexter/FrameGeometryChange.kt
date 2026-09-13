package com.remotedexter

/**
 * Whether the host's declared frame geometry just changed, and what to say
 * about it.
 *
 * Exists because of what the Windows Round-2 trip (2026-08-26) could NOT
 * determine. The host proved it captured and logged both geometries across a
 * landscape -> portrait -> landscape cycle, dropped no frames and raised no
 * fault; the phone was foreground and visible; and the picture still did not
 * follow. That leaves two very different faults indistinguishable:
 *
 * 1. the new geometry never reached the client, or
 * 2. it reached the client and the client failed to render it.
 *
 * The client emitted no frame logging at all, so neither could be shown. One
 * line at the point frames enter the client separates them, and it is the
 * difference between a transport bug and a rendering bug.
 *
 * Pure and Android-free so the rule is provable on the JVM: `Log` is called by
 * the caller, not from here.
 */
object FrameGeometryChange {

    /**
     * A message describing the change, or `null` when nothing changed.
     *
     * `null` for the first frame too — arriving at a size is not a change, and
     * logging it on every reconnect would train the reader to ignore the line.
     */
    fun message(
        previous: Pair<Int, Int>?,
        current: Pair<Int, Int>,
        sequence: Long
    ): String? = message(previous, current, sequence, viewerAttached = true)

    /**
     * As above, but stating whether a viewer was attached to receive it.
     *
     * **This distinction cost the 2026-08-26 Windows trip.** The original line
     * was logged before the "no viewer attached" return — deliberately, so that
     * a size arriving with nothing attached was still visible. What that missed
     * is that the line then proves only that the frame reached the client's
     * front door, NOT that it reached the renderer. Frames can be logged and
     * then silently discarded, and the picture freezes on the last good frame —
     * which is indistinguishable, from the log alone, from a renderer that
     * received the frame and drew it wrongly.
     *
     * Round 3 read four of these lines as proof of delivery to the renderer.
     * They were not that. They are proof of arrival only.
     */
    fun message(
        previous: Pair<Int, Int>?,
        current: Pair<Int, Int>,
        sequence: Long,
        viewerAttached: Boolean
    ): String? {
        if (previous == null || previous == current) return null
        val fate = if (viewerAttached) "queued for decode" else "DISCARDED — no viewer attached"
        return "frame $sequence: host geometry ${previous.first}x${previous.second}" +
            " -> ${current.first}x${current.second} ($fate)"
    }

    /** What the JPEG actually decoded to, which proves the pixels match the header. */
    fun decodedMessage(previous: Pair<Int, Int>?, current: Pair<Int, Int>, sequence: Long): String? {
        if (previous == null || previous == current) return null
        return "frame $sequence: DECODED ${previous.first}x${previous.second}" +
            " -> ${current.first}x${current.second}"
    }

    /**
     * What the RENDERER drew, which is the only line that proves pixels
     * changed. Logged from the pipeline on a geometry change, so a frame that
     * arrives, decodes, and is then never drawn cannot masquerade as a frame
     * that was drawn.
     */
    fun renderedMessage(previous: Pair<Int, Int>?, current: Pair<Int, Int>): String? {
        if (previous == null || previous == current) return null
        return "RENDERED geometry ${previous.first}x${previous.second}" +
            " -> ${current.first}x${current.second}"
    }
}
