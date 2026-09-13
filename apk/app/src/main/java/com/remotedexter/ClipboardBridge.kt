package com.remotedexter

/**
 * Moving text between the phone's clipboard and the host's.
 *
 * ## What this is not
 *
 * Not a mirror. There is no background sync, no watcher, and nothing happens
 * because a clipboard changed. **Every transfer is one the operator pressed a
 * button for**, in both directions. A clipboard that copies itself between two
 * machines is a channel that moves a password off one of them because it
 * happened to be copied, with nobody having asked — and on Android it would not
 * work anyway, since an app in the background cannot read the clipboard at all.
 * The safe design and the possible one are the same design here.
 *
 * ## Not the same as Ctrl+C and Ctrl+V
 *
 * [KeyChord] presses keys ON THE HOST: copy in one host window, paste into
 * another. This carries text ACROSS, between two machines' clipboards. Both are
 * wanted and they are not substitutes — the operator asked for the chords back
 * first, then for this.
 *
 * ## Text never reaches a log
 *
 * No function here logs content, and neither does its caller. Sizes and
 * refusals only. A clipboard is where passwords are.
 */
object ClipboardBridge {

    /**
     * The largest text the client will offer, in UTF-8 bytes.
     *
     * Matches `host_app::clipboard::MAX_TEXT_BYTES`. The host validates
     * independently and is the authority — this is here so an oversized
     * clipboard is refused on the phone, where the user can be told, rather
     * than after a round trip that ends in a denial they cannot act on.
     */
    const val MAX_TEXT_BYTES = 8192

    sealed class Action {
        /** Send this text to the host's clipboard. */
        data class Push(val text: String) : Action()

        /** Ask the host for its clipboard. */
        object Pull : Action()

        /** Refused, with a reason worth showing. */
        data class Drop(val why: Reason) : Action()
    }

    /**
     * Why a transfer did not happen.
     *
     * Distinct cases because they need different things from the user: one
     * wants control granted, one wants a connection, one wants them to copy
     * something first, and one wants a smaller selection.
     */
    enum class Reason {
        NoControl,
        NoSession,
        NothingToSend,
        TooLarge
    }

    /**
     * Whether the phone's clipboard may be sent to the host.
     *
     * **Gated by [InputEmissionPolicy.mayEmit]** — the same rule the pointer,
     * the keyboard and the chords go through. Writing the host's clipboard is
     * writing to the host, and a phone that could do it while control was off
     * would be putting text into a machine it was only supposed to be watching.
     */
    fun push(controlEnabled: Boolean, windowId: Long, text: String?): Action {
        if (!InputEmissionPolicy.mayEmit(controlEnabled, windowId)) {
            return Action.Drop(
                if (!controlEnabled) Reason.NoControl else Reason.NoSession
            )
        }
        if (text.isNullOrEmpty()) return Action.Drop(Reason.NothingToSend)
        if (text.toByteArray(Charsets.UTF_8).size > MAX_TEXT_BYTES) {
            return Action.Drop(Reason.TooLarge)
        }
        return Action.Push(text)
    }

    /**
     * Whether the host's clipboard may be read.
     *
     * The same grant, and that is a deliberate choice rather than symmetry for
     * its own sake. **Reading the host's clipboard is not viewing.** The
     * clipboard holds what was copied, which is very often something that was
     * never on the screen — so a peer with only a view would be taking data the
     * view never showed them.
     */
    fun pull(controlEnabled: Boolean, windowId: Long): Action {
        if (!InputEmissionPolicy.mayEmit(controlEnabled, windowId)) {
            return Action.Drop(
                if (!controlEnabled) Reason.NoControl else Reason.NoSession
            )
        }
        return Action.Pull
    }

    /** What to do with a `clipboard` reply from the host. */
    sealed class Incoming {
        /** Put this on the phone's clipboard. */
        data class Replace(val text: String) : Incoming()

        /** The host's clipboard is empty; clear the phone's to match. */
        object Clear : Incoming()

        /** The message had no text field at all. Not an empty clipboard. */
        object Malformed : Incoming()
    }

    /**
     * What arrived from the host.
     *
     * ## Why an empty reply may now clear the phone's clipboard
     *
     * The first version refused to: an empty result would have been allowed to
     * wipe what the operator had copied on their phone, and at the time
     * **empty was not trustworthy**. `read_host_clipboard` returned `Ok("")` for
     * every non-zero exit of `wl-paste` — nothing copied, a clipboard holding an
     * image, and a genuine tool failure were one value. Overwriting on that
     * would have let a failure destroy the operator's clipboard.
     *
     * The host now tells the three apart, so an empty reply means the host's
     * clipboard really is empty and matching it is the honest thing to do. The
     * operator asked for the overwrite; what made it safe was fixing the layer
     * underneath, not relaxing the check here.
     *
     * An **absent** text field is still not an empty clipboard — it is a
     * message that did not say — so it changes nothing.
     */
    fun receive(text: String?): Incoming = when {
        text == null -> Incoming.Malformed
        text.isEmpty() -> Incoming.Clear
        else -> Incoming.Replace(text)
    }
}
