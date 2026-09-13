package com.remotedexter

/**
 * The controls on the session toolbar, as values rather than view ids.
 *
 * They are named here so the rule deciding whether each one is pressable can be
 * written once, tested exhaustively, and read without an emulator. `R.id` is
 * deliberately absent: a unit test sees every generated resource id as 0, so a
 * rule keyed on them would be untestable off-device — which is how the rule
 * ended up scattered through `MainActivity` in the first place.
 */
enum class ToolbarAction {
    /** Touch versus trackpad. A preference about how a finger drives the cursor. */
    PointerMode,

    /** Show the compose bar and the soft keyboard. */
    Keyboard,

    /** Scan a host's QR code. */
    Pair,

    /** Open the diagnostics screen. */
    Diagnostics
}

/**
 * Which toolbar controls are pressable in a given session state.
 *
 * ## Why this became a table
 *
 * The rules lived as single lines in `MainActivity.renderSessionState`, which
 * is the one place they could not be tested. That was survivable while every
 * button carried a word: a labelled button that refuses is at least a button
 * you can read. **The icon toolbar removes the words**, so a control's state is
 * carried entirely by whether it looks dim — and a dim icon that should have
 * been live, or a live icon that does nothing, is now indistinguishable from a
 * drawing mistake.
 *
 * So the table is exhaustive on purpose. Adding a [SessionState] variant or a
 * [ToolbarAction] is a compile error here until someone says what it means,
 * rather than a control that silently inherits whatever the `else` branch said.
 */
object ToolbarAvailability {

    /**
     * True when [action] may be pressed while the session is in [state].
     *
     * Note what this does NOT decide: whether the action will succeed. Keyboard
     * is pressable while streaming even with control off, because the refusal
     * ("Press Enable Control before typing") is worth more than a dead button —
     * it names the remedy, and the remedy belongs to the user. Availability is
     * about whether the control has any job in this state at all.
     */
    fun isEnabled(action: ToolbarAction, state: SessionState): Boolean = when (action) {
        // A preference, not a session action. Set it before connecting if you
        // like; it changes how the next touch is interpreted and nothing else.
        ToolbarAction.PointerMode -> true

        // Typing needs somewhere for the text to go.
        ToolbarAction.Keyboard -> state is SessionState.Streaming

        // NOTE: Screenshot is deliberately absent. It was here for one day
        // and never worked in any form: rd_request_screenshot falls through an
        // `if let Some(transport)` that is never Some, because the engine's
        // transport has one writer and that writer has no callers anywhere in
        // the tree. Print Screen is now a real keystroke on the chord row,
        // where the host takes the capture itself.

        // Pairing stays reachable in every state, including a live one. It is
        // how a session is established, and an IdentityMismatch — the state
        // where re-pairing is most likely to be what the user wants — must not
        // be a dead end.
        ToolbarAction.Pair -> true

        // Diagnostics is most needed exactly when something is wrong.
        ToolbarAction.Diagnostics -> true
    }
}
