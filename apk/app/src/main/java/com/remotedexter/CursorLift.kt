package com.remotedexter

import android.content.Context

/**
 * How far above the fingertip the remote cursor sits.
 *
 * A finger covers what it is pointing at. Lifting the cursor by a few
 * millimetres means the user can see the thing they are about to click, which
 * on a 6" screen showing a 1920px desktop is the difference between hitting a
 * close button and hitting the window behind it.
 *
 * # Why it moved out of the Activity
 *
 * The slider lived in the main screen's bottom row, taking a quarter of the
 * width of the row that also holds Enable Control, Connect and Disconnect —
 * space those need, and space a preference set once and rarely touched does not
 * deserve. It now lives in Settings, so this is the shared definition both
 * screens use rather than each keeping its own idea of the key and the ceiling.
 */
object CursorLift {

    /**
     * The furthest the cursor may be lifted, in dp.
     *
     * Bounded because an unbounded lift puts the cursor off-screen, where the
     * user cannot see it and every tap lands somewhere they did not look.
     *
     * 120dp is roughly two fingertip widths — far enough to see a small target
     * the finger would cover, short enough that the cursor stays on screen and
     * stays associated with the hand. Verified against the S10's own layout
     * rather than taken as given.
     */
    const val MAX_DP = 120

    /**
     * Clamp a value to the usable range.
     *
     * Pure, so the rule is tested without a device. Applied on BOTH save and
     * load: a preference file survives app upgrades and restores from backup,
     * so "we wrote it, therefore it is in range" is an assumption about a file
     * this code did not necessarily write.
     */
    fun clamp(dp: Int): Int = dp.coerceIn(0, MAX_DP)

    fun load(context: Context): Int =
        clamp(
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getInt(KEY, 0)
        )

    fun save(context: Context, dp: Int) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putInt(KEY, clamp(dp))
            .apply()
    }

    private const val PREFS = "remotedexter.ui"
    private const val KEY = "cursor_lift_dp"
}
