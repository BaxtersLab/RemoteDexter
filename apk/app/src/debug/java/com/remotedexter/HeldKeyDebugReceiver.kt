package com.remotedexter

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * The debug-only trigger for [InputController.holdKey]. **Debug source set only.**
 *
 * # Why a broadcast and not a button
 *
 * Windows round 13 spent three attempts failing to hold the left mouse button
 * from the phone, and reported two facts that decide this:
 *
 *  * *"A press-and-hold on the phone is routed as a TAP"* — a sustained press
 *    needs the long-press threshold crossed and the finger kept on the surface,
 *    and `onGestureEnd` fires on every touch-up.
 *  * *"the operator cannot hold a button and type at the same time"* — any test
 *    needing held input has to be driven programmatically or sequenced so the
 *    reporting happens before the hold begins.
 *
 * Round 13's own fix for the button was to stop asking a person to hold
 * something and drive it by message instead — a watcher, then
 * `PostMessage(hwnd, WM_CLOSE)`. This is the same move for the key half. It also
 * costs the shipping UI nothing: no view is added, no layout is touched, and
 * `ControlRowFitTest`'s measurements are untouched.
 *
 * # Usage, from the Windows box
 *
 * ```
 * adb shell am broadcast -n com.remotedexter/.HeldKeyDebugReceiver \
 *     -a com.remotedexter.debug.HOLD_KEY --ei scan_code 42
 * adb shell am broadcast -n com.remotedexter/.HeldKeyDebugReceiver \
 *     -a com.remotedexter.debug.RELEASE_KEY
 * ```
 *
 * `scan_code` defaults to 42 (LeftShift). [HeldKeyPolicy.HOLDABLE] is the whole
 * accepted set and everything else is refused.
 *
 * **`-n` is required, and so is the app being open.** Measured on an API 34
 * emulator on 2026-09-08, all three cases, because guessing at broadcast
 * delivery rules is how a round gets spent on the harness instead of the
 * product:
 *
 * | receiver | addressing | delivered? |
 * |---|---|---|
 * | `exported="false"` | explicit `-n` | **no** — enqueued, never run |
 * | `exported="true"`  | action only    | **no** — API 34 drops the implicit broadcast |
 * | `exported="true"`  | explicit `-n`  | **yes** |
 *
 * A freshly installed package is also in the stopped state and receives
 * nothing until it has been launched once. In practice this never bites,
 * because the affordance is useless without a live session anyway.
 *
 * # Why it is exported, and why that is acceptable HERE ONLY
 *
 * `am broadcast` runs as the shell UID and cannot deliver to a component that is
 * not exported, so a non-exported receiver would make this unreachable by the
 * one route the test needs. Exported means any app on the phone can send it.
 *
 * What that app could achieve is bounded by the fact that this receiver decides
 * nothing: [InputController.holdKey] applies the same [InputEmissionPolicy] gate
 * every other input path applies, so a broadcast can only hold a key while the
 * user has already paired a host, started a session and tapped Enable Control —
 * and then only one of three keys whose auto-repeat is inert. It cannot grant
 * control, start a session, or reach a host.
 *
 * **None of this ships.** This file is in `src/debug/java` and its declaration
 * is in `src/debug/AndroidManifest.xml`; a release build compiles neither, and
 * the `android-exported` gate row reads the main manifest, which is what the
 * released APK is built from. The `android-exported-debug` row pins this one so
 * the debug surface cannot grow unnoticed either.
 */
class HeldKeyDebugReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        RdxLog.init(context.applicationContext)
        when (intent.action) {
            ACTION_HOLD_KEY -> {
                val scanCode = intent.getIntExtra(EXTRA_SCAN_CODE, DEFAULT_SCAN_CODE)
                val decision = InputController.holdKey(scanCode)
                RdxLog.i(TAG, "HOLD_KEY($scanCode) → $decision")
            }
            ACTION_RELEASE_KEY -> {
                val wasHeld = InputController.isHoldingKey()
                InputController.releaseHeldKeyIfHeld()
                RdxLog.i(TAG, "RELEASE_KEY → was holding: $wasHeld")
            }
            else -> RdxLog.w(TAG, "ignored unknown action ${intent.action}")
        }
    }

    private companion object {
        const val TAG = "HeldKeyDebugReceiver"
        const val ACTION_HOLD_KEY = "com.remotedexter.debug.HOLD_KEY"
        const val ACTION_RELEASE_KEY = "com.remotedexter.debug.RELEASE_KEY"
        const val EXTRA_SCAN_CODE = "scan_code"

        /** LeftShift. Held for a minute it changes nothing on the host. */
        const val DEFAULT_SCAN_CODE = 42
    }
}
