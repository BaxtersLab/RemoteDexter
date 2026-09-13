package com.remotedexter

/**
 * When `RDService` may exist, and when it may hold a wake lock.
 *
 * Deliberately pure: no `android.*` import, no I/O, no singletons. That is what
 * makes the lifecycle contract testable on the JVM in milliseconds instead of
 * only on a device — and these rules are the ones that decide whether the app
 * keeps a phone awake, so they should be cheap enough to check on every change.
 *
 * ## The rules
 *
 * 1. The service exists **only** while a session is being established or is
 *    live. Not on launch, not after a failure, not after a disconnect.
 * 2. The wake lock is held **only** while streaming. `Connecting` does not
 *    justify keeping the screen subsystem awake.
 * 3. Any terminal state stops the service.
 */
object ServicePolicy {

    /** Should `RDService` be running in this state? */
    fun serviceShouldRun(state: SessionState): Boolean = state.isActive

    /**
     * Should a wake lock be held?
     *
     * Narrower than [serviceShouldRun] on purpose. The old code took a
     * `PARTIAL_WAKE_LOCK` in `onCreate` — that is, from the moment the app was
     * opened, for as long as the process lived, regardless of whether anything
     * was connected.
     */
    fun wakeLockShouldBeHeld(state: SessionState): Boolean = state is SessionState.Streaming

    /** Should the service call `stopSelf()` now? */
    fun shouldStopSelf(state: SessionState): Boolean = state.isTerminal

    /**
     * Should the service restart itself when the task is removed?
     *
     * **Always false.** `onTaskRemoved` used to re-launch the service, so
     * swiping the app away brought it straight back. Combined with
     * `START_STICKY` that made the service effectively unkillable by the user,
     * which is a thing a remote-control app must never be.
     */
    fun shouldRestartOnTaskRemoved(): Boolean = false

    /**
     * Should the app ask for battery-optimisation exemption at launch?
     *
     * **Always false.** It used to fire
     * `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` from `onCreate`, so the
     * first thing a new user saw was a system dialog asking for an exemption,
     * before they had connected to anything. It is an explicit settings action
     * now, with an explanation.
     */
    fun shouldRequestBatteryExemptionOnLaunch(): Boolean = false
}
