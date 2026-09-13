package com.remotedexter

/**
 * The one place the app's [SessionState] lives, owned by the application layer.
 *
 * ## What this replaces
 *
 * Callback singletons. `SessionOrchestrator` published progress by invoking
 * lambdas that whichever Activity happened to be alive had registered, which
 * meant state was owned by a view that Android is free to destroy at any moment.
 * Rotate the phone mid-connect and the callback pointed at a dead Activity;
 * the session carried on with nothing observing it.
 *
 * State lives here instead — above the Activity, below the service — and views
 * subscribe to it. Rotation re-subscribes and gets the current value
 * immediately, which is why `rotationPreservesActiveState` can pass.
 *
 * Deliberately free of `android.*` so the whole state machine is JVM-testable.
 */
object SessionStateHolder {

    /** A subscriber. Called immediately on subscribe, then on every change. */
    fun interface Observer {
        fun onState(state: SessionState)
    }

    private val observers = mutableListOf<Observer>()

    @Volatile
    private var current: SessionState = SessionState.Idle

    /** The current state. Never null; the app starts Idle. */
    @Synchronized
    fun current(): SessionState = current

    /**
     * Subscribe. The observer is called straight away with the current state,
     * so a freshly created view never renders a stale or empty screen while it
     * waits for the next change.
     */
    @Synchronized
    fun subscribe(observer: Observer): Observer {
        observers.add(observer)
        observer.onState(current)
        return observer
    }

    /** Unsubscribe. Views must do this in `onDestroy` or they leak. */
    @Synchronized
    fun unsubscribe(observer: Observer) {
        observers.remove(observer)
    }

    /**
     * Move to a new state and notify everyone.
     *
     * An identity mismatch is **sticky**: once the host's key has changed, no
     * later transition may quietly clear it. Only [resolveIdentityMismatch],
     * called from a deliberate Unpair, can leave that state. Without this an
     * automatic reconnect could overwrite the mismatch with `Connecting` and
     * the user would never see that anything was wrong.
     */
    @Synchronized
    fun set(state: SessionState) {
        if (current is SessionState.IdentityMismatch &&
            state !is SessionState.IdentityMismatch
        ) {
            return
        }
        current = state
        observers.toList().forEach { it.onState(state) }
    }

    /**
     * Clear a blocking identity mismatch. **Only** legitimate after the user
     * has seen both fingerprints and confirmed an Unpair.
     */
    @Synchronized
    fun resolveIdentityMismatch() {
        if (current is SessionState.IdentityMismatch) {
            current = SessionState.Idle
            observers.toList().forEach { it.onState(current) }
        }
    }

    /**
     * Test seam: return to Idle **without touching the observer list**.
     *
     * It used to call `observers.clear()`, which in instrumentation silently
     * unsubscribed the *running service's* own observer — leaving a live
     * service deaf to every later transition and making the lifecycle tests
     * pass or fail depending on their order. Components manage their own
     * subscriptions (`onDestroy` unsubscribes); a test has no business
     * severing them.
     */
    @Synchronized
    fun resetForTest() {
        current = SessionState.Idle
    }
}
