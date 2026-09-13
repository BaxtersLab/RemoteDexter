package com.remotedexter

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ComponentCallbacks2
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.core.app.NotificationCompat

class RDService : Service() {

    private val tickHandler = Handler(Looper.getMainLooper())
    private val tickRunnable = object : Runnable {
        override fun run() {
            TransportBindings.rd_tick()
            val tickInterval = if (isDozing) 300L else 50L
            tickHandler.postDelayed(this, tickInterval)
        }
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var stateObserver: SessionStateHolder.Observer? = null
    private var isDozing = false

    companion object {
        /**
         * Whether a wake lock is currently held, for instrumentation.
         *
         * Reads the real field rather than a mirror flag: a mirror would let
         * the lock and the reported state disagree, which is exactly the class
         * of defect these tests exist to catch.
         */
        @JvmStatic
        fun isWakeLockHeldForTest(): Boolean = instance?.wakeLock?.isHeld == true

        private const val NOTIF_ID = 1
        private const val CHANNEL_ID = "remotedexter_service"

        /**
         * The running service, for [Agent2Bindings] to route host commands to.
         *
         * A Service, never an Activity — holding an Activity here would leak it
         * across rotation. Published in [onCreate] and cleared in [onDestroy]
         * only when it still refers to this instance: Android can construct a
         * replacement before tearing down its predecessor, and an unguarded
         * `instance = null` would unregister the live one.
         */
        @Volatile
        @JvmStatic
        var instance: RDService? = null
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        // BEFORE init_session, and before anything can connect: the native side
        // needs somewhere to keep ONE Noise identity. Without it the client
        // generates a fresh keypair per connection and the host sees a
        // different device every time, so durable pairing cannot work.
        // `filesDir` is app-private and survives updates. It also must not
        // leave the device, and THAT TAKES TWO SETTINGS, not one. This comment
        // used to cite `allowBackup=false` alone, which stops cloud backup and
        // does nothing about device-to-device transfer: from API 31 a D2D
        // transfer includes everything unless res/xml/data_extraction_rules.xml
        // excludes it, so a phone-to-phone move would have cloned this key and
        // handed a second device an enrolled identity the host never paired.
        // Both are now set; see that file for the whole reasoning.
        if (RDRust.isAvailable()) {
            TransportBindings.rd_set_data_dir(filesDir.absolutePath)
        }
        TransportBindings.rd_init_session()
        Agent2State.setSession(Agent2State.Session.Active)
        // NO WAKE LOCK HERE. It used to be acquired in onCreate, i.e. from the
        // moment the app was opened, for the life of the process, whether or
        // not anything was connected. ServicePolicy decides now, and only
        // Streaming qualifies.
        // ORDER MATTERS, and getting it wrong is subtle.
        //
        // `subscribe` replays the CURRENT state to a new observer immediately —
        // which at this moment is Idle, because no connect has been processed
        // yet. Subscribing first therefore made the service decide to stop
        // itself, and only then post its foreground notification: the
        // notification appeared and outlived the service that owned it.
        //
        // Found by `theForegroundNotificationDisappearsWhenTheSessionEnds` on
        // real hardware, then reproduced on the emulator, which is what showed
        // it was mine and not the OEM's.
        startForeground(NOTIF_ID, buildNotification())
        observeSessionState()
        tickHandler.post(tickRunnable)
    }

    override fun onDestroy() {
        tickHandler.removeCallbacks(tickRunnable)
        Agent2State.setSession(Agent2State.Session.Idle)
        TransportBindings.rd_shutdown_session()
        stateObserver?.let { SessionStateHolder.unsubscribe(it) }
        stateObserver = null
        releaseWakeLock()
        if (instance === this) {
            instance = null
        }
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // A deliberate connection request. The intent carries an opaque id and
        // nothing else — never a token, never key material. The invite itself
        // is exchanged for that id out of process memory.
        if (intent?.action == PendingConnects.ACTION_CONNECT) {
            val id = intent.getStringExtra(PendingConnects.EXTRA_REQUEST_ID)
            val invite = PendingConnects.take(id)
            if (invite == null) {
                SessionStateHolder.set(
                    SessionState.Failed(FailureReason.InviteParse, "connection request expired")
                )
                stopSelf()
                return START_NOT_STICKY
            }
            when (invite) {
                is PendingInvite.Direct -> {
                    SessionStateHolder.set(SessionState.Connecting(invite.invite.addr))
                    SessionOrchestrator.beginConnect(invite.invite, applicationContext)
                }
                is PendingInvite.ViaRelay -> {
                    // The RELAY is what the user is shown, never the session id.
                    SessionStateHolder.set(
                        SessionState.Connecting("relay ${invite.invite.relayAddr}")
                    )
                    SessionOrchestrator.beginRelayConnect(invite.invite, applicationContext)
                }
            }
        }
        // The no-QR path. Nothing is exchanged out of process memory because
        // nothing secret is involved; the orchestrator publishes its own
        // refusal when no host is stored.
        if (intent?.action == PendingConnects.ACTION_RECONNECT) {
            if (!SessionOrchestrator.beginReconnect(applicationContext)) {
                stopSelf()
                return START_NOT_STICKY
            }
        }
        if (intent?.action == PendingConnects.ACTION_DISCONNECT) {
            SessionOrchestrator.disconnect()
            SessionStateHolder.set(SessionState.Idle)
        }
        if (intent?.action == "SET_DOZING") {
            val dozing = intent.getBooleanExtra("dozing", false)
            isDozing = dozing
            onPowerStateChange(isDozing = dozing, screenOff = false)
        }
        if (intent?.action == "SCREEN_OFF") {
            onPowerStateChange(isDozing = isDozing, screenOff = true)
        }
        if (intent?.action == "SCREEN_ON") {
            onPowerStateChange(isDozing = false, screenOff = false)
        }
        // START_NOT_STICKY: if Android kills this process, the session is gone
        // and its one-use token is spent. Resurrecting the service would give a
        // user a foreground notification for a session that cannot exist.
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /**
     * Swiping the app away ends the session. It does **not** restart the
     * service.
     *
     * This used to re-launch itself here, which combined with `START_STICKY`
     * made the service effectively unkillable from the UI: the user swiped the
     * app away and the foreground notification came straight back. For an app
     * that can control a desktop, "the user cannot turn it off" is not a
     * resilience feature.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        check(!ServicePolicy.shouldRestartOnTaskRemoved()) {
            "ServicePolicy says restart-on-task-removal is allowed; it must never be"
        }
        SessionOrchestrator.disconnect()
        SessionStateHolder.set(SessionState.Idle)
        releaseWakeLock()
        stopForegroundCompat()
        stopSelf()
        super.onTaskRemoved(rootIntent)
    }

    /**
     * Follow the observable state: hold the wake lock only while streaming, and
     * stop the service the moment the session reaches a terminal state.
     */
    private fun observeSessionState() {
        // The replayed current value is delivered synchronously inside
        // `subscribe`. At that instant the service has just posted its
        // foreground notification and no connect has been processed, so the
        // state is still Idle — acting on it would stop the service the moment
        // it started. Skip exactly that first delivery; every real transition
        // after it is honoured.
        var sawReplay = false
        stateObserver = SessionStateHolder.subscribe { state ->
            if (!sawReplay) {
                sawReplay = true
                return@subscribe
            }
            if (ServicePolicy.wakeLockShouldBeHeld(state)) {
                acquireWakeLock()
            } else {
                releaseWakeLock()
            }
            if (ServicePolicy.shouldStopSelf(state)) {
                // Remove the notification EXPLICITLY before stopping.
                //
                // Destroying a foreground service usually takes its
                // notification with it, but `setOngoing(true)` plus Samsung's
                // notification handling left it on screen on the real
                // SM-G970U — telling the user a remote session was active when
                // the service had already stopped. That is the worst direction
                // for this particular lie to fail in.
                stopForegroundCompat()
                stopSelf()
            }
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        // Reduce work during low memory
        if (level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW) {
            isDozing = true // Slow down ticking
        }
        // (Camera/mic shutdown under memory pressure was removed with the
        // VirtualOffice split — RemoteDexter drives no phone sensors.)
    }

    /** Remove the foreground notification across API levels. */
    @Suppress("DEPRECATION")
    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            stopForeground(true)
        }
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (wakeLock?.isHeld == true) return
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "RDService::EngineLock")
        wakeLock?.acquire()
    }

    private fun releaseWakeLock() {
        if (wakeLock?.isHeld == true) {
            wakeLock?.release()
        }
        wakeLock = null
    }

    fun onAgent2Command(json: String) {
        // Streaming-negotiation replies (windows/ack/denied/error) arrive on this
        // same inbound path but are NOT Agent2 commands — Agent2Parser would throw
        // on them. Offer them to the orchestrator first; only route what it does
        // not claim, and never let an unrecognised host message crash the callback.
        if (SessionOrchestrator.onHostMessage(json)) return
        try {
            Agent2Router.handle(Agent2Parser.parse(json))
        } catch (e: Exception) {
            RdxLog.w("Agent2", "unhandled host message: ${json.take(80)}", e)
        }
    }

    fun onSessionStateChange(active: Boolean) {
        Agent2State.setSession(
            if (active) Agent2State.Session.Active else Agent2State.Session.Suspended
        )
    }

    fun onPowerStateChange(isDozing: Boolean, screenOff: Boolean) {
        Agent2State.setPower(
            when {
                screenOff -> Agent2State.Power.ScreenOff
                isDozing -> Agent2State.Power.Dozing
                else -> Agent2State.Power.Awake
            }
        )
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            // IMPORTANCE_LOW, not IMPORTANCE_MIN.
            //
            // A foreground service is a bargain: the app keeps running, and in
            // exchange the user gets a notification telling them so. For an app
            // that can control a desktop, that notification is their only
            // ambient signal that a session exists.
            //
            // IMPORTANCE_MIN defeats it. On the real SM-G970U (API 31) it
            // produced NO notification visible to `activeNotifications` at all;
            // on other builds it collapses into a hidden group. The emulator
            // does not reproduce this — it was found only because Block 5 ran
            // on real hardware. LOW is silent but visible and persistent,
            // which is what a foreground service is supposed to be.
            val channel = NotificationChannel(
                CHANNEL_ID,
                "RemoteDexter session",
                NotificationManager.IMPORTANCE_LOW
            )
            channel.description =
                "Shown while a remote session is active. It cannot be dismissed " +
                "while the session is running."
            channel.setShowBadge(false)
            mgr.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        ensureChannel()
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("RemoteDexter session active")
            .setContentText("This device is connected to a remote desktop.")
            .setOngoing(true)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)

        return builder.build()
    }
}