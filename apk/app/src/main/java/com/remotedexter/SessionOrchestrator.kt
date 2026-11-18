package com.remotedexter

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import org.json.JSONObject

/**
 * Turns a *connected* session into a *streaming* one, and makes the whole
 * process visible.
 *
 * Two problems this solves, both learned the hard way:
 *
 * 1. **Nothing drove streaming.** `RDRust.startSession` opens the pinned Noise
 *    session, but the host sends no frames until the client asks. Without the
 *    negotiation below, pairing succeeded and the screen stayed black.
 *
 * 2. **The session was silent.** `startSession` returns the instant the worker
 *    thread spawns, so its return said nothing about whether the connection or
 *    the handshake actually succeeded. [watch] polls [RDRust.sessionStatus] and
 *    reports every transition to [RdxLog] and the user, so a failure names
 *    itself instead of looking like a hang.
 *
 * ### Full desktop, not a window picker
 *
 * VirtualOffice was window-scoped: the operator chose a window to view. On
 * Linux the host offers exactly one surface — the whole desktop — because
 * Wayland will not enumerate windows, and full-desktop is what RemoteDexter is
 * for. So this negotiator does not present a picker: it takes the single surface
 * the host lists and streams it. If the host ever lists more than one, the first
 * is taken; RemoteDexter has no per-window UI by design.
 *
 * ### Wire sequence (all over the pinned Noise session)
 *
 * ```
 *   → {"type":"list_windows"}
 *   ← {"type":"windows","windows":[{"id":N,...}]}
 *   → {"type":"permit_window","window":N}
 *   ← {"type":"ack","for":"permit_window"}
 *   → {"type":"stream_start","window":N,"input_coordinates":"normalized_v1"}
 *   ← {"type":"ack","for":"stream_start","input_coordinates":"normalized_v1"}
 * ```
 *
 * Frame *delivery* is separate and surface-driven: [FrameReceiver] registers
 * when a drawable Surface exists (see MainActivity). This negotiator only makes
 * the host start sending.
 */
object SessionOrchestrator {

    private const val TAG = "SessionOrchestrator"

    /** Poll cadence while waiting for the worker to connect; the ceiling is [ConnectCeiling]'s, by route. */
    private const val POLL_MS = 250L

    private enum class Phase { Idle, Connecting, Listing, Permitting, Starting, Streaming, Failed }

    private val main = Handler(Looper.getMainLooper())

    @Volatile private var _phase = Phase.Idle
    @Volatile private var pointerCoordinateSpace: PointerCoordinateSpace? = null

    /**
     * Session phase, with a setter that notifies [onPhaseChanged].
     *
     * Written as a property rather than a plain field so every existing
     * `phase = ...` assignment in this class fires the callback without any of
     * them having to be edited — there are seven, and one missed would leave the
     * indicator lying about the link state, which is worse than having no
     * indicator at all.
     */
    private var phase: Phase
        get() = _phase
        set(value) {
            if (value != Phase.Streaming) pointerCoordinateSpace = null
            if (_phase == value) return
            _phase = value
            onPhaseChanged?.invoke(value == Phase.Streaming, value.name)
        }

    /**
     * Observed by [MainActivity] to keep the link indicator truthful. First arg
     * is "is a device actually streaming", second is the phase name for detail.
     */
    var onPhaseChanged: ((linked: Boolean, phaseName: String) -> Unit)? = null
    @Volatile private var appContext: Context? = null

    /** Window id chosen from the host's list; sent back on permit and start. */
    @Volatile private var windowId: Long = -1

    /**
     * The desktop's window id, once known — [InputController] needs it to
     * scope `input_event`/`grant_input` to the same surface that's actually
     * streaming. Read-only on purpose: only this class's own negotiation
     * should ever change it.
     */
    fun currentWindowId(): Long = windowId

    fun currentPointerCoordinateSpace(): PointerCoordinateSpace? =
        if (phase == Phase.Streaming) pointerCoordinateSpace else null

    /**
     * Begin a connection the user explicitly asked for.
     *
     * Called only from `RDService` after it exchanged an opaque request id for
     * the invite. The invite — and its one-use token — never travelled through
     * an Intent extra to get here.
     *
     * Failures are published to [SessionStateHolder] with a specific
     * [FailureReason], not logged and swallowed. That is the whole point of
     * Block 5: a refusal the user cannot see is indistinguishable from a bug.
     */
    /**
     * Begin a session THROUGH A RELAY, from a v5 invite.
     *
     * Mirrors [beginConnect] gate for gate — the ABI check, the expiry check
     * and the pin decode are the same and in the same order. What differs is
     * only the native it calls and what it reports as the endpoint.
     *
     * **The session id is never used as a label.** `hostLabel` and the
     * connecting state name the relay, because the id is what this device
     * presents to reach the host and it ends up in the UI and the log.
     */
    fun beginRelayConnect(invite: com.remotedexter.bootstrap18.InviteV5, context: Context) {
        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
        if (!RDRust.isAvailable()) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.UnsupportedAbi, "no native library for $abi")
            )
            return
        }
        if (com.remotedexter.bootstrap18.InviteDecoder.isExpired(
                invite,
                System.currentTimeMillis() / 1000
            )
        ) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteExpired, "scan a fresh code")
            )
            return
        }
        val label = "relay ${invite.relayAddr}"
        SessionStateHolder.set(SessionState.Connecting(label))
        // What to remember once the host has accepted this device. A relay
        // pairing used to leave nothing: the relay gave the host a new random
        // session id every time it registered, so the id was dead after the
        // host's next restart. An enrolled host now keeps its id for as long as
        // the relay runs, so the route is worth keeping — and it is recorded
        // HERE but stored only on `connected`, never on scan.
        //
        // Built from the invite alone, and never from its token.
        pendingPairing = PairedHostRecord.viaRelay(
            invite.hostIdentityPubkey,
            invite.relayAddr,
            invite.relayPort,
            invite.session,
            invite.hostPubkey
        )
        reconnectingViaRelay = false
        hostLabel = label
        val pin = decodeHostPin(invite.hostPubkey)
        if (pin == null) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "invalid host key pin")
            )
            return
        }
        try {
            RDRust.startRelaySession(
                invite.relayAddr,
                invite.relayPort,
                invite.session,
                invite.token,
                pin
            )
            watch(context, viaRelay = true)
        } catch (t: Throwable) {
            RdxLog.e(TAG, "native relay session start failed", t)
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.Network, "could not start the connection")
            )
        }
    }

    fun beginConnect(invite: com.remotedexter.bootstrap18.InviteV4, context: Context) {
        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
        if (!RDRust.isAvailable()) {
            SessionStateHolder.set(
                SessionState.Failed(
                    FailureReason.UnsupportedAbi,
                    "no native library for $abi"
                )
            )
            return
        }
        if (com.remotedexter.bootstrap18.InviteDecoder.isExpired(
                invite,
                System.currentTimeMillis() / 1000
            )
        ) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteExpired, "scan a fresh code")
            )
            return
        }
        SessionStateHolder.set(SessionState.Connecting(invite.addr))
        // The IDENTITY comes from the same invite as the address and the pin.
        // It is what decides whether a host is one we know, and storing it
        // beside a different host's address is the failure PairedHostRecord
        // exists to make unrepresentable — so the record is built in one place,
        // from one source, or not at all.
        pendingPairing = PairedHostRecord.of(
            invite.hostIdentityPubkey, invite.addr, invite.port, invite.hostPubkey
        )
        reconnectingViaRelay = false
        hostLabel = invite.addr
        val pin = decodeHostPin(invite.hostPubkey)
        if (pin == null) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "invalid host key pin")
            )
            return
        }
        try {
            RDRust.startSession(invite.addr, invite.port, invite.token, pin)
            watch(context, viaRelay = false)
        } catch (t: Throwable) {
            RdxLog.e(TAG, "native session start failed", t)
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.Network, "could not start the connection")
            )
        }
    }

    /**
     * Reconnect to the host this device is already enrolled with — no QR.
     *
     * The whole of Block 9 from the user's side. What authenticates is this
     * device's persistent Noise key; there is no token, nothing to expire, and
     * nothing to scan.
     *
     * Refuses, visibly, when there is nothing stored. A Connect button that
     * silently did nothing would be indistinguishable from one that tried and
     * failed, and the remedy differs: one needs a QR, the other needs the host
     * started.
     *
     * @return false if there was nothing to reconnect to.
     */
    fun beginReconnect(context: Context): Boolean {
        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
        if (!RDRust.isAvailable()) {
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.UnsupportedAbi, "no native library for $abi")
            )
            return false
        }
        val paired = PairedHostRegistry(context).active()
        if (paired == null) {
            RdxLog.w(TAG, "reconnect requested with no paired host stored")
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.InviteParse, "no paired host — scan a QR first")
            )
            return false
        }
        // The route this device last paired by. A LAN route reconnects exactly
        // as it always has; a relay route presents the session id kept from the
        // relay pairing. The label names the route and never the session.
        val route = paired.reconnectRoute()
        val label = paired.label()
        SessionStateHolder.set(SessionState.Connecting(label))
        // A reconnect has no pairing to record: the record is already stored,
        // and the one it would write is the one it read.
        pendingPairing = null
        reconnectingViaRelay = route is PairedHostRecord.Reconnect.ViaRelay
        hostLabel = label
        try {
            when (route) {
                is PairedHostRecord.Reconnect.Lan ->
                    RDRust.startPairedSession(route.host.addr, route.host.port, route.host.pinBytes())
                is PairedHostRecord.Reconnect.ViaRelay ->
                    RDRust.startPairedRelaySession(
                        route.route.relayAddr,
                        route.route.relayPort,
                        route.route.pinBytes(),
                        route.route.session
                    )
            }
            watch(context, viaRelay = route is PairedHostRecord.Reconnect.ViaRelay)
        } catch (t: Throwable) {
            RdxLog.e(TAG, "native paired session start failed", t)
            SessionStateHolder.set(
                SessionState.Failed(FailureReason.Network, "could not start the connection")
            )
            return false
        }
        return true
    }

    /** End the session deliberately. */
    fun disconnect() {
        pendingPairing = null
        reconnectingViaRelay = false
        hostLabel = null
        InputController.reset()
        // Invalidate the streaming monitor before native shutdown reports
        // `idle`; an intentional disconnect must not be rendered as failure.
        reset()
        try {
            RDRust.stopSession()
        } catch (e: Throwable) {
            RdxLog.w("RDSession", "stopSession: ${e.javaClass.simpleName}")
        }
        // NOT rd_shutdown_session(). That is the SERVICE's shutdown, and it
        // used to be called here.
        //
        // It sets `service_running = false` in the session engine, and the
        // engine will only return to Active from Closed or Idle **while the
        // service is running**. So one disconnect poisoned the process: every
        // later connection reported "connected", and every frame was dropped
        // silently by `InboundFrame`'s `if state == Active` guard, with nothing
        // logged on either side. The picture stayed black and the app said it
        // was streaming.
        //
        // The operator found it by ending a session — "this was only after I
        // clicked forget this host that it went black" — and it needed no
        // reinstall to reproduce, only a disconnect.
        //
        // Ending a SESSION is not ending the SERVICE. `RDRust.stopSession()`
        // above already tears the transport down, and the session loop raises
        // `TransportDisconnected` on its way out, which closes the engine's
        // session and clears its queue. That is the whole of the correct
        // teardown; the service keeps running, so the next connect can reach
        // Active again.
        //
        // `rd_shutdown_session` remains where the engine documents it:
        // `RDService.onDestroy`.
    }

    /** The invite a connect is running for, if any. Process memory only. */
    @Volatile
    /**
     * Called with the host's clipboard text when it arrives.
     *
     * A callback rather than a direct write because putting text on the phone's
     * clipboard needs a Context, and this object holds an application Context
     * for the session — not the Activity that should be telling the user it
     * happened.
     */
    var onHostClipboard: ((String) -> Unit)? = null

    /** Called when the host's clipboard was empty. */
    var onHostClipboardEmpty: (() -> Unit)? = null

    /**
     * Called when the host refused a clipboard command, with its reason.
     *
     * The reason is the host's own short string — "the host's clipboard is not
     * text", "RD_CAP_CLIPBOARD" — and never carries clipboard content.
     */
    var onClipboardRefused: ((String) -> Unit)? = null

    /**
     * What to store once the host accepts this device: the route just paired
     * by, built from the invite and never from its token. Null on a reconnect,
     * which has nothing new to record.
     */
    private var pendingPairing: PairedHostRecord? = null

    /**
     * Whether the connection in progress is a TOKEN-LESS reconnect through the
     * relay — the one case where a refusal from the relay means "the relay does
     * not know this host right now" rather than "this code is wrong".
     */
    private var reconnectingViaRelay = false

    /**
     * The host this session is talking to, for display.
     *
     * Separate from [pendingPairing] because a reconnect has no invite at all.
     * Reading the label off the invite meant the Streaming state was published
     * only on the QR path; on a reconnect the session would stream while the
     * UI still read "Connecting", which is the exact class of silent
     * divergence Block 5 exists to prevent.
     */
    @Volatile private var hostLabel: String? = null

    /** Report a session failure with a specific, visible reason. */
    fun fail(reason: FailureReason, detail: String) {
        SessionStateHolder.set(SessionState.Failed(reason, detail))
    }

    /** Report a blocking host-identity change. */
    fun failIdentityMismatch(expected: String, received: String) {
        SessionStateHolder.set(SessionState.IdentityMismatch(expected, received))
    }

    /** Last `state|detail` seen, so only real transitions are logged. */
    private var lastStatus: String = ""

    /** Invalidates delayed status checks from an older or deliberately ended session. */
    @Volatile private var watchGeneration: Long = 0

    /**
     * Begin watching a session that has just been asked to start.
     *
     * Call right after [RDRust.startSession]. Polls [RDRust.sessionStatus] on the
     * main thread, logs each transition, and — when the handshake reports
     * `connected` — kicks off the streaming negotiation. Gives up after the
     * route's [ConnectCeiling] so a host that never answers does not poll
     * forever — and a relayed host is not abandoned before the relay itself
     * would give up on it.
     */
    fun watch(context: Context, viaRelay: Boolean) {
        appContext = context.applicationContext
        reset()
        val generation = watchGeneration
        val maxTries = ConnectCeiling.tries(viaRelay, POLL_MS)
        phase = Phase.Connecting
        main.post(object : Runnable {
            var tries = 0
            override fun run() {
                if (generation != watchGeneration) return
                val status = RDRust.sessionStatus()
                if (status != lastStatus) {
                    lastStatus = status
                    RdxLog.i(TAG, "session status: $status")
                }
                when (status.substringBefore('|')) {
                    "connected" -> {
                        rememberHostForReconnect()
                        beginNegotiation()                     // stop polling
                    }
                    "failed" -> fail(status.substringAfter('|', "connection failed"))
                    else -> {
                        if (++tries >= maxTries) {
                            fail("timed out waiting for the host to connect")
                        } else {
                            main.postDelayed(this, POLL_MS)
                        }
                    }
                }
            }
        })
    }

    /**
     * Record where to reconnect, now that the handshake has succeeded.
     *
     * Deliberately here and not in [beginConnect]. `connected` is published
     * only once the host has answered `pair_ok`, which it does only after
     * spending the pairing token and enrolling this device's key. Storing on
     * scan instead would leave the phone offering to reconnect to a host that
     * refused it — and every attempt would fail identically to a host that is
     * simply switched off, so the user could not tell which.
     *
     * A reconnect has no invite, so this is a no-op on that path: the record is
     * already there and unchanged.
     */
    private fun rememberHostForReconnect() {
        val pairing = pendingPairing ?: return
        val context = appContext ?: return
        PairedHostRegistry(context).remember(pairing)
    }

    /** Send `list_windows` and move into the negotiation. */
    private fun beginNegotiation() {
        if (phase == Phase.Streaming || phase == Phase.Failed) return
        toast("Connected — starting stream")
        phase = Phase.Listing
        send("""{"type":"list_windows"}""", "list_windows")
    }

    /**
     * Offer a host message to the negotiation.
     *
     * @return true if this was a negotiation message (windows/ack/denied/error)
     *   and was consumed here; false if it is an ordinary Agent2 command the
     *   caller should route onward. Returning false is what keeps clipboard and
     *   power commands working — they are not our messages.
     */
    @Synchronized
    fun onHostMessage(json: String): Boolean {
        val obj = try {
            JSONObject(json)
        } catch (e: Exception) {
            return false // not JSON we own; let the caller deal with it
        }
        when (obj.optString("type")) {
            "windows" -> { onWindows(obj); return true }
            "ack" -> { onAck(obj); return true }
            // The host's clipboard, arriving because the operator asked for it.
            // Consumed here rather than routed onward: it is a reply to a
            // command this object sent, and nothing else has any business with
            // it. The TEXT IS NEVER LOGGED — only its size.
            "clipboard" -> {
                // `has` rather than `optString`: an ABSENT text field is a
                // message that did not say, which is not the same as a host
                // whose clipboard is empty — and only the second may clear this
                // phone's clipboard.
                val text = if (obj.has("text")) obj.getString("text") else null
                when (val incoming = ClipboardBridge.receive(text)) {
                    is ClipboardBridge.Incoming.Replace -> {
                        onHostClipboard?.invoke(incoming.text)
                        RdxLog.i(
                            TAG,
                            "host clipboard received (${incoming.text.toByteArray().size} bytes)"
                        )
                    }
                    ClipboardBridge.Incoming.Clear -> {
                        RdxLog.i(TAG, "host clipboard is empty")
                        onHostClipboardEmpty?.invoke()
                    }
                    ClipboardBridge.Incoming.Malformed ->
                        RdxLog.w(TAG, "a clipboard message arrived with no text field")
                }
                return true
            }
            "denied", "error" -> {
                val forCmd = obj.optString("for")
                val reason = obj.optString("reason", "no reason given")
                // A denied/errored grant_input (or a stray input_event, e.g.
                // if the window scope changed mid-session) is not fatal to an
                // already-streaming session — it just means control isn't
                // available right now. Only negotiation-phase commands
                // (list_windows/permit_window/stream_start) should tear the
                // whole session down; everything else routes to whoever
                // actually asked, same as "ack" already does two lines up.
                // The list lives in SessionDenialPolicy and is walked by a
                // test. It used to be three command names written out here,
                // which was right until the clipboard was added: "the host's
                // clipboard is not text" is an ordinary answer to an ordinary
                // question, and answering it by tearing down a live stream is
                // not a trade anyone would make.
                when {
                    SessionDenialPolicy.isClipboard(forCmd) -> {
                        RdxLog.i(TAG, "host refused $forCmd: $reason")
                        onClipboardRefused?.invoke(reason)
                    }
                    // A refused text run names itself, so the compose field
                    // can take back what did not reach the desktop.
                    !SessionDenialPolicy.isFatalToSession(forCmd) ->
                        InputController.onDenied(forCmd, reason, InputJson.textReply(obj))
                    else -> fail("host ${obj.optString("type")} for $forCmd: $reason")
                }
                return true
            }
            else -> return false
        }
    }

    private fun onWindows(obj: JSONObject) {
        if (phase != Phase.Listing) return
        val windows = obj.optJSONArray("windows")
        if (windows == null || windows.length() == 0) {
            fail("host offered no shareable surface")
            return
        }
        // The sole surface on Linux is the whole desktop. No picker by design.
        //
        // Which entry is "the desktop" used to be inferred by always taking
        // index 0 — harmless while a numeric id was also being relied on as a
        // sentinel, but that sentinel is exactly what corrupted in transit
        // (see share_source.rs's DESKTOP_ID comment on the host side: u64::MAX
        // doesn't survive optLong, a signed-64-bit reader). The durable fix is
        // to stop needing a magic id at all: prefer the entry the host
        // explicitly flags with "desktop": true, and only fall back to index 0
        // for a host build old enough not to send that field yet.
        var chosen = windows.getJSONObject(0)
        for (i in 0 until windows.length()) {
            val w = windows.getJSONObject(i)
            if (w.optBoolean("desktop", false)) {
                chosen = w
                break
            }
        }
        windowId = chosen.optLong("id", -1)
        if (windowId < 0) {
            fail("host surface has no usable id")
            return
        }
        val title = chosen.optString("title", "desktop")
        RdxLog.i(TAG, "host offers surface id=$windowId (\"$title\"); permitting")
        phase = Phase.Permitting
        send("""{"type":"permit_window","window":$windowId}""", "permit_window")
    }

    private fun onAck(ack: JSONObject) {
        val forCmd = ack.optString("for")
        when (forCmd) {
            "permit_window" -> {
                if (phase != Phase.Permitting) return
                phase = Phase.Starting
                send(InputJson.streamStart(windowId), "stream_start")
            }
            "stream_start" -> {
                if (phase != Phase.Starting) return
                val space = InputJson.acknowledgedCoordinates(ack)
                if (space == null) {
                    fail("host acknowledged an unsupported input coordinate space")
                    return
                }
                pointerCoordinateSpace = space
                phase = Phase.Streaming
                hostLabel?.let {
                    SessionStateHolder.set(SessionState.Streaming(it))
                }
                RdxLog.i(TAG, "stream_start acked — host is now streaming the desktop")
                if (space == PointerCoordinateSpace.DESKTOP_PIXELS) {
                    RdxLog.w(TAG, "legacy host: update the host for adaptive-resolution pointer calibration")
                }
                toast("Streaming")
                monitorStreaming()
            }
            // Not part of this negotiator's own state machine — grant_input is
            // InputController's request, arriving over the same inbound path
            // (RDService routes every host message through onHostMessage first).
            // Forwarding rather than duplicating the routing keeps one place
            // that decodes host JSON, matching how this file already handles
            // "windows"/"ack"/"denied"/"error" for its own negotiation.
            "grant_input", "revoke_input" -> InputController.onAck(forCmd)
            // A text run typed in full settles the phone's copy of it.
            "input_event" -> InputController.onInputAck(ack)
        }
    }

    /**
     * Send a command over the session, logging and failing if it cannot be
     * enqueued. A false return from [RDRust.sendCommand] means nothing was sent —
     * usually the session is gone — so the negotiation cannot continue.
     */
    private fun send(json: String, label: String) {
        val ok = RDRust.sendCommand(json)
        if (ok) {
            RdxLog.i(TAG, "→ $label")
        } else {
            fail("could not send $label — session not accepting commands")
        }
    }

    /**
     * Give up on this session — and tell the NATIVE side, which is the half
     * this used to forget.
     *
     * # Why `stopSession` belongs here
     *
     * The timeout above is Kotlin's. Rust knows nothing about it: `run_session`
     * is still inside its connect or its session loop, and it still owns the
     * process-global command channel it claimed before connecting. So the two
     * sides disagreed about whether the session was over.
     *
     * The user then taps Connect again and Rust refuses **itself**, locally, in
     * 50-250 ms with no network traffic at all:
     *
     * ```
     * a session already owns the command channel
     * ```
     *
     * To the operator that reads as "failed instantly, and worse than last
     * time", and the only way out was force-stopping the app. **Windows round
     * 16 lost most of a round to it** after a single mistimed QR scan.
     *
     * `release_session` in the native side is not the bug — it runs
     * unconditionally on both success and failure. The bug is that nothing
     * asked the loop to finish, so it never got there.
     *
     * Wrapped, and the failure state is set REGARDLESS: a native teardown that
     * throws must not stop the UI reporting the failure the user is waiting to
     * see. That is why this is not simply `stopSession()` on the line above.
     */
    private fun fail(reason: String) {
        if (phase == Phase.Failed) return
        InputController.reset()
        phase = Phase.Failed
        RdxLog.e(TAG, "streaming setup failed: $reason")
        try {
            RDRust.stopSession()
        } catch (e: Throwable) {
            // Reported, never rethrown. The session has already failed; a
            // teardown that also fails must not replace the reason the user
            // needs with a stack trace they cannot act on.
            RdxLog.w(TAG, "stopSession during failure: ${e.javaClass.simpleName}")
        }
        val failed = NativeFailure.classify(reason, reconnectingViaRelay)
        SessionStateHolder.set(failed)
        toast("Session failed: ${failed.detail}")
    }

    /** Keep observing the native socket after negotiation has completed. */
    private fun monitorStreaming() {
        val generation = watchGeneration
        main.post(object : Runnable {
            override fun run() {
                if (generation != watchGeneration || phase != Phase.Streaming) return
                val status = RDRust.sessionStatus()
                if (status != lastStatus) {
                    lastStatus = status
                    RdxLog.i(TAG, "session status: $status")
                }
                val failure = SessionStatusPolicy.streamingFailure(status)
                if (failure != null) {
                    fail(failure)
                    return
                }
                main.postDelayed(this, POLL_MS)
            }
        })
    }

    private fun decodeHostPin(hex: String): ByteArray? {
        if (hex.length != 64) return null
        return try {
            ByteArray(32) { index ->
                hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        } catch (e: NumberFormatException) {
            null
        }
    }

    private fun reset() {
        watchGeneration++
        phase = Phase.Idle
        windowId = -1
        lastStatus = ""
    }

    private fun toast(msg: String) {
        val ctx = appContext ?: return
        main.post { Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show() }
    }
}
