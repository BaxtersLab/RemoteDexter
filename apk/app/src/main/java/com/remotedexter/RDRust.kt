package com.remotedexter

/**
 * Native library loader and the session entry points.
 *
 * Every `external fun` here must match a `RegisterNatives` entry in
 * `rust/src/lib.rs` (`native_registrations()`) by name **and** JNI descriptor.
 * `JNI_OnLoad` now fails closed — a missing or mistyped declaration returns
 * `JNI_ERR` and `System.loadLibrary` throws — so a mismatch is loud rather than
 * a library that loads and then has no working entry points. The Rust test
 * `every_registered_native_is_declared_in_kotlin` checks this file against that
 * table on every build.
 */
object RDRust {

    /**
     * Whether the native library actually loaded for this device's ABI.
     *
     * The APK ships arm64-v8a, armeabi-v7a and x86_64. A device outside that
     * set gets an `UnsatisfiedLinkError` in the initialiser, and before Block 5
     * that surfaced as a crash or a screen that never changed. It is now a
     * distinct visible state: `FailureReason.UnsupportedAbi`.
     */
    @Volatile
    @JvmStatic
    var loaded: Boolean = false
        private set

    /** True when the native entry points below can be called. */
    @JvmStatic
    fun isAvailable(): Boolean = loaded

    init {
        // ONE native-code trust root: the library inside the signed APK.
        //
        // This used to prefer `files/active/libremotedexter.so` via
        // `System.load`, falling back to the bundled library. That is a SECOND
        // trust root, and an unsigned one: the APK's library is verified by
        // Android, a file in app-private storage is not. Anything able to write
        // there — a historical updater, a transfer feature, instrumentation,
        // root, or any same-UID compromise — got arbitrary code execution in
        // this process.
        //
        // It was the last limb of a feature that had already been deleted.
        // Block 13 removed the update path, its UpdateManager and its
        // placeholder key; this loader survived, and NOTHING IN THE TREE EVER
        // WROTE THAT PATH. A load path with no writer is attack surface with no
        // function. Removed 2026-09-07 after an outside security review;
        // `single-android-tree` now fails on any path-based `System.load`, which
        // is the check that should have caught it the first time.
        System.loadLibrary("remotedexter")
        loaded = true
    }

    /**
     * Open a pinned Noise session to the host. Returns immediately; the
     * handshake and session loop run on a native thread.
     *
     * `hostPubkey` must be the host's 32-byte Noise static key from the invite.
     * Rust refuses to connect without exactly 32 bytes — there is no unpinned
     * path. Descriptor: `(Ljava/lang/String;ILjava/lang/String;[B)V`
     */
    external fun startSession(
        hostIp: String,
        port: Int,
        sessionToken: String,
        hostPubkey: ByteArray
    )

    /**
     * Connect to a host THROUGH A RELAY, using a v5 pairing invite.
     *
     * A separate native from [startSession] for the same reason
     * [startPairedSession] is: what matters to a reader here is WHICH ROUTE is
     * being taken, and a method that decided it from whether a string happened
     * to be blank would hide exactly that. It also means this path cannot be
     * reached by accident from a direct invite whose address failed to parse.
     *
     * `session` is the id the relay issued to the host, carried in the signed
     * invite. It is not a secret from the relay — the relay issued it — but it
     * is a credential against the relay, so it is never logged.
     *
     * `hostPubkey` is still the host's 32-byte Noise static key and is still
     * mandatory. **Going through a relay changes nothing about who the host has
     * to prove itself to be:** the handshake runs end to end through the splice
     * and a relay that spliced this connection to a machine of its own choosing
     * fails at the pin. Descriptor:
     * `(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;[B)V`
     */
    external fun startRelaySession(
        relayIp: String,
        relayPort: Int,
        session: String,
        sessionToken: String,
        hostPubkey: ByteArray
    )

    /**
     * Reconnect to a host that has already enrolled this device — **no token**.
     *
     * There is no QR in this path and nothing to expire. What authenticates is
     * this device's own persistent Noise key, which means it only works after
     * [TransportBindings.rd_set_data_dir] has been called at least once in a
     * previous run; with a throwaway identity the host sees a device it has
     * never met and refuses.
     *
     * `hostPubkey` is still mandatory and still 32 bytes. Dropping the device's
     * credential does not drop the host's: an attacker who answers on the
     * stored address is rejected here exactly as on the invite path.
     *
     * A refusal is not distinguishable from "revoked" by design — the host
     * refuses unknown and revoked devices identically, so it cannot be used to
     * probe which keys it knows. Descriptor: `(Ljava/lang/String;I[B)V`
     */
    external fun startPairedSession(
        hostIp: String,
        port: Int,
        hostPubkey: ByteArray
    )

    /**
     * Send one JSON command to the live session. Descriptor:
     * `(Ljava/lang/String;)Z`
     *
     * Non-blocking and safe to call from the main thread: Rust validates
     * synchronously and enqueues without waiting, so this never touches the
     * network on the caller's thread.
     *
     * Returns false — never throws — when there is no session, the command is
     * not a JSON object, it exceeds the Noise plaintext ceiling, or the bounded
     * channel is full. A false result means nothing was sent.
     */
    external fun sendCommand(json: String): Boolean

    /** Ask the owning session loop to close cleanly. Descriptor: `()V` */
    external fun stopSession()

    /**
     * Attach [FrameReceiver] as the destination for inbound video frames.
     * Descriptor: `()V`
     *
     * Called by [FrameReceiver.attach], not directly — the receiver is the only
     * thing that knows whether a viewer actually exists.
     */
    external fun registerFrameReceiver()

    /**
     * Detach it again. Descriptor: `()V`
     *
     * Without this the receiver would stay registered for the life of the
     * process and Rust would keep pushing frames at a backgrounded app.
     */
    external fun unregisterFrameReceiver()

    /**
     * Latest state of the session worker, as `state|detail`. Descriptor:
     * `()Ljava/lang/String;`
     *
     * [startSession] returns as soon as the worker thread is spawned, so its
     * return says only that the call was accepted — the TCP connect, the Noise
     * handshake and the host-key pin all happen afterwards on another thread.
     * Poll this to find out what actually happened; prefer [sessionState].
     *
     * `state` is one of `idle`, `connecting`, `connected`, `failed`. `detail` is
     * human-readable and meant for the log, not for parsing.
     */
    external fun sessionStatus(): String

    /** Session state alone, with the detail stripped off. */
    fun sessionState(): String = sessionStatus().substringBefore('|')

    /** The human-readable half of [sessionStatus]. */
    fun sessionDetail(): String = sessionStatus().substringAfter('|', "")
}
