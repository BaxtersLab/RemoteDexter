package com.remotedexter

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import com.remotedexter.mobile.render.SurfaceFramePipeline
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Destination for inbound remote-desktop frames.
 *
 * Rust calls [rdOnFrame] once per tick with one JPEG frame and the metadata the
 * host put on the wire. Rust holds no lock while doing so — see
 * `tick_and_dispatch_frame` in `rust/src/lib.rs`.
 *
 * The contract is checked from Rust on every build
 * (`frame_receiver_declares_the_exact_callback_signature`), and `JNI_OnLoad`
 * resolves the method at load time, so a rename or changed parameter type
 * refuses to load the library rather than failing at the first frame.
 *
 * ### Why JPEG in, Bitmap out
 *
 * The host streams JPEG. The Rust client deliberately carries no image decoder
 * — `stream_chunk` was split into its own crate precisely so the Android `.so`
 * would not inherit module11's encode stack (~85 crates, including a second
 * crypto library). So the JPEG is decoded here, on Android, using the platform
 * decoder, and handed to [SurfaceFramePipeline] as a Bitmap.
 *
 * ### Threading
 *
 * `rdOnFrame` arrives on whichever thread ticks the engine — currently the main
 * thread, via `RDService`'s handler. It must therefore return immediately: it
 * stores the frame and hands decoding to a single worker. Rendering happens on
 * the pipeline's own thread. Nothing decodes or draws on the caller's thread.
 *
 * ### Work bounds
 *
 * At most **one** frame is ever waiting to decode, and at most one decoded
 * bitmap is ever waiting to draw. A frame arriving mid-decode replaces the
 * pending one — latest wins, because a stale desktop is worse than a skipped
 * one.
 */
object FrameReceiver {

    private const val TAG = "RDFrameReceiver"

    /** One frame handed over by Rust, waiting to be decoded. */
    private class PendingFrame(
        val jpeg: ByteArray,
        val sequence: Long,
        val width: Int,
        val height: Int
    )

    /**
     * The render target, held weakly.
     *
     * This is a process-global object and the pipeline holds a `SurfaceHolder`,
     * which reaches the `SurfaceView` and through it the Activity. A strong
     * reference here would leak the Activity on every rotation. The Activity
     * owns the pipeline strongly; this only borrows it.
     */
    @Volatile
    private var target: WeakReference<SurfaceFramePipeline>? = null

    /** The single pending frame. Latest wins; this never becomes a queue. */
    private val pending = AtomicReference<PendingFrame?>(null)

    /** Whether a decode pass is already posted, so at most one is in flight. */
    private val decodeQueued = AtomicBoolean(false)

    /**
     * Last geometry the host declared, for [FrameGeometryChange].
     *
     * Diagnostic only — nothing renders from it. It exists so a geometry change
     * that ARRIVES is distinguishable from one that never did; see
     * `FrameGeometryChange` for why that distinction cost a Windows trip.
     */
    private val lastDeclared = java.util.concurrent.atomic.AtomicReference<Pair<Int, Int>?>(null)

    /** Last size a decoded JPEG actually had. Diagnostic only. */
    private val lastDecoded = java.util.concurrent.atomic.AtomicReference<Pair<Int, Int>?>(null)

    @Volatile
    private var decodeThread: HandlerThread? = null

    @Volatile
    private var decodeHandler: Handler? = null

    /**
     * Entry point invoked from Rust `call_kotlin_on_frame`.
     * Must be a @JvmStatic for CallStaticVoidMethod to resolve it.
     */
    @JvmStatic
    fun rdOnFrame(
        jpeg: ByteArray,
        sequence: Long,
        width: Int,
        height: Int,
        keyframe: Boolean
    ) {
        if (jpeg.isEmpty()) {
            Log.w(TAG, "dropping empty frame $sequence")
            return
        }
        if (width <= 0 || height <= 0) {
            Log.w(TAG, "dropping frame $sequence: implausible size ${width}x$height")
            return
        }
        // Fail closed on delta frames. `keyframe == false` means the payload is
        // a dirty SUB-RECTANGLE (module11 `encoder.rs`: is_keyframe = rect.is_none()),
        // but the header still reports the FULL screen width/height
        // (`stream_pump.rs` chunks with self.width/self.height) and
        // `stream_chunk`'s 14-byte header carries NO rect origin. There is
        // therefore no way to place the patch correctly: drawing it would
        // stretch a fragment across the whole surface.
        //
        // The live host path (`host_app`, rect = None) only ever emits
        // keyframes, so this drops nothing today. It exists so that wiring
        // StreamPump in later fails loudly instead of corrupting the picture.
        // Rendering deltas requires the wire format to carry x/y first.
        if (!keyframe) {
            Log.w(
                TAG,
                "frame $sequence: dropping delta frame — the wire format carries " +
                    "no rect origin, so a sub-rectangle cannot be placed"
            )
            return
        }
        // Rare by construction: only when the host's declared geometry actually
        // changes, so this cannot become the load. Logged BEFORE the
        // no-viewer return, because "the new size arrived while nothing was
        // attached" is itself the answer on a trip like Round 2.
        // States the frame's FATE, not merely its arrival. The 2026-08-26
        // Windows trip read the arrival-only form as proof the renderer had the
        // frame; it never was. See FrameGeometryChange.
        val handler = decodeHandler
        FrameGeometryChange.message(
            lastDeclared.getAndSet(width to height),
            width to height,
            sequence,
            viewerAttached = handler != null && target?.get() != null
        )?.let { Log.i(TAG, it) }

        // No viewer attached — nothing to draw, and no worker to draw it with.
        if (handler == null) return

        // Latest wins. A frame still waiting is replaced, never queued behind.
        pending.set(PendingFrame(jpeg, sequence, width, height))
        if (decodeQueued.compareAndSet(false, true)) {
            handler.post(decodeRunnable)
        }
    }

    /**
     * Route frames to [pipeline] and tell Rust a receiver now exists.
     * Call from `SurfaceHolder.Callback.surfaceCreated`, once the surface is
     * valid — not from `onCreate`, where there is no drawable surface yet.
     *
     * The caller retains ownership of [pipeline] and must [SurfaceFramePipeline.stop] it.
     */
    fun attach(pipeline: SurfaceFramePipeline) {
        target = WeakReference(pipeline)
        if (decodeThread == null) {
            val thread = HandlerThread("rd-frame-decode").apply { start() }
            decodeThread = thread
            decodeHandler = Handler(thread.looper)
        }
        RDRust.registerFrameReceiver()
    }

    /**
     * Stop routing frames and release the decode worker.
     * Call from `SurfaceHolder.Callback.surfaceDestroyed`.
     *
     * Safe to call more than once, and safe to call when nothing is attached.
     */
    fun detach() {
        if (target == null && decodeThread == null) return

        RDRust.unregisterFrameReceiver()
        target = null
        pending.set(null)
        lastDeclared.set(null)
        lastDecoded.set(null)

        decodeHandler?.removeCallbacks(decodeRunnable)
        decodeHandler = null
        decodeThread?.quitSafely()
        decodeThread = null
        decodeQueued.set(false)
    }

    /**
     * Decode whatever is pending. Runs on the worker thread.
     *
     * `decodeQueued` is cleared *before* the frame is taken: the other order
     * leaves a window in which a producer sees "already queued", declines to
     * post, and its frame is then stranded by a consumer that has already taken
     * the slot.
     */
    private val decodeRunnable = Runnable {
        decodeQueued.set(false)
        val frame = pending.getAndSet(null) ?: return@Runnable
        decodeAndSubmit(frame)
    }

    private fun decodeAndSubmit(frame: PendingFrame) {
        val bitmap = try {
            BitmapFactory.decodeByteArray(frame.jpeg, 0, frame.jpeg.size)
        } catch (e: OutOfMemoryError) {
            // Drop this frame rather than take the process down with it.
            Log.w(TAG, "frame ${frame.sequence}: out of memory decoding")
            null
        } catch (e: RuntimeException) {
            Log.w(TAG, "frame ${frame.sequence}: decode failed (${e.javaClass.simpleName})")
            null
        }

        // Malformed or truncated network data. Dropped — never replaced with a
        // placeholder, which would show a picture the host never sent.
        if (bitmap == null) {
            Log.w(TAG, "frame ${frame.sequence}: ${frame.jpeg.size} bytes are not a decodable JPEG")
            return
        }

        if (bitmap.width != frame.width || bitmap.height != frame.height) {
            Log.w(
                TAG,
                "frame ${frame.sequence}: decoded ${bitmap.width}x${bitmap.height} " +
                    "but the host declared ${frame.width}x${frame.height}"
            )
            bitmap.recycle()
            return
        }

        // What the JPEG ACTUALLY decoded to, on change. The declared size is
        // already logged on arrival; this proves the pixels agree with it, and
        // together with the renderer's line it closes the gap between "a frame
        // with the new size arrived" and "the new size was drawn".
        FrameGeometryChange.decodedMessage(
            lastDecoded.getAndSet(bitmap.width to bitmap.height),
            bitmap.width to bitmap.height,
            frame.sequence
        )?.let { Log.i(TAG, it) }

        val pipeline = target?.get()
        if (pipeline == null) {
            // Detached between arrival and decode.
            bitmap.recycle()
            return
        }
        // The pipeline takes ownership of the bitmap from here.
        pipeline.submitBitmap(bitmap)
    }
}
