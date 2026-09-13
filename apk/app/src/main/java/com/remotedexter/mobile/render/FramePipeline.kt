package com.remotedexter.mobile.render

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.RectF
import android.os.Handler
import android.os.HandlerThread
import android.view.SurfaceHolder
import com.remotedexter.mobile.render.DesktopCoordinateMapper.RenderGeometry
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean


data class DecodedFrame(
    val width: Int,
    val height: Int,
    val rgba8888: ByteArray,
    val timestampNs: Long = System.nanoTime()
)

class SurfaceFramePipeline(
    private val surfaceHolder: SurfaceHolder,
    private val fpsCap: Int = 60
) {
    private var renderThread: HandlerThread? = null
    private var renderHandler: Handler? = null
    private val started = AtomicBoolean(false)
    private val renderPosted = AtomicBoolean(false)
    private val pendingFrameLock = Any()

    @Volatile
    private var pendingFrame: DecodedFrame? = null

    /**
     * Latest already-decoded bitmap awaiting display — the JPEG transport path.
     *
     * The host streams JPEG and the Rust client deliberately carries no image
     * decoder (`stream_chunk` was split out precisely so the Android `.so` would
     * not inherit one, along with ~85 crates). So the JPEG is decoded on Android
     * and arrives here as a Bitmap, skipping the RGBA8888 copy entirely. The raw
     * [submitFrame] path is untouched and still works.
     *
     * The pipeline takes **ownership** of any bitmap submitted this way and is
     * responsible for recycling it.
     */
    private var pendingBitmap: Bitmap? = null

    @Volatile
    private var lastRenderNs = 0L

    private var reusableBitmap: Bitmap? = null

    /** Last size actually drawn, for the render-side geometry log. */
    private var lastDrawnSize: Pair<Int, Int>? = null

    // ── Zoom & pan (client-side only — no protocol involvement) ──────────
    //
    // Written from the UI thread (MainActivity's ScaleGestureDetector /
    // pan-drag handling), read from this class's own render thread on every
    // frame. Plain @Volatile floats are enough here: each field is read as
    // a single atomic value and a frame that's one gesture-event stale by
    // the time it draws is invisible to the eye at 60fps, so this doesn't
    // need a full lock the way pendingFrame/pendingBitmap do.
    @Volatile private var zoomScale: Float = 1f
    @Volatile private var panOffsetX: Float = 0f
    @Volatile private var panOffsetY: Float = 0f

    /**
     * The geometry of the most recent draw — viewport, frame, zoom and pan as
     * they were at that instant.
     *
     * Touch mapping reads this instead of assembling the same numbers itself.
     * That matters because the parts change independently: a device rotation
     * resizes the viewport at once, while the frame only changes when a host
     * that has itself rotated sends the next one. Anything that samples them
     * separately can invert a rectangle that was never on screen — which is how
     * clicks end up landing near, but not on, what the user touched.
     *
     * Null until the first frame is drawn. Callers must fail closed on null
     * rather than assume a default.
     */
    @Volatile private var lastGeometry: RenderGeometry? = null

    companion object {
        const val MIN_ZOOM = 1f
        const val MAX_ZOOM = 4f
    }

    /**
     * Multiply the current zoom by [scaleFactor] (as reported by
     * `ScaleGestureDetector.OnScaleGestureListener.onScale`'s
     * `scaleFactor`), zooming around ([focusX], [focusY]) in view
     * coordinates — the point under the pinch stays visually stationary,
     * standard pinch-zoom behaviour. Clamped to [MIN_ZOOM]..[MAX_ZOOM].
     * At [MIN_ZOOM] pan is forced back to zero — "zoomed all the way out"
     * should always mean "exactly fit-center", never a stale offset from a
     * previous zoomed-in pan.
     */
    fun applyZoom(scaleFactor: Float, focusX: Float, focusY: Float) {
        val oldScale = zoomScale
        val newScale = (oldScale * scaleFactor).coerceIn(MIN_ZOOM, MAX_ZOOM)
        if (newScale == oldScale) return
        if (newScale == MIN_ZOOM) {
            zoomScale = MIN_ZOOM
            panOffsetX = 0f
            panOffsetY = 0f
            return
        }
        // Keep the focus point stationary: the point (focusX, focusY) maps
        // to the same on-screen location before and after the scale change.
        val ratio = newScale / oldScale
        panOffsetX = focusX - (focusX - panOffsetX) * ratio
        panOffsetY = focusY - (focusY - panOffsetY) * ratio
        zoomScale = newScale
    }

    /** A two-finger pan drag, in view-pixel deltas. No-op at [MIN_ZOOM] — nothing to pan when fully zoomed out. */
    fun applyPan(dx: Float, dy: Float) {
        if (zoomScale <= MIN_ZOOM) return
        panOffsetX += dx
        panOffsetY += dy
    }

    /** Back to fit-center, no zoom, no pan — e.g. a double-tap-to-reset gesture. */
    fun resetZoomPan() {
        zoomScale = MIN_ZOOM
        panOffsetX = 0f
        panOffsetY = 0f
    }

    fun currentZoom(): Float = zoomScale

    /** Geometry of the last drawn frame, or null if nothing has been drawn yet. */
    fun currentGeometry(): RenderGeometry? = lastGeometry

    fun start() {
        if (started.getAndSet(true)) return
        val thread = HandlerThread("SurfaceFramePipeline").apply { start() }
        renderThread = thread
        renderHandler = Handler(thread.looper)
    }

    fun stop() {
        if (!started.getAndSet(false)) return
        val orphan = synchronized(pendingFrameLock) {
            pendingFrame = null
            val b = pendingBitmap
            pendingBitmap = null
            b
        }
        orphan?.takeIf { !it.isRecycled }?.recycle()
        reusableBitmap?.recycle()
        reusableBitmap = null
        renderHandler = null
        renderThread?.quitSafely()
        renderThread = null
        renderPosted.set(false)
        lastRenderNs = 0L
        // A destroyed surface must not leave behind geometry that touch mapping
        // would happily keep inverting.
        lastGeometry = null
    }

    fun submitFrame(frame: DecodedFrame) {
        if (!started.get()) return
        synchronized(pendingFrameLock) {
            pendingFrame = frame
        }
        scheduleRender()
    }

    /**
     * Submit an already-decoded frame. Latest-wins: a bitmap still waiting is
     * recycled and replaced rather than queued behind, so a slow surface can
     * never build a backlog of stale desktops.
     *
     * Takes ownership of [bitmap] — the caller must not touch it afterwards.
     */
    fun submitBitmap(bitmap: Bitmap) {
        if (!started.get()) {
            bitmap.recycle()
            return
        }
        val displaced = synchronized(pendingFrameLock) {
            val old = pendingBitmap
            pendingBitmap = bitmap
            // A newer decoded frame supersedes any pending raw frame.
            pendingFrame = null
            old
        }
        if (displaced !== bitmap) {
            displaced?.takeIf { !it.isRecycled }?.recycle()
        }
        scheduleRender()
    }

    private fun scheduleRender() {
        if (!started.get()) return
        if (!renderPosted.compareAndSet(false, true)) return
        val handler = renderHandler ?: return
        handler.post {
            renderPosted.set(false)
            renderLatestFrame()
            synchronized(pendingFrameLock) {
                if (pendingFrame != null || pendingBitmap != null) {
                    scheduleRender()
                }
            }
        }
    }

    private fun renderLatestFrame() {
        // The decoded-bitmap path takes precedence and needs no pixel copy.
        val ready = synchronized(pendingFrameLock) {
            val b = pendingBitmap
            pendingBitmap = null
            b
        }
        if (ready != null) {
            renderDecodedBitmap(ready)
            return
        }

        val frame = synchronized(pendingFrameLock) {
            val next = pendingFrame
            pendingFrame = null
            next
        } ?: return

        val frameIntervalNs = 1_000_000_000L / fpsCap
        val now = System.nanoTime()
        if (lastRenderNs != 0L && now - lastRenderNs < frameIntervalNs) {
            return
        }
        lastRenderNs = now

        val expectedSize = frame.width * frame.height * 4
        if (frame.rgba8888.size < expectedSize) {
            return
        }

        val bitmap = ensureBitmap(frame.width, frame.height)
        bitmap.copyPixelsFromBuffer(ByteBuffer.wrap(frame.rgba8888, 0, expectedSize))

        val canvas = try {
            surfaceHolder.lockCanvas()
        } catch (_: Throwable) {
            null
        } ?: return

        try {
            drawFixedOrientation(canvas, bitmap)
        } finally {
            surfaceHolder.unlockCanvasAndPost(canvas)
        }
    }

    /**
     * Draw an already-decoded bitmap, then release it. Applies the same fps cap
     * as the raw path; a frame dropped by the cap is recycled rather than
     * leaked, since this pipeline owns it.
     */
    private fun renderDecodedBitmap(bitmap: Bitmap) {
        try {
            if (bitmap.isRecycled) return

            val frameIntervalNs = 1_000_000_000L / fpsCap
            val now = System.nanoTime()
            if (lastRenderNs != 0L && now - lastRenderNs < frameIntervalNs) {
                return
            }
            lastRenderNs = now

            val canvas = try {
                surfaceHolder.lockCanvas()
            } catch (_: Throwable) {
                null
            } ?: return

            try {
                drawFixedOrientation(canvas, bitmap)
            } finally {
                surfaceHolder.unlockCanvasAndPost(canvas)
            }
        } finally {
            if (!bitmap.isRecycled) bitmap.recycle()
        }
    }

    private fun ensureBitmap(width: Int, height: Int): Bitmap {
        val current = reusableBitmap
        if (current != null && current.width == width && current.height == height) {
            return current
        }
        current?.recycle()
        val created = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        reusableBitmap = created
        return created
    }

    /**
     * Draw the frame, and record exactly the geometry it was drawn with.
     *
     * The destination rectangle comes from [DesktopCoordinateMapper], not from
     * arithmetic local to this class. That is the whole point: touch mapping
     * inverts the same function, so the two cannot drift. `fitCenter` and
     * `applyZoomPan` used to live here and were moved there wholesale — at
     * `zoom == 1` with no pan this still produces plain fit-center, the same
     * rectangle as before the cursor-offset feature existed.
     */
    private fun drawFixedOrientation(canvas: Canvas, frameBitmap: Bitmap) {
        canvas.drawColor(Color.BLACK)

        val geometry = RenderGeometry(
            viewportWidth = canvas.width,
            viewportHeight = canvas.height,
            frameWidth = frameBitmap.width,
            frameHeight = frameBitmap.height,
            zoom = zoomScale,
            panX = panOffsetX,
            panY = panOffsetY
        )
        // The only line that proves PIXELS changed. A frame can arrive, decode,
        // and still never be drawn at its new size; without this the log cannot
        // tell that apart from a renderer that drew it correctly.
        com.remotedexter.FrameGeometryChange.renderedMessage(
            lastDrawnSize,
            frameBitmap.width to frameBitmap.height
        )?.let { android.util.Log.i("RDFramePipeline", it) }
        lastDrawnSize = frameBitmap.width to frameBitmap.height

        val rect = DesktopCoordinateMapper.destinationRect(geometry)
        if (rect == null) {
            // Nothing sensible to draw. Leave the surface black and publish no
            // geometry, so touch mapping refuses rather than guessing.
            lastGeometry = null
            return
        }

        // RectF (not Rect) because a pinch-zoomed rect rarely lands on an
        // integer pixel boundary; drawBitmap has a dst-as-RectF overload for
        // exactly this.
        canvas.drawBitmap(
            frameBitmap,
            null,
            RectF(rect.left, rect.top, rect.right, rect.bottom),
            null
        )
        lastGeometry = geometry
    }
}
