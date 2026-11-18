package com.remotedexter

import com.remotedexter.mobile.render.Scaling
import com.remotedexter.mobile.render.ScalingMode
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.widget.Button
import android.view.MotionEvent
import android.view.View
import android.widget.ImageButton
import android.widget.RelativeLayout
import android.widget.SeekBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.remotedexter.bootstrap18.QrScanActivity
import com.remotedexter.mobile.render.DesktopCoordinateMapper
import com.remotedexter.mobile.render.SurfaceFramePipeline

class MainActivity : AppCompatActivity() {

    /** The remote desktop surface. */
    private lateinit var desktopSurface: SurfaceView

    /** Toggles [InputController]; label kept truthful via onControlStateChanged. */
    private lateinit var btnToggleControl: Button

    /** Live link state, driven by [SessionOrchestrator.onPhaseChanged]. */
    private lateinit var linkIndicator: TextView

    /** Explicit session teardown; Back only backgrounds the live viewer. */
    private lateinit var btnDisconnect: Button
    private lateinit var btnConnect: Button
    private lateinit var btnKeyboard: ImageButton
    private lateinit var btnPointerMode: ImageButton
    private val pointerRouter = PointerModeRouter()

    /**
     * Touch by default: it is the obvious behaviour, and a user who has not
     * chosen a mode should get the one that needs no explanation.
     */
    private var pointerMode = PointerMode.Touch

    /** Fit until the user asks otherwise: the whole desktop is the safe default. */
    private var scalingMode = ScalingMode.Fit

    /** How far above the fingertip the real host cursor sits, in dp. */

    /**
     * Current cursor lift in dp. Mirrored here so the touch path reads a plain
     * field rather than touching a View from the gesture callbacks.
     */
    @Volatile private var cursorLiftDp: Int = 0

    /**
     * Turns the surface's touch stream into intent. The routing itself lives in
     * [SurfaceTouchRouter] so it can be driven by real MotionEvents in an
     * instrumentation test without a session or the JNI bridge; this object is
     * the shipped destination for those calls.
     */
    private val gestures = object : SurfaceGestures {
        override fun onTouchAt(viewX: Float, viewY: Float, eventTimeMs: Long) {
            // Which of the two proven paths this becomes is [PointerModeRouter]'s
            // decision, kept out of here so the state that trackpad mode needs
            // — the previous point — is testable without a device.
            when (val move = pointerRouter.onMove(pointerMode, viewX, viewY)) {
                is PointerMove.Absolute -> {
                    val p = mapTouch(move.viewX, move.viewY) ?: return
                    InputController.onAbsoluteMove(p)
                }
                // Relative deltas are in VIEW pixels and are sent as-is. They
                // are deliberately NOT scaled by the current zoom: a trackpad's
                // whole appeal is that a small finger movement is a small
                // cursor movement, and dividing by a 3x zoom would make it
                // three times harder to cross the desktop at exactly the moment
                // the user zoomed in to be precise.
                is PointerMove.Relative ->
                    InputController.onDrag(move.dx, move.dy, eventTimeMs)
                null -> Unit
            }
        }

        override fun onTap(viewX: Float, viewY: Float) {
            val p = mapTouch(viewX, viewY) ?: return
            InputController.onTapAt(p)
        }

        override fun onLongPress(viewX: Float, viewY: Float) {
            val p = mapTouch(viewX, viewY) ?: return
            InputController.onLongPressAt(p)
        }

        override fun onGestureEnd(eventTimeMs: Long) {
            // Forgetting the reference point is what stops the next gesture
            // measuring its first sample against where this one ended.
            pointerRouter.onGestureEnd()
            InputController.onGestureEnd(eventTimeMs)
        }

        /**
         * Double-tap toggles fit and original.
         *
         * The plan asks for both scalings. They go on the double-tap rather
         * than a sixth toolbar button because that row is already at the width
         * its labels need — proven twice, once by "CONN/ECT" and once by
         * "Trackpad" — and because toggling zoom is exactly what a double-tap
         * means everywhere else.
         *
         * Falls back to a plain reset whenever the geometry cannot answer the
         * question, so a double-tap before the first frame still does the
         * obvious thing instead of nothing.
         */
        override fun onResetZoomPan() {
            val pipe = pipeline ?: return
            val g = pipe.currentGeometry()
            if (g == null || !g.isUsable()) {
                pipe.resetZoomPan()
                return
            }
            scalingMode = scalingMode.next()
            if (scalingMode == ScalingMode.Fit) {
                pipe.resetZoomPan()
                return
            }
            val target = Scaling.originalZoom(
                g.viewportWidth,
                g.viewportHeight,
                g.frameWidth,
                g.frameHeight,
                SurfaceFramePipeline.MAX_ZOOM
            )
            val factor = target?.let { Scaling.factorToReach(it, g.zoom) }
            if (factor == null) {
                // The geometry said yes and the arithmetic said no. Leave the
                // view alone rather than applying a factor we do not trust, and
                // put the mode back so the next tap is not a no-op too.
                scalingMode = scalingMode.next()
                pipe.resetZoomPan()
                return
            }
            // Around the view centre: a double-tap has no meaningful focus
            // point of its own, and centring keeps whatever was in the middle
            // of the screen in the middle of the screen.
            pipe.applyZoom(factor, g.viewportWidth / 2f, g.viewportHeight / 2f)
        }

        override fun onZoomPan(
            scaleFactor: Float,
            focusX: Float,
            focusY: Float,
            panDx: Float,
            panDy: Float
        ) {
            val p = pipeline ?: return
            // Two fingers move the view. In all directions, at every zoom, with
            // no second meaning — the operator's decision after the zoom-gated
            // split left scrolling unreachable whenever they were zoomed in,
            // which the landscape layout made almost always. Scrolling the host
            // is the ▲/▼ pair instead, aimed by the cursor exactly as a mouse
            // wheel is.
            //
            // The pinch still has to pass a deadzone before it moves the zoom,
            // or the finger-span jitter of an ordinary drag zooms the picture
            // while the operator is trying to slide it.
            twoFinger.onSample(scaleFactor)?.let { p.applyZoom(it, focusX, focusY) }
            p.applyPan(panDx, panDy)
        }

        override fun onTwoFingerTap(viewX: Float, viewY: Float) {
            val p = mapTouch(viewX, viewY) ?: return
            InputController.onSecondaryTapAt(p)
        }

        override fun onTwoFingerGestureEnd() {
            twoFinger.onGestureEnd()
        }
    }

    /** Keeps a two-finger drag's jitter from zooming the view. */
    private val twoFinger = TwoFingerGesture()

    private val touchRouter by lazy { SurfaceTouchRouter(this, gestures) }

    /**
     * Fingertip -> negotiated surface position, lifted by the slider.
     *
     * Fails closed. If no frame has been drawn yet, or the surface was
     * destroyed, or the geometry is degenerate, this returns null and the
     * caller sends nothing — a remote-control client that invents a coordinate
     * when it does not know where the frame is will click *something*, and
     * clicking nothing is the correct behaviour.
     */
    private fun mapTouch(viewX: Float, viewY: Float): PointerPosition? {
        val space = SessionOrchestrator.currentPointerCoordinateSpace() ?: return null
        val geometry = pipeline?.currentGeometry() ?: return null
        val offsetPx = DesktopCoordinateMapper.dpToPx(cursorLiftDp, resources.displayMetrics.density)
        val point = when (space) {
            PointerCoordinateSpace.DESKTOP_PIXELS ->
                DesktopCoordinateMapper.mapTouchToDesktop(geometry, viewX, viewY, offsetPx)
            PointerCoordinateSpace.NORMALIZED_V1 ->
                DesktopCoordinateMapper.mapTouchToNormalized(geometry, viewX, viewY, offsetPx)
        } ?: return null
        return PointerPosition(point.x, point.y, space)
    }

    /**
     * Visible to instrumentation on purpose. The persistence round trip is a
     * real product behaviour — a client preference that must outlive the
     * Activity — and the only honest way to test it is to drive the same two
     * functions the UI drives.
     */
    /**
     * Re-read the cursor lift.
     *
     * Called from [onResume] because Settings can change it while this screen
     * is in the back stack. Without that, a change made in Settings would not
     * take effect until the app was restarted — and the user, having just
     * moved the slider, would reasonably conclude it did nothing.
     */
    private fun refreshCursorLift() {
        cursorLiftDp = CursorLift.load(this)
    }

    companion object {
        /**
         * How faint an unavailable icon is drawn, out of 255.
         *
         * 77 is 30%, the framework's own disabled alpha for light themes, so a
         * dim icon sits at the same weight as the dim text on the row below it.
         */
        const val DISABLED_ICON_ALPHA = 77

        private const val PREFS = "remotedexter.ui"
        private const val KEY_CURSOR_LIFT = "cursor_lift_dp"

        /**
         * Lines the compose field grows to before it scrolls. Enough to read a
         * few sentences back; few enough that the desktop stays visible above.
         */
        const val COMPOSE_MAX_LINES = 4
    }

    /** The operator-facing sentence for text the host handed back. */
    private fun describeReturn(reason: String, returned: PendingTexts.Returned, max: Int?): String =
        when (val k = TextReturn.kind(reason, returned, max)) {
            is TextReturn.Kind.Untypable -> getString(R.string.text_returned_untypable, k.label)
            is TextReturn.Kind.TooLong ->
                if (k.max != null) getString(R.string.text_returned_too_long, k.max)
                else getString(R.string.text_returned_too_long_unknown)
            is TextReturn.Kind.StoppedPartway ->
                getString(R.string.text_returned_partway, k.typed, k.composed, k.reason)
            is TextReturn.Kind.EnterNotPressed -> getString(R.string.text_returned_before_enter, k.reason)
            is TextReturn.Kind.NotTyped -> getString(R.string.text_returned_not_typed, k.reason)
        }

    /**
     * Owns the render pipeline for the lifetime of the surface.
     *
     * The Activity holds this strongly; [FrameReceiver] only borrows it weakly,
     * so a missed detach cannot leak the Activity.
     */
    private var pipeline: SurfaceFramePipeline? = null

    /**
     * Frames are routed only while there is a real, drawable surface — which is
     * a narrower window than the Activity being started. Binding to the surface
     * callbacks rather than `onStart`/`onStop` means we never hand the pipeline
     * a `SurfaceHolder` whose `lockCanvas` would fail, and rotation tears down
     * and rebuilds cleanly.
     */
    private val surfaceCallback = object : SurfaceHolder.Callback {
        override fun surfaceCreated(holder: SurfaceHolder) {
            val created = SurfaceFramePipeline(holder)
            created.start()
            pipeline = created
            FrameReceiver.attach(created)
        }

        override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
            // The pipeline reads the canvas size on each draw, so a resize needs
            // no action here.
        }

        override fun surfaceDestroyed(holder: SurfaceHolder) {
            // Detach first: no frame may be submitted to a dead surface.
            FrameReceiver.detach()
            pipeline?.stop()
            pipeline = null
            // A dead surface means no session to control either — never let
            // "control enabled" silently survive past the stream it applied to.
            InputController.reset()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Before any content: this window shows the host's desktop.
        SecureWindow.apply(this)
        setContentView(R.layout.activity_main)

        // The title bar spends 168px saying the app's name on a screen whose
        // entire purpose is the picture, and txtSessionState already carries
        // the only status worth reading. Reclaiming it is what lets the control
        // panel fit: the panel wants about 600px, and it was overflowing the
        // window by ~110 — which is why the bottom row was measured 40px tall
        // on the SM-G970U instead of 144, with the scroll buttons clipped. That
        // overflow predates the scroll row; the original control row ran past
        // the window bottom too, and it went unnoticed because a button that is
        // 40px short still looks like a button.
        //
        // In landscape it matters more than anywhere: it is 168 of 1080.
        supportActionBar?.hide()

        applyOrientation(resources.configuration.orientation)
        // Upright, the panel is re-fitted to its rows after every layout, so a
        // row that grows can never push the scroll pair out. See fitPortraitPanel.
        val panelInner = findViewById<View>(R.id.controlsPanelInner)
        panelInner.viewTreeObserver.addOnGlobalLayoutListener {
            if (resources.configuration.orientation !=
                android.content.res.Configuration.ORIENTATION_LANDSCAPE
            ) {
                fitPortraitPanel(panelInner)
            }
        }

        desktopSurface = findViewById(R.id.desktopSurface)
        desktopSurface.holder.addCallback(surfaceCallback)

        // Split by finger count: one finger drives the remote cursor (and
        // only when InputController.isControlEnabled() — before "Enable
        // Control" is tapped, a touch on the surface does nothing, same as
        // before this feature existed); two fingers navigate the view
        // (zoom/pan), always available regardless of control state — you
        // can look around a stream you're only viewing, because view
        // navigation is entirely client-side and sends nothing to the host.
        // The finger-count split and gesture-end routing live in SurfaceTouchRouter.
        desktopSurface.setOnTouchListener { _, event -> touchRouter.onTouch(event) }

        refreshCursorLift()
        findViewById<Button>(R.id.btnSettings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        btnToggleControl = findViewById(R.id.btnToggleControl)
        btnDisconnect = findViewById(R.id.btnDisconnect)
        btnConnect = findViewById(R.id.btnConnect)
        btnKeyboard = findViewById(R.id.btnKeyboard)
        btnPointerMode = findViewById(R.id.btnPointerMode)
        renderPointerMode()
        btnPointerMode.setOnClickListener {
            pointerMode = pointerMode.next()
            // The reference point belongs to the old mode's gesture. Keeping it
            // would make the first sample after a switch a delta measured from
            // wherever the finger last was under the other mode.
            pointerRouter.onGestureEnd()
            renderPointerMode()
        }
        linkIndicator = findViewById(R.id.linkIndicator)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                moveTaskToBack(true)
            }
        })

        // Truthful by construction: driven by the orchestrator's own phase, not
        // by whether a frame happened to arrive recently.
        SessionOrchestrator.onPhaseChanged = { linked, phaseName ->
            runOnUiThread {
                linkIndicator.setText(if (linked) R.string.link_active else R.string.link_idle)
                RdxLog.i("MainActivity", "link indicator → $phaseName")
            }
        }

        InputController.reset()
        InputController.onControlStateChanged = { enabled ->
            runOnUiThread {
                // Label always names the ACTION tapping performs next, not
                // the current state — so "enabled" (controlling) shows the
                // string that turns it back off, and vice versa.
                btnToggleControl.setText(
                    if (enabled) R.string.disable else R.string.enable
                )
                Toast.makeText(
                    this,
                    if (enabled) "Control enabled" else "Viewing only",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
        // A refused grant changes no state, so it would otherwise be invisible:
        // the button simply would not respond. The host's reason names the
        // cause — e.g. that input injection is not enabled for this run.
        InputController.onControlDenied = { _, reason ->
            runOnUiThread {
                Toast.makeText(
                    this,
                    getString(R.string.control_denied, reason),
                    Toast.LENGTH_LONG
                ).show()
            }
        }
        btnToggleControl.setOnClickListener {
            if (InputController.isControlEnabled()) {
                InputController.requestDisable()
            } else {
                InputController.requestEnable()
            }
        }
        btnDisconnect.setOnClickListener {
            startService(Intent(this, RDService::class.java).apply {
                action = PendingConnects.ACTION_DISCONNECT
            })
        }

        // ── NOTHING IS STARTED HERE ──────────────────────────────────────
        //
        // This used to call startForegroundService() unconditionally and then
        // immediately fire ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS. Opening
        // the app therefore started a sticky foreground service, took a
        // PARTIAL_WAKE_LOCK for the life of the process, and asked for a
        // battery exemption — all before the user had chosen to connect to
        // anything, and all while the manifest claimed in prose that the app
        // "does NOT run when the user has not opened it".
        //
        // The service now starts only from an explicit connection action, and
        // the battery exemption is an optional settings action with an
        // explanation. ColdLaunchTest holds both of these on a real device.
        check(!ServicePolicy.shouldRequestBatteryExemptionOnLaunch()) {
            "ServicePolicy says a launch-time battery prompt is allowed; it must never be"
        }
        observeSessionState()

        // Button wiring
        wireKeyboard()

        btnConnect.setOnClickListener {
            // The service owns the session's lifetime, exactly as on the QR
            // path: a connection started straight from the Activity would die
            // with it the first time the screen locked.
            startService(Intent(this, RDService::class.java).apply {
                action = PendingConnects.ACTION_RECONNECT
            })
        }

        wireChord(R.id.btnPasteChord, KeyChord.Chord.Paste)
        wireChord(R.id.btnCopyChord, KeyChord.Chord.Copy)
        wireChord(R.id.btnPrintScreen, KeyChord.Chord.PrintScreen)
        wireClipboardBridge()

        findViewById<ImageButton>(R.id.btnPair).setOnClickListener {
            startActivity(Intent(this, QrScanActivity::class.java))
        }

        findViewById<ImageButton>(R.id.btnDiagnostics).setOnClickListener {
            startActivity(Intent(this, DiagnosticsActivity::class.java))
        }

        // Positive is up, matching the wheel: `ScrollGesture` chose that sign
        // and `inject_linux` puts it straight onto REL_WHEEL.
        wireScrollButton(findViewById(R.id.btnScrollUp), dy = 1)
        wireScrollButton(findViewById(R.id.btnScrollDown), dy = -1)
    }

    /**
     * Re-arrange for the current orientation.
     *
     * ## Why this is code and not a `layout-land` resource
     *
     * The activity declares
     * `configChanges="orientation|screenSize|smallestScreenSize|screenLayout|
     * keyboardHidden"`, so Android hands it the rotation and **never re-inflates
     * the layout**. A `res/layout-land/` file is therefore dead weight: it is
     * consulted only if the activity happens to be created while already
     * sideways, and never when the phone is turned. One was written and deleted
     * after the emulator proved it: rotated to 2340x1080, the surface still
     * measured 2204x279.
     *
     * Rearranging the views we already have is also the better answer on its
     * own merits. Re-inflating would destroy the SurfaceView, and with it the
     * render pipeline and the picture, every time the phone is turned — which
     * is presumably why `configChanges` was set in the first place.
     *
     * ## What it fixes
     *
     * Held sideways with the controls beneath it, the desktop was measured on
     * the operator's SM-G970U at **1904x256 — a quarter of the screen** — and a
     * 16:9 desktop fitted into that is a 455px-wide postage stamp. Unreadable,
     * so they pinched to zoom; being zoomed is what turned the two-finger drag
     * into a pan; and that is why nothing scrolled in any application. One
     * missing arrangement produced a bug report about scrolling.
     *
     * Beside it instead of beneath it, because the shape of the problem is
     * width: a 19.5:9 phone held sideways has width to spare and no height.
     */
    private fun applyOrientation(orientation: Int) {
        val landscape = orientation == android.content.res.Configuration.ORIENTATION_LANDSCAPE
        val panel = findViewById<View>(R.id.controlsPanel)
        val status = findViewById<View>(R.id.txtSessionState)
        val compose = findViewById<View>(R.id.composeRow)
        val surface = findViewById<View>(R.id.desktopSurface)

        val rules = intArrayOf(
            RelativeLayout.ALIGN_PARENT_TOP,
            RelativeLayout.ALIGN_PARENT_BOTTOM,
            RelativeLayout.ALIGN_PARENT_START,
            RelativeLayout.ALIGN_PARENT_END,
            RelativeLayout.START_OF,
            RelativeLayout.BELOW,
            RelativeLayout.ABOVE
        )
        val params = listOf(panel, status, compose, surface)
            .map { it to it.layoutParams as RelativeLayout.LayoutParams }
        // Cleared before anything is set: these are re-applied on every
        // rotation, and a rule left over from the other orientation is how a
        // view ends up anchored to two things at once.
        for ((_, lp) in params) {
            for (r in rules) lp.removeRule(r)
        }
        val (_, panelLp) = params[0]
        val (_, statusLp) = params[1]
        val (_, composeLp) = params[2]
        val (_, surfaceLp) = params[3]

        reflowPanel(landscape)

        // The panel's own height is pinned to @dimen/controls_panel_height,
        // which is portrait's four rows. Landscape has SIX — the two crowded
        // rows gained a second line — and it has the height to spare, so it
        // fills the column instead. Left at the portrait figure, Disconnect and
        // Settings measured 15px tall and the scroll arrows fell off the
        // bottom entirely.
        val inner = findViewById<View>(R.id.controlsPanelInner)
        inner.layoutParams = inner.layoutParams.apply {
            height = if (landscape) {
                android.view.ViewGroup.LayoutParams.MATCH_PARENT
            } else {
                resources.getDimensionPixelSize(R.dimen.controls_panel_height)
            }
        }

        if (landscape) {
            panelLp.width = resources.getDimensionPixelSize(R.dimen.controls_panel_width)
            panelLp.height = RelativeLayout.LayoutParams.MATCH_PARENT
            panelLp.addRule(RelativeLayout.ALIGN_PARENT_END)
            panelLp.addRule(RelativeLayout.ALIGN_PARENT_TOP)
            panelLp.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM)

            statusLp.addRule(RelativeLayout.ALIGN_PARENT_TOP)
            statusLp.addRule(RelativeLayout.ALIGN_PARENT_START)
            statusLp.addRule(RelativeLayout.START_OF, R.id.controlsPanel)

            composeLp.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM)
            composeLp.addRule(RelativeLayout.ALIGN_PARENT_START)
            composeLp.addRule(RelativeLayout.START_OF, R.id.controlsPanel)

            surfaceLp.addRule(RelativeLayout.BELOW, R.id.txtSessionState)
            surfaceLp.addRule(RelativeLayout.ABOVE, R.id.composeRow)
            surfaceLp.addRule(RelativeLayout.ALIGN_PARENT_START)
            surfaceLp.addRule(RelativeLayout.START_OF, R.id.controlsPanel)
        } else {
            panelLp.width = RelativeLayout.LayoutParams.MATCH_PARENT
            panelLp.height = RelativeLayout.LayoutParams.WRAP_CONTENT
            panelLp.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM)

            statusLp.addRule(RelativeLayout.ALIGN_PARENT_TOP)

            composeLp.addRule(RelativeLayout.ABOVE, R.id.controlsPanel)

            surfaceLp.addRule(RelativeLayout.BELOW, R.id.txtSessionState)
            surfaceLp.addRule(RelativeLayout.ABOVE, R.id.composeRow)
        }
        for ((v, lp) in params) v.layoutParams = lp
    }

    /**
     * Give the upright panel exactly the height its rows need, measured.
     *
     * The panel is the last thing on the screen and the scroll pair is its last
     * row, so whatever the rows need beyond the panel's height comes out of the
     * scroll pair — and with two fingers always panning (f42210e), those two
     * buttons are the operator's ONLY way to scroll.
     *
     * The height was pinned by arithmetic, `controls_panel_height`, because
     * `wrap_content` let the parent squeeze the panel (see dimens.xml). The
     * arithmetic was short: it never counted the chord row's padding, so the
     * rows needed 557px of the 550 given on a 440dpi screen — measured
     * 2026-09-18 after the operator reported the scroll pair missing. Measuring
     * keeps the height explicit, so the old squeeze cannot come back, and makes
     * it follow the content, so a row that grows — a label, a larger font, a
     * state line — grows the panel instead of pushing the pair off the screen.
     *
     * Called after every layout. It only writes when the need changed, so it
     * settles in one extra pass.
     */
    private fun fitPortraitPanel(inner: View) {
        val width = inner.width
        if (width <= 0) return
        inner.measure(
            View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        )
        val needed = inner.measuredHeight
        val lp = inner.layoutParams
        if (needed > 0 && lp.height != needed) {
            lp.height = needed
            inner.layoutParams = lp
        }
    }

    /** Where a movable button lives in portrait, so it can be put back. */
    private data class PanelHome(val parent: android.widget.LinearLayout, val index: Int)

    private val panelHomes = mutableMapOf<Int, PanelHome>()

    /**
     * Re-flow the control column for the orientation.
     *
     * ## Why the column was half the screen
     *
     * The operator: *"when i turn it sideways the button pannel takes 50% of
     * the screen (entire right side)"*. It did, and the cause is one row: on
     * their SM-G970U, ENABLE + CONNECT + DISCONNECT + Settings measure 1019px —
     * 340dp — in a single line, and the column can be no narrower than its
     * widest row. Nothing could be trimmed without clipping labels that took
     * two attempts to make fit.
     *
     * So the crowded rows get a second line in landscape, and the column drops
     * to 200dp: about 28% of the screen instead of 50%.
     *
     * ## Moved, not re-created
     *
     * `removeView` + `addView` keeps the same view objects, so the click and
     * touch listeners bound in `onCreate` survive a rotation with nothing to
     * rebind. That is the whole reason this is done here rather than by
     * inflating a second panel layout: fifteen views the operator had just
     * signed off would have needed rebinding, and a missed one is a button that
     * silently stops working.
     */
    private fun reflowPanel(landscape: Boolean) {
        val chordRow2 = findViewById<android.widget.LinearLayout>(R.id.chordRow2)
        val controlRow2 = findViewById<android.widget.LinearLayout>(R.id.controlRow2)
        val moves = listOf(
            findViewById<View>(R.id.btnClipToHost) to chordRow2,
            findViewById<View>(R.id.btnClipFromHost) to chordRow2,
            findViewById<View>(R.id.btnDisconnect) to controlRow2,
            findViewById<View>(R.id.btnSettings) to controlRow2
        )
        // Recorded once, from the layout as inflated, which is portrait's
        // arrangement by construction.
        for ((view, _) in moves) {
            val parent = view.parent as android.widget.LinearLayout
            panelHomes.getOrPut(view.id) { PanelHome(parent, parent.indexOfChild(view)) }
        }
        if (landscape) {
            for ((view, target) in moves) {
                if (view.parent === target) continue
                (view.parent as android.view.ViewGroup).removeView(view)
                target.addView(view)
            }
        } else {
            // Order-independent. Each view goes back at its recorded index,
            // clamped to the row's current size — so a view restored "too
            // early" lands at the end and is pushed into place by the one that
            // follows it. Tried it both ways on the device and the arrangement
            // is identical, so there is no ordering rule here to get wrong.
            for ((view, _) in moves) {
                val home = panelHomes[view.id] ?: continue
                if (view.parent === home.parent) continue
                (view.parent as android.view.ViewGroup).removeView(view)
                home.parent.addView(view, home.index.coerceAtMost(home.parent.childCount))
            }
        }
        val extras = if (landscape) View.VISIBLE else View.GONE
        chordRow2.visibility = extras
        controlRow2.visibility = extras
    }

    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        applyOrientation(newConfig.orientation)
    }

    /** Posts the repeats for a held scroll button. Main looper: it only sends. */
    private val scrollHandler = android.os.Handler(android.os.Looper.getMainLooper())

    /**
     * A wheel button: one notch on a tap, and a steady spin while held.
     *
     * The host delivers the wheel to whatever is under the pointer, which is
     * the whole point — *"cursor over scroll target then scroll up or down
     * gives the desired result"*. No window targeting is attempted here.
     *
     * The click listener is what actually sends a single notch, so an
     * accessibility activation scrolls exactly like a tap does; the touch
     * listener only owns the REPEAT. It returns false throughout, leaving the
     * ordinary click path intact rather than reimplementing it — and a press
     * that has already repeated suppresses the trailing click, or letting go
     * after a long hold would add one notch nobody asked for.
     */
    private fun wireScrollButton(button: ImageButton, dy: Int) {
        var repeated = false
        val repeat = object : Runnable {
            override fun run() {
                // A refusal means control is off or the session is gone. Stop
                // rather than reschedule: a button that keeps firing into a
                // closed session is a log flood with a battery cost.
                if (!InputController.scroll(0, dy)) return
                repeated = true
                scrollHandler.postDelayed(this, ScrollRepeat.REPEAT_INTERVAL_MS)
            }
        }
        button.setOnClickListener { if (!repeated) InputController.scroll(0, dy) }
        button.setOnTouchListener { _, ev ->
            when (ev.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    repeated = false
                    scrollHandler.postDelayed(repeat, ScrollRepeat.INITIAL_DELAY_MS)
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL ->
                    scrollHandler.removeCallbacks(repeat)
            }
            false
        }
    }

    /**
     * Wire the compose bar to the host.
     *
     * Composed, not live. The field holds what you type until you commit it, so
     * a typo is fixed here rather than in a remote shell. Live per-keystroke
     * typing was the first attempt and the operator's verdict was "its a blind
     * send": a 1dp field that cleared itself after every character gave nothing
     * to read and no chance to correct.
     *
     * Every decision below is [KeyboardInput]'s, so the rules are proven on the
     * JVM rather than eyeballed on a device — including the one that matters,
     * that nothing is sent unless control is granted.
     */
    private fun wireKeyboard() {
        val sink = findViewById<android.widget.EditText>(R.id.keyboardSink)
        val row = findViewById<android.view.View>(R.id.composeRow)

        // Two controls, two meanings — and they must NOT be the same act.
        //
        // They were: both sent the line with a trailing Enter, so there was no
        // way to put text into a field on the host without submitting it. No
        // filling in a username, no typing a search term you then want to edit.
        // The operator's words: "enter is send and send is enter".
        //
        //   Type  -> the text lands in whatever has focus, and stops there.
        //   Enter -> the text lands AND is submitted.
        // A paragraph has to be READABLE before it is sent — that is the whole
        // point of composing (RD-TEXT-1). The field stays a single-line INPUT,
        // so the keyboard's action key is still Go rather than a newline, but
        // it wraps onto a few lines instead of scrolling sideways out of sight.
        // Set here, not in the layout: a single-line input type forces one
        // horizontally scrolling line while the view is inflated, and these
        // two calls are what undo that after it.
        sink.setHorizontallyScrolling(false)
        sink.maxLines = COMPOSE_MAX_LINES

        fun send(submit: Boolean) {
            val buffer = sink.text?.toString() ?: ""
            val sent =
                if (submit) InputController.commitText(buffer)
                else InputController.stageText(buffer)
            // Cleared only when the run was actually queued. Clearing on a
            // refusal — no control, too long, a session that would not take
            // it — would throw away what the user typed and leave them nothing
            // to retry with.
            if (sent.clearsField) {
                sink.setText("")
                return
            }
            val message = when (sent) {
                TextSend.NotQueued -> getString(R.string.keyboard_not_queued)
                is TextSend.Refused -> when (val a = sent.action) {
                    is KeyboardInput.Action.TooLong ->
                        getString(R.string.keyboard_too_long, a.length, a.max)
                    is KeyboardInput.Action.TooLargeToSend ->
                        getString(R.string.keyboard_too_large, a.bytes, a.max)
                    // "nothing typed" is a button pressed on an empty field and
                    // needs no announcement.
                    is KeyboardInput.Action.Drop ->
                        if (a.why == "nothing typed") null
                        else getString(R.string.keyboard_needs_control)
                    else -> null
                }
                TextSend.Queued -> null
            }
            message?.let { Toast.makeText(this, it, Toast.LENGTH_LONG).show() }
        }

        // The host refused or stopped a run this phone sent. Whatever did not
        // reach the desktop goes back into the field — IN FRONT of anything
        // typed since, because it came first — and the operator is told why.
        InputController.onTextReturned = { reason, returned, max ->
            runOnUiThread {
                if (returned.untyped.isNotEmpty()) {
                    val since = sink.text?.toString() ?: ""
                    sink.setText(returned.untyped + since)
                    sink.setSelection(sink.text?.length ?: 0)
                }
                Toast.makeText(this, describeReturn(reason, returned, max), Toast.LENGTH_LONG).show()
            }
        }

        sink.setOnEditorActionListener { _, _, _ ->
            send(submit = true)
            true
        }
        findViewById<Button>(R.id.btnSendText).setOnClickListener { send(submit = false) }

        // Backspace on an EMPTY field reaches the host. While there is text it
        // is a local edit and this listener declines it, which is the whole
        // point of composing — but once the field is empty there is nothing
        // local left to delete, and a remote Backspace is the only way to
        // remove text on the host that was never typed here.
        sink.setOnKeyListener { _, keyCode, event ->
            if (keyCode == android.view.KeyEvent.KEYCODE_DEL &&
                event.action == android.view.KeyEvent.ACTION_DOWN
            ) {
                InputController.backspace(sink.text?.toString() ?: "") is KeyboardInput.Action.SendKey
            } else {
                false
            }
        }

        btnKeyboard.setOnClickListener {
            if (!InputController.isControlEnabled()) {
                // Said on a deliberate press rather than logged: the user asked
                // for a keyboard and the remedy — Enable Control — is theirs.
                Toast.makeText(this, R.string.keyboard_needs_control, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            val showing = row.visibility == android.view.View.VISIBLE
            row.visibility = if (showing) android.view.View.GONE else android.view.View.VISIBLE
            val imm = getSystemService(Context.INPUT_METHOD_SERVICE)
                as android.view.inputmethod.InputMethodManager
            if (showing) {
                imm.hideSoftInputFromWindow(sink.windowToken, 0)
            } else {
                // POSTED, not called here. The operator's report was "have to
                // click keyboard button 2x to get it to open", and this is why:
                // the row's visibility had only just been SET, so the field was
                // not yet through a layout pass and was not in the focus
                // hierarchy. `requestFocus` on it returns false and
                // `showSoftInput` on an unfocused view does nothing — the row
                // appeared and no keyboard came with it. Pressing again toggled
                // it shut, and the press after that found a field that HAD been
                // laid out once, so it worked. A control that needs to be used
                // wrong once before it works right is worse than one that fails.
                //
                // `post` runs this after the layout pass the visibility change
                // schedules, which is the earliest moment the field can take
                // focus.
                sink.post {
                    if (sink.requestFocus()) {
                        imm.showSoftInput(
                            sink,
                            android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT
                        )
                    } else {
                        // Said out loud rather than silently leaving an open row
                        // with no keyboard, which is the state the defect
                        // produced and which looks identical to a broken app.
                        RdxLog.w("MainActivity", "the compose field would not take focus; no keyboard shown")
                    }
                }
            }
        }
    }

    /**
     * One chord button: Ctrl+C, Ctrl+V or Print Screen.
     *
     * **Left enabled in every state, and it answers when it cannot act.** The
     * alternative was tried and the operator hit it: a disabled button swallows
     * the tap entirely — no ripple, no haptic, the listener never runs — so the
     * dead `PrtScr` icon was indistinguishable from a broken app, and the only
     * thing that responded was the long-press tooltip. A refusal the user
     * cannot see is indistinguishable from a bug, which is the whole reason
     * Block 5 made every refusal visible.
     *
     * So the button always responds. When it cannot send, it says which of the
     * two things is missing, because "turn on control" and "connect first" send
     * the user to different places.
     */
    private fun wireChord(viewId: Int, chord: KeyChord.Chord) {
        findViewById<Button>(viewId).setOnClickListener {
            val action = InputController.pressChord(chord)
            if (action is KeyChord.Action.Drop) {
                Toast.makeText(
                    this,
                    if (!InputController.isControlEnabled()) R.string.chord_needs_control
                    else R.string.chord_needs_session,
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    /**
     * The two buttons that carry text between this phone's clipboard and the
     * host's.
     *
     * Reading the phone's clipboard needs an Activity in the foreground —
     * Android refuses it to a background app outright — which is why this lives
     * here and why the transfer is a button press rather than a sync. The safe
     * design and the possible one agree.
     *
     * **No clipboard text is ever logged**, and none is put into a Toast: the
     * messages say that a transfer happened, never what moved.
     */
    private fun wireClipboardBridge() {
        val manager = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

        findViewById<Button>(R.id.btnClipToHost).apply {
            contentDescription = getString(R.string.clip_to_host_description)
            setOnClickListener {
                val text = manager.primaryClip
                    ?.takeIf { it.itemCount > 0 }
                    ?.getItemAt(0)
                    ?.coerceToText(this@MainActivity)
                    ?.toString()
                when (val action = InputController.pushClipboard(text)) {
                    is ClipboardBridge.Action.Push -> toast(R.string.clip_sent)
                    is ClipboardBridge.Action.Drop -> toast(reasonFor(action.why))
                    else -> Unit
                }
            }
        }

        findViewById<Button>(R.id.btnClipFromHost).apply {
            contentDescription = getString(R.string.clip_from_host_description)
            setOnClickListener {
                val action = InputController.pullClipboard()
                if (action is ClipboardBridge.Action.Drop) toast(reasonFor(action.why))
            }
        }

        // The reply arrives on a transport thread; the clipboard and the Toast
        // are both main-thread work.
        SessionOrchestrator.onHostClipboard = { text ->
            runOnUiThread {
                manager.setPrimaryClip(ClipData.newPlainText("RemoteDexter", text))
                toast(R.string.clip_received)
            }
        }
        // The operator asked for the empty case to overwrite rather than be
        // protected. It is safe to do now because the HOST tells an empty
        // clipboard apart from a failed read — before that fix, every failure
        // arrived as empty and this would have wiped their phone clipboard on a
        // broken read.
        SessionOrchestrator.onHostClipboardEmpty = {
            runOnUiThread {
                manager.setPrimaryClip(ClipData.newPlainText("RemoteDexter", ""))
                toast(R.string.clip_host_empty)
            }
        }
        SessionOrchestrator.onClipboardRefused = { reason ->
            runOnUiThread {
                // The host's own short reason, which never carries content.
                Toast.makeText(this, reason, Toast.LENGTH_LONG).show()
            }
        }
    }

    /** One refusal, one sentence naming what to do about it. */
    private fun reasonFor(why: ClipboardBridge.Reason): Int = when (why) {
        ClipboardBridge.Reason.NoControl -> R.string.chord_needs_control
        ClipboardBridge.Reason.NoSession -> R.string.chord_needs_session
        ClipboardBridge.Reason.NothingToSend -> R.string.clip_nothing_to_send
        ClipboardBridge.Reason.TooLarge -> R.string.clip_too_large
    }

    private fun toast(message: Int) =
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()

    /**
     * Apply the availability table to one icon: whether it responds, AND
     * whether it looks like it responds.
     *
     * The alpha is set here rather than left to a tint colour-state-list, which
     * is what this first shipped as and what a screenshot of the real device
     * disproved: the icons rendered at FULL BLACK with `isEnabled` false, so a
     * disabled control was indistinguishable from a live one and pressing it
     * did nothing with no explanation. The framework dims a Button's TEXT for
     * free; nothing dims an ImageButton's drawable unless it is asked to.
     *
     * Worth naming the way that got through: the test asserted the colour list
     * held two different colours, which it did. What it never asserted was that
     * the view USED them. A test that inspects configuration instead of outcome
     * passes on a screen the user cannot read.
     *
     * Both properties are set in one call so they cannot disagree — a control
     * that is dim but live, or live-looking but inert, is worse than either.
     */
    private fun setAvailable(button: ImageButton, action: ToolbarAction, state: SessionState) {
        val available = ToolbarAvailability.isEnabled(action, state)
        button.isEnabled = available
        button.imageAlpha = if (available) 255 else DISABLED_ICON_ALPHA
    }

    /**
     * Show the mode the toggle is currently IN, not the one it switches to — a
     * control that names its own effect reads as a statement of fact to half of
     * users and as an instruction to the other half.
     *
     * **The icon and the description are set in the same two lines on purpose.**
     * They are the sighted and the unsighted halves of one fact, and the way
     * they end up disagreeing is a second code path updating one of them; there
     * is no second path here, and `ToolbarIconsTest` presses the
     * button and checks both halves moved.
     */
    private fun renderPointerMode() {
        val touch = pointerMode == PointerMode.Touch
        btnPointerMode.setImageResource(
            if (touch) R.drawable.ic_pointer_touch else R.drawable.ic_pointer_mouse
        )
        btnPointerMode.contentDescription = getString(
            if (touch) R.string.pointer_touch_description
            else R.string.pointer_trackpad_description
        )
        btnPointerMode.tooltipText = getString(
            if (touch) R.string.pointer_touch else R.string.pointer_trackpad
        )
    }

    /** Settings may have changed the cursor lift while we were in the back stack. */
    override fun onResume() {
        super.onResume()
        refreshCursorLift()
    }

    override fun onDestroy() {
        // Belt and braces: surfaceDestroyed normally fires first, but if this
        // Activity is torn down without it, nothing may be left holding the
        // surface or the decode worker.
        desktopSurface.holder.removeCallback(surfaceCallback)
        FrameReceiver.detach()
        pipeline?.stop()
        pipeline = null
        InputController.onControlStateChanged = null
        InputController.onControlDenied = null
        SessionOrchestrator.onPhaseChanged = null
        InputController.reset()
        super.onDestroy()
    }
    private var stateObserver: SessionStateHolder.Observer? = null

    /**
     * Render whatever the app is actually doing.
     *
     * Subscribing returns the current state immediately, so this is also what
     * makes rotation safe: a recreated Activity renders the live session rather
     * than a blank Home.
     */
    private fun observeSessionState() {
        stateObserver = SessionStateHolder.subscribe { state ->
            runOnUiThread { renderSessionState(state) }
        }
    }

    private fun renderSessionState(state: SessionState) {
        desktopSurface.keepScreenOn = state is SessionState.Streaming
        btnToggleControl.isEnabled = state is SessionState.Streaming
        // One table, walked exhaustively by ToolbarAvailabilityTest. With the
        // labels gone, "is this control live" is carried entirely by how dim it
        // looks, so the rule deciding it does not get to live in an Activity
        // where nothing can test it.
        setAvailable(btnKeyboard, ToolbarAction.Keyboard, state)
        btnDisconnect.isEnabled = state.isActive
        // Offered only when there is somewhere to go and nothing already
        // running. Re-read from the store on every state change rather than
        // cached at startup: a pairing can appear (a QR scanned this run) or
        // vanish (Unpair in Diagnostics) while this Activity is alive, and a
        // stale button would either refuse for no visible reason or invite the
        // user to connect to a host they just forgot.
        btnConnect.isEnabled = !state.isActive && PairedHostRegistry(this).active() != null
        val text = when (state) {
            // Idle is two different situations wearing one label. Naming the
            // remembered host is what makes a greyed Connect self-explanatory
            // instead of looking like a broken control.
            is SessionState.Idle -> when (
                val line = IdleStatus.describe(PairedHostRegistry(this).active()?.idleLabel())
            ) {
                is IdleStatus.Line.NeedsPairing -> getString(R.string.state_idle_unpaired)
                is IdleStatus.Line.Paired ->
                    getString(R.string.state_idle_paired, line.hostLabel)
            }
            is SessionState.Connecting -> getString(R.string.state_connecting, state.hostLabel)
            is SessionState.Streaming -> getString(R.string.state_streaming, state.hostLabel)
            is SessionState.Failed ->
                getString(R.string.state_failed, state.reason.label(), state.detail)
            is SessionState.IdentityMismatch ->
                getString(R.string.state_identity_mismatch)
        }
        findViewById<android.widget.TextView>(R.id.txtSessionState)?.text = text

        // A changed host identity is a blocking sheet, not a toast. It offers
        // Cancel or a deliberate Unpair showing both PUBLIC fingerprints, and
        // never an automatic retry.
        if (state is SessionState.IdentityMismatch) {
            showIdentityMismatchSheet(state)
        }
    }

    private fun showIdentityMismatchSheet(state: SessionState.IdentityMismatch) {
        if (isFinishing || identityDialogShowing) return
        identityDialogShowing = true
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.identity_mismatch_title)
            .setMessage(
                getString(
                    R.string.identity_mismatch_body,
                    state.expectedFingerprint,
                    state.receivedFingerprint
                )
            )
            .setCancelable(false)
            .setNegativeButton(R.string.cancel) { d, _ ->
                identityDialogShowing = false
                d.dismiss()
            }
            .setPositiveButton(R.string.unpair_and_forget) { d, _ ->
                // Second confirmation. Unpairing throws away the pin that is
                // the only thing standing between this device and a substituted
                // host, so it is never one tap.
                androidx.appcompat.app.AlertDialog.Builder(this)
                    .setTitle(R.string.unpair_confirm_title)
                    .setMessage(R.string.unpair_confirm_body)
                    .setNegativeButton(R.string.cancel) { d2, _ ->
                        identityDialogShowing = false
                        d2.dismiss()
                    }
                    .setPositiveButton(R.string.unpair_confirm_action) { d2, _ ->
                        // Everything, in the tested order — not the pin
                        // alone. See DeviceUnpair.
                        DeviceUnpair.forgetEverything(this)
                        SessionStateHolder.resolveIdentityMismatch()
                        identityDialogShowing = false
                        d2.dismiss()
                    }
                    .show()
                d.dismiss()
            }
            .show()
    }

    private var identityDialogShowing = false
}
