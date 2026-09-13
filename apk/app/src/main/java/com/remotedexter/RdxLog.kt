package com.remotedexter

import android.content.Context
import android.util.Log
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * In-app log buffer, readable on the device without a USB cable.
 *
 * The pairing path is the reason this exists. Every security gate in
 * [com.remotedexter.bootstrap18.SessionStarter] refuses by logging and
 * returning — it shows the user nothing at all. On a phone with no adb attached
 * that made a failed pairing indistinguishable from a hang. Everything written
 * here also goes to logcat, so `adb logcat -s <tag>` still works when a cable is
 * available; [snapshot] is for when it is not.
 *
 * Entries are kept in a bounded in-memory ring ([MAX_ENTRIES]) so a long session
 * cannot grow without limit. The most recent entries are the ones kept.
 *
 * [init] also installs an uncaught-exception handler that flushes the buffer to
 * disk, so a crash is still readable on the next launch — a crash otherwise
 * takes the only copy of the log down with the process.
 */
object RdxLog {

    private const val TAG = "RdxLog"

    /** Bounded ring size. Oldest entries are dropped first. */
    private const val MAX_ENTRIES = 2000

    /** Where a crash flush lands, relative to the app's private files dir. */
    private const val CRASH_FILE = "rdx-crash-log.txt"

    private val entries = ArrayDeque<String>()
    private val stamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    /** Set once by [init]; used only to locate the crash file. */
    @Volatile
    private var appContext: Context? = null

    @Volatile
    private var crashHandlerInstalled = false

    /**
     * Wire up the log. Safe to call more than once — the crash handler is only
     * installed on the first call, so repeated calls cannot chain handlers.
     *
     * Recovers and clears any log flushed by a previous crashed run, so the
     * failure that killed the process is visible in this run's snapshot.
     */
    fun init(context: Context) {
        appContext = context.applicationContext

        runCatching {
            val f = File(context.applicationContext.filesDir, CRASH_FILE)
            if (f.exists()) {
                append("=== log recovered from previous run (crash) ===")
                f.readLines().forEach { append(it) }
                append("=== end of recovered log ===")
                f.delete()
            }
        }

        if (!crashHandlerInstalled) {
            installCrashHandler()
            crashHandlerInstalled = true
        }

        i(TAG, buildHeader(context))
    }

    fun d(tag: String, msg: String) { Log.d(tag, msg); append("D/$tag: $msg") }
    fun i(tag: String, msg: String) { Log.i(tag, msg); append("I/$tag: $msg") }
    fun w(tag: String, msg: String) { Log.w(tag, msg); append("W/$tag: $msg") }
    fun e(tag: String, msg: String) { Log.e(tag, msg); append("E/$tag: $msg") }

    fun w(tag: String, msg: String, t: Throwable) {
        Log.w(tag, msg, t)
        append("W/$tag: $msg")
        append(stackTraceToText(t))
    }

    fun e(tag: String, msg: String, t: Throwable) {
        Log.e(tag, msg, t)
        append("E/$tag: $msg")
        append(stackTraceToText(t))
    }

    /** The whole buffer as one block of text, newest last. */
    fun snapshot(): String = synchronized(entries) { entries.joinToString("\n") }

    fun clear() = synchronized(entries) { entries.clear() }

    private fun append(line: String) {
        val stamped = "${stamp.format(Date())} $line"
        synchronized(entries) {
            entries.addLast(stamped)
            while (entries.size > MAX_ENTRIES) entries.removeFirst()
        }
    }

    private fun stackTraceToText(t: Throwable): String {
        val sw = StringWriter()
        PrintWriter(sw).use { t.printStackTrace(it) }
        return sw.toString().trimEnd()
    }

    private fun buildHeader(context: Context): String {
        val version = runCatching {
            val pm = context.packageManager
            val pi = pm.getPackageInfo(context.packageName, 0)
            "${pi.versionName} (${context.packageName})"
        }.getOrDefault("unknown")

        return buildString {
            append("RemoteDexter $version")
            append(" | Android ${android.os.Build.VERSION.RELEASE}")
            append(" (API ${android.os.Build.VERSION.SDK_INT})")
            append(" | ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
            append(" | abis=${android.os.Build.SUPPORTED_ABIS.joinToString(",")}")
        }
    }

    /**
     * Flush to disk on an uncaught exception, then hand off to the previous
     * handler so the platform still does whatever it would normally do. Never
     * swallow the crash — that would trade a visible failure for a silent one,
     * which is the exact problem this class exists to fix.
     */
    private fun installCrashHandler() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                e(TAG, "uncaught exception on thread ${thread.name}", throwable)
                appContext?.let { ctx ->
                    File(ctx.filesDir, CRASH_FILE).writeText(snapshot())
                }
            }
            previous?.uncaughtException(thread, throwable)
        }
    }
}
