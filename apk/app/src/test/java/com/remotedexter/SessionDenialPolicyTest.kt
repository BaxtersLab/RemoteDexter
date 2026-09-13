package com.remotedexter

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which host refusals end the session.
 *
 * ## The defect this was written for
 *
 * `SessionOrchestrator` called `fail()` — tearing down a live stream — for every
 * `denied`/`error` except three input commands. Correct while those three were
 * the only things a running session could send.
 *
 * **Adding the clipboard broke it silently.** Pressing "← Host" while the host
 * had an image copied is answered `denied … the host's clipboard is not text`,
 * which is an ordinary answer to an ordinary question — and it would have
 * ended the operator's session. So would a host running without
 * `RD_CAP_CLIPBOARD`, which is the default, so the very first press of that
 * button on a normally-launched host would have killed the stream.
 *
 * Caught by reading the denial path while wiring the feature, not by a test. It
 * has one now.
 */
class SessionDenialPolicyTest {

    /**
     * Everything a person can press during a live stream. A refusal is "not
     * that, not now" and the remedy is a sentence on screen.
     */
    @Test
    fun aRefusedButtonPressNeverEndsTheSession() {
        for (cmd in listOf(
            "grant_input", "revoke_input", "input_event",
            "clipboard_push", "clipboard_pull"
        )) {
            assertFalse(
                "$cmd being refused must not tear down a live session",
                SessionDenialPolicy.isFatalToSession(cmd)
            )
        }
    }

    /**
     * The negotiation commands are the ones a session cannot continue without.
     */
    @Test
    fun aRefusedNegotiationCommandStillEndsTheSession() {
        for (cmd in listOf("list_windows", "permit_window", "stream_start")) {
            assertTrue(
                "$cmd being refused leaves nothing to continue with",
                SessionDenialPolicy.isFatalToSession(cmd)
            )
        }
    }

    /**
     * **The default is fatal**, and that is the safe direction. An unknown
     * command being refused means the two ends disagree about what this
     * protocol is; being wrong here costs a reconnect, while being wrong the
     * other way leaves a session running on a host that has refused the thing
     * it depends on.
     */
    @Test
    fun anUnknownCommandDefaultsToFatal() {
        assertTrue(SessionDenialPolicy.isFatalToSession("something_invented_later"))
        assertTrue(SessionDenialPolicy.isFatalToSession(""))
    }

    /**
     * The clipboard refusals are identifiable, so the reason reaches the
     * operator as a message rather than being routed to the input controller —
     * which would turn control off on a clipboard problem.
     */
    @Test
    fun clipboardRefusalsAreTellableFromInputRefusals() {
        assertTrue(SessionDenialPolicy.isClipboard("clipboard_push"))
        assertTrue(SessionDenialPolicy.isClipboard("clipboard_pull"))
        assertFalse(SessionDenialPolicy.isClipboard("input_event"))
        assertFalse(SessionDenialPolicy.isClipboard("grant_input"))
    }
}
