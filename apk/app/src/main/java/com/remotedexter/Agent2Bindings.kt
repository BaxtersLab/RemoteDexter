package com.remotedexter

/**
 * Agent2 JNI callback endpoint.
 *
 * Called by the Rust cdylib when an AGENT2_COMMAND (0x21) envelope arrives
 * from the Windows host.  Routes through [RDService.onAgent2Command].
 *
 * This is the Rust → Kotlin direction; no `external fun` needed here because
 * the Rust side calls the static method directly via JNI `CallStaticVoidMethod`.
 */
object Agent2Bindings {
    init { RDRust } // ensure native library is loaded

    /**
     * Entry point invoked from Rust [call_kotlin_on_agent2_command].
     * Must be a @JvmStatic for CallStaticVoidMethod to resolve it.
     */
    @JvmStatic
    fun rd_on_agent2_command(json: String) {
        RDService.instance?.onAgent2Command(json)
    }
}
