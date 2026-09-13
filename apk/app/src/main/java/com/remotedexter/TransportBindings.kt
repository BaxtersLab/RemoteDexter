package com.remotedexter

object TransportBindings {
    init { RDRust } // ensure library loaded

    /**
     * Tell the native side where this app's private directory is, so it can
     * keep ONE Noise identity instead of generating a new one per connection.
     *
     * Must be called before the first connect. Without it the client still
     * works, but the host sees a different device every time and pairing cannot
     * persist.
     */
    external fun rd_set_data_dir(dir: String)

    /**
     * Renounce this device's own Noise identity.
     *
     * The Android half of "fully prevent future reconnects": the host can
     * revoke a device, and the device can renounce itself. The next connection
     * uses a new key, so the host sees an unknown device and refuses it until
     * the owner pairs again with a fresh QR.
     */
    external fun rd_forget_identity(): Boolean

    external fun rd_init_session()
    external fun rd_shutdown_session()
    external fun rd_tick()
}