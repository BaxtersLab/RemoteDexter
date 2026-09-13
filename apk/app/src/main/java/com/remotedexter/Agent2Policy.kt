package com.remotedexter

object Agent2Policy {

    // Camera/mic gating was removed with the VirtualOffice split — those are
    // VO-agent sensors, not RemoteDexter features. See the divergence spec.

    fun allowScreenshot(): Boolean {
        return Agent2State.session == Agent2State.Session.Active
    }
}