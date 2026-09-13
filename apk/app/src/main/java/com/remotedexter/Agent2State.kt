package com.remotedexter

object Agent2State {

    enum class Session { Idle, Active, Suspended }
    enum class Power { Awake, Dozing, ScreenOff }

    var session = Session.Idle
        private set

    var power = Power.Awake
        private set

    fun setSession(s: Session) {
        session = s
    }

    fun setPower(p: Power) {
        power = p
    }

    // sensorsAllowed()/onStateChanged() stopped the phone's camera and mic when
    // the session went inactive. Both were removed with the VirtualOffice split;
    // RemoteDexter drives no phone sensors, so there is nothing to gate here.
    // Session/Power are still tracked — RDService and Agent2Policy use them.
}