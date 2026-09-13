package com.remotedexter

object PowerBindings {
    init { RDRust }

    external fun rd_on_system_sleep()
    external fun rd_on_system_wake()
    external fun rd_on_transport_idle()
    external fun rd_on_transport_wake()
}