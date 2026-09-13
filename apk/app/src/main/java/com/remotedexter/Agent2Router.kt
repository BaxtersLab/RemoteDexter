package com.remotedexter

object Agent2Router {

    fun handle(cmd: Agent2Command) {
        when (cmd) {

            Agent2Command.ScreenshotRequest -> {
                if (Agent2Policy.allowScreenshot()) {
                    ScreenshotController.request()
                }
            }

            Agent2Command.Wake -> {
                PowerBindings.rd_on_system_wake()
            }

            Agent2Command.Sleep -> {
                PowerBindings.rd_on_system_sleep()
            }
        }
    }
}