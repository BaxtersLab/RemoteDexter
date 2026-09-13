package com.remotedexter

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class PowerStateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_SHUTDOWN -> {
                PowerBindings.rd_on_system_sleep()
                // Notify service of doze
                val svcIntent = Intent(context, RDService::class.java).apply {
                    action = "SET_DOZING"
                    putExtra("dozing", true)
                }
                context.startService(svcIntent)
            }
            Intent.ACTION_SCREEN_OFF -> {
                PowerBindings.rd_on_system_sleep()
                val svcIntent = Intent(context, RDService::class.java).apply {
                    action = "SCREEN_OFF"
                }
                context.startService(svcIntent)
            }
            Intent.ACTION_SCREEN_ON -> {
                PowerBindings.rd_on_system_wake()
                // Notify service doze ended and screen on
                val svcIntent = Intent(context, RDService::class.java).apply {
                    action = "SCREEN_ON"
                }
                context.startService(svcIntent)
            }
        }
    }
}