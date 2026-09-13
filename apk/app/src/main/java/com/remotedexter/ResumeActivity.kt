package com.remotedexter

import android.os.Bundle
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity

class ResumeActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_resume)

        findViewById<Button>(R.id.btnWake).setOnClickListener {
            // Host wake request is already handled in Rust engine
            // This activity simply signals user intent and closes
            PowerBindings.rd_on_system_wake()
            finish()
        }
    }
}