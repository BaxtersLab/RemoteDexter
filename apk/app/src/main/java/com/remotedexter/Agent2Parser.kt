package com.remotedexter

import org.json.JSONObject

object Agent2Parser {

    fun parse(json: String): Agent2Command {
        val obj = JSONObject(json)
        return when (obj.getString("cmd")) {


            "ScreenshotRequest" -> Agent2Command.ScreenshotRequest

            "Wake" -> Agent2Command.Wake
            "Sleep" -> Agent2Command.Sleep

            else -> throw IllegalArgumentException("Unknown Agent2 cmd")
        }
    }
}