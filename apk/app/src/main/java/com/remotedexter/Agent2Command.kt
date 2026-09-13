package com.remotedexter

// Camera/mic commands were removed with the RemoteDexter ⇔ VirtualOffice split:
// controlling the phone's camera and microphone is a managed-agent feature,
// not a remote-desktop-viewer one, and is deliberately absent here.
sealed class Agent2Command {

    object ScreenshotRequest : Agent2Command()

    object Wake : Agent2Command()
    object Sleep : Agent2Command()
}