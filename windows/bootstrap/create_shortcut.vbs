Set oWS = WScript.CreateObject("WScript.Shell")
Set oLink = oWS.CreateShortcut(WScript.Arguments(0))
oLink.TargetPath = WScript.Arguments(1)
oLink.IconLocation = WScript.Arguments(2)
oLink.WorkingDirectory = WScript.Arguments(3)
oLink.Save
