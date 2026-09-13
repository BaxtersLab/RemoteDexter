@echo off
setlocal

rem Supported Windows entry point. Viewing is enabled for this process only;
rem input and file access remain separate opt-ins.
rem
rem This file does not build anything. `host_app.exe` is expected NEXT TO IT,
rem staged there by packaging\windows\build_windows.ps1. On a clean checkout
rem nothing stages it, and the shortcut -> run.bat -> exe chain used to end at
rem a silent `start` of a file that was not there: the console flashed and
rem vanished with no message, which reads exactly like a crash.

set "RD_EXE=%~dp0host_app.exe"

if not exist "%RD_EXE%" (
    echo(
    echo   RemoteDexter: the host executable is not here.
    echo(
    echo     expected: "%RD_EXE%"
    echo(
    echo   Build and stage it with:
    echo(
    echo     powershell -ExecutionPolicy Bypass -File "%~dp0..\packaging\windows\build_windows.ps1"
    echo(
    echo   or copy host_app.exe from a release build next to this file.
    echo(
    pause
    exit /b 1
)

rem Viewing. Deliberately narrow: this grants the picture, nothing else.
set RD_CAP_SCREENSHOT=1

rem Input is OFF by default and that is not an oversight.
rem
rem Deny-by-default for input is the policy: a host that can move the mouse and
rem type is a different thing from one that can only be looked at, and it is
rem not something a launcher should decide on the operator's behalf. What this
rem block adds is the missing half - SAYING SO. The refusal otherwise arrives
rem as a toast on the phone naming an environment variable, on a machine the
rem operator may not be sitting at.
if defined RD_CAP_INPUT (
    echo   input control: ENABLED for this launch ^(RD_CAP_INPUT=%RD_CAP_INPUT%^)
) else (
    echo   input control: OFF - the phone will show this desktop but cannot drive it.
    echo(
    echo   To enable it for one launch, from a cmd window:
    echo       set "RD_CAP_INPUT=1" ^&^& "%~f0"
    echo(
    rem The quotes around the assignment are NOT decoration, and this line was
    rem tested on a real cmd.exe rather than reasoned about. Written the obvious
    rem way -
    rem
    rem     set RD_CAP_INPUT=1 ^&^& "%~f0"
    rem
    rem - cmd takes EVERYTHING up to the `^&^&` as the value, so the variable
    rem becomes "1 " with a trailing space. `capability_granted` compares
    rem exactly against "1", so the gate stays shut and the phone still cannot
    rem drive the desktop - after the operator did precisely what they were
    rem told. `set "VAR=1"` ends the value at the closing quote.
)

start "" "%RD_EXE%"

endlocal
exit /b 0
