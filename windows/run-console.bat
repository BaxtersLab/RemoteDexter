@echo off
setlocal

rem The DIAGNOSTIC entry point. Same grants as run.bat, but the host runs
rem ATTACHED so its console output can be captured.
rem
rem WHY THIS FILE EXISTS
rem
rem run.bat ends in `start "" "%RD_EXE%"`, which is correct for a desktop
rem launcher: the operator gets their prompt back and the GUI owns its own
rem console. The cost appears when the ARTIFACT IS CONSOLE OUTPUT. Windows
rem round 13 had to prove P9 by finding a single line -
rem
rem     [module10] shutdown released input state: 0 key(s), 1 button(s)
rem
rem - and via run.bat that line goes to a detached console and is lost. They
rem declared a deviation and launched host_app.exe directly with the same
rem environment. This file makes that a supported thing to do rather than a
rem deviation to explain each round:
rem
rem     windows\run-console.bat > host.log 2>&1
rem
rem THIS IS NOT A SECOND SUPPORTED LAUNCHER. run.bat is what the shortcut runs
rem and what a user should use. This one exists to be piped.
rem
rem THE HAZARD THIS FILE CREATES, named so it is not forgotten: the 2026-09-05
rem defect was TWO launchers where one was fixed and the other was not. A third
rem that grants capabilities is the same shape. So the capability lines below
rem are not merely copied - windows\test-run-bat.ps1 RUNS BOTH launchers and
rem asserts they deliver the SAME capability environment. If these two ever
rem disagree, that is a test failure, not a discovery.

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
    exit /b 1
)

rem Viewing. Deliberately narrow: this grants the picture, nothing else.
set RD_CAP_SCREENSHOT=1

rem Input is OFF by default here for the same reason it is off in run.bat -
rem deny-by-default is the policy, and a diagnostic launcher does not get to
rem relax it just because it is convenient for testing.
if defined RD_CAP_INPUT (
    echo   input control: ENABLED for this launch ^(RD_CAP_INPUT=%RD_CAP_INPUT%^)
) else (
    echo   input control: OFF - the phone will show this desktop but cannot drive it.
    echo(
    echo   To enable it for one launch, from a cmd window:
    echo       set "RD_CAP_INPUT=1" ^&^& "%~f0"
    echo(
    rem The quotes are load-bearing and this was tested on a real cmd.exe:
    rem written `set RD_CAP_INPUT=1 ^&^& ...` the value becomes "1 " with a
    rem trailing space, capability_granted compares exactly against "1", and the
    rem gate stays shut after the operator did what they were told. Windows
    rem round 12 proved both forms at runtime.
)

echo   running ATTACHED - output can be redirected. Close the host window to stop.
echo(

rem No `start`: the host inherits this console, so stdout and stderr can be
rem piped. %* is passed through so a caller can add host arguments.
"%RD_EXE%" %*
set "RD_RC=%ERRORLEVEL%"

endlocal & exit /b %RD_RC%
