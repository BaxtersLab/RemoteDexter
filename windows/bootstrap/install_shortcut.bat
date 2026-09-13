@echo off
setlocal

set APP_NAME=RemoteDexter
set WIN_DIR=%~dp0..
set HOST_LAUNCHER=%WIN_DIR%\run.bat
set ICON=%~dp0bootstrap.ico

set DESKTOP=%USERPROFILE%\Desktop
set STARTMENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs
set STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup

echo Creating Desktop and Start Menu shortcuts...

cscript //nologo "%~dp0create_shortcut.vbs" "%DESKTOP%\%APP_NAME%.lnk" "%HOST_LAUNCHER%" "%ICON%" "%WIN_DIR%"
cscript //nologo "%~dp0create_shortcut.vbs" "%STARTMENU%\%APP_NAME%.lnk" "%HOST_LAUNCHER%" "%ICON%" "%WIN_DIR%"

echo.
set /p AUTORUN=Do you want RemoteDexter to auto-start when Windows boots? (Y/N): 

if /I "%AUTORUN%"=="Y" (
    echo Creating Startup shortcut...
    cscript //nologo "%~dp0create_shortcut.vbs" "%STARTUP%\%APP_NAME%.lnk" "%HOST_LAUNCHER%" "%ICON%" "%WIN_DIR%"
    echo Auto-start enabled.
) else (
    echo Auto-start disabled.
)

echo.
echo Launching RemoteDexter...
call "%HOST_LAUNCHER%"

endlocal
exit /b 0
