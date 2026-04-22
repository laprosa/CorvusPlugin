@echo off
setlocal enabledelayedexpansion

REM Change to native directory
cd /d "%~dp0"

REM Compile the C++ plugin with all helper files using MinGW64
x86_64-w64-mingw32-g++ -shared -fPIC -O2 plugin.cpp delete_pending_file.cpp pe_hdrs_helper.cpp injection_helpers.cpp -o corvusminer-windows-amd64.dll

pause
