@echo off
rem Build the CFG-instrumented beacon DLL at a fixed base address.
rem /guard:cf instruments indirect-call SITES; the /GUARDCF: table lists the
rem export's address as a VALID target in the process bitmap.
rem /base fixes the preferred base so the plant script can compute the VA.
rem /fixed avoids relocation issues on this standalone demo DLL.
rem Requires: VS BuildTools (adjust the vcvars64 path for your install).
setlocal
set HERE=%~dp0
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%HERE%"
cl /nologo /W4 /O2 /LD /guard:cf /base:0x180000000 /fixed beacon.c /Fe:beacon.dll /link /guard:cf /DLL /BASE:0x180000000 /FIXED /OUT:beacon.dll user32.lib
if errorlevel 1 (
    echo BUILD FAILED - adjust the vcvars64 path above for your install
    exit /b 1
)
dumpbin /headers beacon.dll | findstr /i "image base guard"
echo === exports ===
dumpbin /exports beacon.dll | findstr /i "BeaconProc"
echo === load config ===
dumpbin /loadconfig beacon.dll | findstr /i "GuardFlags GuardCFFunctionTable count"
