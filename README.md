# msheif_store UAF → code execution (PoC)
CVE-2026-100204                                                                                                                                                                              
Use-after-free in the Microsoft HEIF/AVIF metadata rewrite path
(`msheif_store.dll`, reached via `PhotoMetadataHandler!CPhotoPropertyStore::Commit`)
drives an attacker-influenced indirect call. This repo demonstrates full code
execution: the corrupted call passes Control Flow Guard and lands in a
CFG-registered beacon, which drops a proof file and launches a URL via `cmd.exe`.

> **Note:** the corrupted bytes are planted with a debugger to simulate
> attacker-controlled freed memory (standard exploitability-demonstration
> practice). There is no debugger-free heap reclaim here.

## Tested against

- Windows 11 Insider Preview build 29648, `PhotoMetadataHandler` 10.0.29648.1000
- HEIF Image Extension 1.2.48.0 (`msheif_store.dll` 10.0.29640.1000)

## Layout

```text
poc/crash_seed.heic   trigger file (fully valid image, animated+audio container shape)
poc/crash_seed.avif   byte-identical copy under the .avif extension
repro/ps_trigger.ps1  COM trigger: Initialize(RW) -> SetValue(CameraModel) -> Commit
demo/beacon.c         CFG-instrumented beacon DLL source (/guard:cf)
demo/build_beacon.cmd builds beacon.dll (fixed base 0x180000000, needs VS BuildTools)
demo/fullchain.cmd    runs the trigger under cdb, plants the fake object, continues
```

## Requirements

- `cdb.exe` on `PATH` (WinDbg / Windows SDK Debugging Tools)
- VS BuildTools 2022 (for `build_beacon.cmd`)
- A vulnerable build (see above)

## Usage

```bat
REM 1. build the CFG-instrumented beacon
call demo\build_beacon.cmd

REM 2. run the full chain (defaults to poc\crash_seed.heic)
call demo\fullchain.cmd
REM with an explicit seed:
call demo\fullchain.cmd C:\path\to\crash_seed.heic
```

Expected on a vulnerable build: `%USERPROFILE%\Desktop\pwned.txt` appears and the
URL opens in the browser. The raw debugger log goes to `fullchain.txt`.

## Credit
Austin Mannchen, discoverer of the vuln.


                                      
William Ryan Hanna, PoC idea.
