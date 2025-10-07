#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <Wtsapi32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Advapi32.lib")

#define LOGFILE "C:\\Windows\\Temp\\injector.log"

FILE* log_fp = NULL;

void writeLog(const char* format, ...) {
    if (!log_fp) return;
    va_list args;
    va_start(args, format);
    vfprintf(log_fp, format, args);
    fprintf(log_fp, "\n");
    fflush(log_fp);
    va_end(args);
}

BOOL EnablePrivilege(LPCSTR privName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success;
}

BOOL GetUserTokenFromSession(HANDLE* hUserToken) {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF)
        return FALSE;

    return WTSQueryUserToken(sessionId, hUserToken);
}

int main(int argc, char* argv[]) {
    log_fp = fopen(LOGFILE, "a+");
    if (!log_fp) return 1;

    writeLog("[>] DLL Injector started...");

    if (argc < 2) {
        writeLog("[-] Usage: %s <FullPathToDLL>", argv[0]);
        return 1;
    }

    LPCSTR lpDllName = argv[1];
    DWORD dwSize = (DWORD)(strlen(lpDllName) + 1);
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    EnablePrivilege(SE_DEBUG_NAME);
    writeLog("[+] SeDebugPrivilege enabled");

    HANDLE hUserToken = NULL;
    if (!GetUserTokenFromSession(&hUserToken)) {
        writeLog("[-] Failed to get active user token: 0x%x", GetLastError());
        return 1;
    }

    writeLog("[+] Retrieved user token from active session");

    if (!CreateProcessAsUserA(
        hUserToken,
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE,
        NULL, NULL,
        &si, &pi))
    {
        writeLog("[-] Failed to start Notepad as user: 0x%x", GetLastError());
        return 1;
    }

    writeLog("[+] Notepad launched: PID = %lu", pi.dwProcessId);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        writeLog("[-] GetModuleHandle failed: 0x%x", GetLastError());
        return 1;
    }

    FARPROC fLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!fLoadLibrary) {
        writeLog("[-] GetProcAddress failed: 0x%x", GetLastError());
        return 1;
    }

    writeLog("[+] LoadLibraryA is at: 0x%p", fLoadLibrary);

    LPVOID remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuffer) {
        writeLog("[-] VirtualAllocEx failed: 0x%x", GetLastError());
        return 1;
    }

    writeLog("[+] Allocated memory at 0x%p", remoteBuffer);

    SIZE_T written;
    if (!WriteProcessMemory(pi.hProcess, remoteBuffer, lpDllName, dwSize, &written)) {
        writeLog("[-] WriteProcessMemory failed: 0x%x", GetLastError());
        return 1;
    }

    writeLog("[+] Wrote %zu bytes", written);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fLoadLibrary, remoteBuffer, 0, NULL);
    if (!hThread) {
        writeLog("[-] CreateRemoteThread failed: 0x%x", GetLastError());
        return 1;
    }

    writeLog("[+] Remote thread started");

    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    if (GetExitCodeThread(hThread, &exitCode)) {
        if (exitCode == 0)
            writeLog("[-] DLL failed to load (LoadLibraryA returned NULL): 0x%x", GetLastError());
        else
            writeLog("[+] DLL successfully loaded at: 0x%p", (LPVOID)exitCode);
    }
    else {
        writeLog("[-] GetExitCodeThread failed: 0x%x", GetLastError());
    }

    CloseHandle(hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hUserToken);
    fclose(log_fp);

    writeLog("[+] Injection completed\n");
    return 0;
}
