#include <Windows.h>
#include <stdio.h>

#define INFO "[>]"
#define SUCCES "[+]"
#define ERROR "[-]"

int WriteToFile(char* lpFileName, char* cBuffer) {
    HANDLE hFile;
    DWORD dwBytesWritten;
    SIZE_T sBufferSize = strlen(cBuffer);

    printf("%s Writing to a file\n", INFO);
    hFile = CreateFileA(lpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("%s CreateFile failed with error: 0x%x\n", ERROR, GetLastError());
        return 1;
    }

    SetFilePointer(hFile, 0, NULL, FILE_END);

    if (!WriteFile(hFile, cBuffer, sBufferSize, &dwBytesWritten, NULL)) {
        printf("%s WriteFile failed with error: 0x%x\n", ERROR, GetLastError());
    }

    CloseHandle(hFile);
}
