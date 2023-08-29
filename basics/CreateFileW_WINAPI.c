#include <Windows.h>
#include <stdio.h>

#define BUFFER_SIZE 2000

int main() {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    wchar_t filePath[MAX_PATH]; // Buffer to hold selected file path
    char buffer[BUFFER_SIZE];          // Buffer to read file content

    // Prompt the user to enter the file path
    wprintf(L"Enter the file path:");
    wscanf_s(L"%ls", filePath);

    // Open the selected file
    hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        // Read and print file content
        DWORD bytesRead;
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            printf("%.*s", bytesRead, buffer);
        }
        CloseHandle(hFile);
    }
    else {
        wprintf(L"Error opening file: %ls\n", filePath);
        printf("CreateFileW API Error: %d\n", GetLastError());
    }
    return 0;
}
