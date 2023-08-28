#include <Windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    // Prompt the user to enter a string
    printf("Enter string to be allocated: ");
    char inputString[100];
    fgets(inputString, sizeof(inputString), stdin);
    inputString[strcspn(inputString, "\n")] = '\0'; // Remove newline character

    // Allocate memory to store the entered string
    SIZE_T dwSize = strlen(inputString) + 1; // Include space for null-terminator
    DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
    DWORD flProtect = PAGE_READWRITE;
    PVOID lpMemory = VirtualAlloc(NULL, dwSize, flAllocationType, flProtect);

    // Check if memory allocation was successful
    if (lpMemory != NULL) {
        printf("[+] Base Address of Allocated Memory: 0x%p\n", lpMemory);
        memcpy(lpMemory, inputString, dwSize); // Copy the entered string to allocated memory
        printf("[+] String in Allocated Memory: %s\n", (char*)lpMemory);
        VirtualFree(lpMemory, 0, MEM_RELEASE); // Free allocated memory
    }
    else {
        printf("[-] Memory allocation failed.\n");
        printf("Virtual Alloc Error: %d\n", GetLastError());
    }

    return 0;
}

