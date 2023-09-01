// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>



// Defining a USTRING struct
// This is what SystemFunction032 function take as parameters
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;


// Defining how does the SystemFunction032 function look. 
// More on this structure in the API Hashing module
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
	);


BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// The return of SystemFunction032
	NTSTATUS	STATUS = NULL;

	// Making 2 USTRING variables
	// 1 is passed as the key and the other one is passed as the block of data to encrypt/decrypt
	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
			Data = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };


	// Since SystemFunction032 is exported from Advapi32.dll, use LoadLibraryA to load Advapi32.dll into the process, 
	// And use LoadLibraryA's return value as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// If the SystemFunction032 invocation failed, it will return a non-zero value 
	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

unsigned char shellcode[] = { 
	"This is very spooky stuff, doing rc4 encryption !" 
};

unsigned char key[] = { 
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};




int main() {
	// Printing the address of the shellcode
	printf("[i] shellcode : 0x%p \n", shellcode);

	// Encryption
	if (!Rc4EncryptionViSystemFunc032(key, shellcode, sizeof(key), sizeof(shellcode))){
		// Failed
		return -1;
	}

	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Decryption
	if (!Rc4EncryptionViSystemFunc032(key, shellcode, sizeof(key), sizeof(shellcode))) {
		// Failed
		return -1;
	}
	// Printing shellcode to verify successful decryption 
	printf("[i] shellcode : \"%s\" \n", (char*)shellcode);

	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;

}

