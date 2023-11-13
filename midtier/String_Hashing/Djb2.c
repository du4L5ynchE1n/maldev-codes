#include <Windows.h>
#include <stdio.h>

// reference: https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringDjb2.cpp


#define INITIAL_HASH	3731		// added to randomize 
#define INITIAL_SEED	7			// recommended to be 0 < INITIAL_SEED < 10

// generate Djb2 hashes from Ascii input string
DWORD HashStringDjb2A(_In_ PCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

// generate Djb2 hashes from wide-character input string
DWORD HashStringDjb2W(_In_ PWCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}


int main() {

	CHAR*	cTest = "MaldevAcademy";
	WCHAR*	wTest = L"MaldevAcademy";
	
	printf("[+] Hash Of \"%s\" Is : 0x%0.8X \n", cTest, HashStringDjb2A(cTest));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest, HashStringDjb2W(wTest));


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

/*	
	OUTPUT:

[+] Hash Of "MaldevAcademy" Is : 0xB4FEAFA0
[+] Hash Of "MaldevAcademy" Is : 0xB4FEAFA0
*/
