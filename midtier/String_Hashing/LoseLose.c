#include <Windows.h>
#include <stdio.h>

// reference: https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringLoseLose.cpp

#define INITIAL_SEED	2	// recommended to be 0 < INITIAL_SEED < 5

// generate LoseLose hashes from Ascii input string
DWORD HashStringLoseLoseA(_In_ PCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}
	return Hash;
}

// generate LoseLose hashes from wide-character input string
DWORD HashStringLoseLoseW(_In_ PWCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}

	return Hash;
}




int main() {

	CHAR*	cTest = "MaldevAcademy";
	WCHAR*	wTest = L"MaldevAcademy";

	printf("[+] Hash Of \"%s\" Is : 0x%0.8X \n", cTest, HashStringLoseLoseA(cTest));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest, HashStringLoseLoseW(wTest));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

/*
	OUTPUT:

[+] Hash Of "MaldevAcademy" Is : 0x82131A35
[+] Hash Of "MaldevAcademy" Is : 0x82131A35
*/
