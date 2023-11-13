#include <Windows.h>
#include <stdio.h>

// reference: https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringJenkinsOneAtATime32Bit.cpp

#define INITIAL_SEED	7	// recommended to be 0 < INITIAL_SEED < 10

// generate JenkinsOneAtATime32Bit hashes from Ascii input string
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

// generate JenkinsOneAtATime32Bit hashes from wide-character input string
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}





int main() {

	CHAR*	cTest	= "MaldevAcademy";
	WCHAR*	wTest	= L"MaldevAcademy";

	printf("[+] Hash Of \"%s\" Is : 0x%0.8X \n", cTest, HashStringJenkinsOneAtATime32BitA(cTest));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest, HashStringJenkinsOneAtATime32BitW(wTest));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

/*
	OUTPUT:

[+] Hash Of "MaldevAcademy" Is : 0x1FE854F9
[+] Hash Of "MaldevAcademy" Is : 0x1FE854F9
*/
