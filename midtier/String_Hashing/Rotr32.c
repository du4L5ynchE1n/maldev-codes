#include <Windows.h>
#include <stdio.h>

// reference: https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringRotr32.cpp


#define INITIAL_SEED	5	// recommended to be 0 < INITIAL_SEED < 10



// helper function that apply the bitwise rotation
UINT32 HashStringRotr32Sub(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

// generate Rotr32 hashes from Ascii input string
INT HashStringRotr32A(_In_ PCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < lstrlenA(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

// generate Rotr32 hashes from wide-character input string
INT HashStringRotr32W(_In_ PWCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < lstrlenW(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}




int main() {

	CHAR*	cTest = "MaldevAcademy";
	WCHAR*	wTest = L"MaldevAcademy";

	printf("[+] Hash Of \"%s\" Is : 0x%0.8X \n", cTest, HashStringRotr32A(cTest));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest, HashStringRotr32W(wTest));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

/*
	OUTPUT:

[+] Hash Of "MaldevAcademy" Is : 0xAA4A09DF
[+] Hash Of "MaldevAcademy" Is : 0xAA4A09DF
*/
