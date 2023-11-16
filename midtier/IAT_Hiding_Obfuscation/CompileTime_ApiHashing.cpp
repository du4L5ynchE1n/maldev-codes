#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


#define        SEED       5

// generate a random key (used as initial hash)
constexpr int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
};

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;


// compile time Djb2 hashing function (WIDE)
constexpr DWORD HashStringDjb2W(const wchar_t* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

// compile time Djb2 hashing function (ASCII)
constexpr DWORD HashStringDjb2A(const char* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}




// runtime hashing macros 
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)



// compile time hashing macros (used to create variables)
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);



FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER			pImgDosHdr				= (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS			pImgNtHdrs				= (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER		ImgOptHdr				= pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY		pImgExportDir			= (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD						FunctionNameArray		= (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD						FunctionAddressArray	= (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD						FunctionOrdinalArray	= (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR*	pFunctionName		= (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress	= (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		if (dwApiNameHash == RTIME_HASHA(pFunctionName)) { // runtime hash value check 
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}









// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa

typedef int (WINAPI* fnMessageBoxA)(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
	);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw

typedef int (WINAPI* fnMessageBoxW)(
	HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType
);



// create compile time variables
CTIME_HASHA(MessageBoxA)									// this will create `MessageBoxA_Rotr32A` variable
CTIME_HASHW(MessageBoxW)									// this will create `MessageBoxW_Rotr32W` variable


// The above CTIME_HASHA(MessageBoxA) will do the following:
// constexpr auto MessageBoxA_Rotr32A = HashStringDjb2A((const char*)"MessageBoxA");

// The above CTIME_HASHW(MessageBoxW) will do the following:
// constexpr auto MessageBoxW_Rotr32W = HashStringDjb2W((const wchar_t*)L"MessageBoxW");



int main() {


	HMODULE hUser32Module = NULL;

	if ((hUser32Module = LoadLibraryA("USER32.DLL")) == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return 0;
	}
	
	/*
	// printing values of hashes (to verify it is changing every time it is compiled)
	printf("[i] MessageBoxA_Rotr32A : 0x%0.8X \n", MessageBoxA_Rotr32A);
	printf("[i] MessageBoxW_Rotr32W : 0x%0.8X \n", MessageBoxW_Rotr32W);
	*/

	// MessageBoxA_Rotr32A created by CTIME_HASHA(MessageBoxA)
	fnMessageBoxA pMessageBoxA = (fnMessageBoxA)GetProcAddressH(hUser32Module, MessageBoxA_Rotr32A);
	if (pMessageBoxA == NULL) {
		return -1;
	}

	// MessageBoxW_Rotr32W created by CTIME_HASHW(MessageBoxW)
	fnMessageBoxW pMessageBoxW = (fnMessageBoxW)GetProcAddressH(hUser32Module, MessageBoxW_Rotr32W);
	if (pMessageBoxW == NULL) {
		return -1;
	}

	pMessageBoxA(NULL, "Building Malware With Maldev", "Wow", MB_OK | MB_ICONINFORMATION);

	pMessageBoxW(NULL, L"Malware Is Bad For Your Health", L"Danger", MB_OK | MB_ICONWARNING);


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}


