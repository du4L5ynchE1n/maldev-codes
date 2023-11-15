#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


#define INITIAL_SEED	7

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

// macros used to make the code neater & cleaner
// HASHA pass the input string to HashStringJenkinsOneAtATime32BitA 
// HASHW pass the input string to HashStringJenkinsOneAtATime32BitW
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))






/*
-	`dwApiNameHash` is the hash value of the function name 
	of the function specified to get it's address.
	
-	The function is exported by a dll of a handle `hModule` 
	(`hModule` is returned by GetModuleHandleH)
*/

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

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

		// hashing every function name `pFunctionName`
		// if both hashes are equal, then we found the function we want 
		if (dwApiNameHash == HASHA(pFunctionName)) {
			return pFunctionAddress;
		}
	}

	return NULL;
}



/*
-	dwModuleNameHash is the hash of the dll name to get the handle of.
	the name should be hashed in *UPPER* case letters - capitalized; 

	HASHA("NTDLL.DLL") - HASHA("USER32.DLL") - HASHA("KERNEL32.DLL")		
*/
HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {
			
			// converting `FullDllName.Buffer` to upper case string 
			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';

			// hashing `UpperCaseDllName` and comparing the hash value to that's of the input `dwModuleNameHash`
			if (HASHA(UpperCaseDllName) == dwModuleNameHash)
				return pDte->Reserved2[0];
			
		}
		else {
			break;
		}

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
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



/*
	printf("[i] Hash Of \"%s\" Is : 0x%0.8X \n", "USER32.DLL", HASHA("USER32.DLL"));
	printf("[i] Hash Of \"%s\" Is : 0x%0.8X \n", "MessageBoxA", HASHA("MessageBoxA"));

	//	 [OUTPUT]	//

	[i] Hash Of "USER32.DLL" Is : 0x81E3778E
	[i] Hash Of "MessageBoxA" Is : 0xF10E27CA
*/


// hard coded hashes

#define USER32DLL_HASH		0x81E3778E
#define MessageBoxA_HASH	0xF10E27CA



int main() {
	
	// load user32.dll to the current process, so that GetModuleHandleH sill work
	if (LoadLibraryA("USER32.DLL") == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return 0;
	}

	// getting the handle of user32.dll using GetModuleHandleH 
	HMODULE hUser32Module = GetModuleHandleH(USER32DLL_HASH);
	if (hUser32Module == NULL){
		printf("[!] Cound'nt Get Handle To User32.dll \n");
		return -1;
	}

	// getting the address of MessageBoxA function using GetProcAddressH
	fnMessageBoxA pMessageBoxA = (fnMessageBoxA)GetProcAddressH(hUser32Module, MessageBoxA_HASH);
	if (pMessageBoxA == NULL) {
		printf("[!] Cound'nt Find Address Of Specified Function \n");
		return -1;
	}

	// calling MessageBoxA
	pMessageBoxA(NULL, "Building Malware With Maldev", "Wow", MB_OK | MB_ICONEXCLAMATION);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}


