#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

	// we do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;
	
	// getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER	pImgDosHdr		= (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) 
		return NULL;
	
	// getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs		= (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) 
		return NULL;

	// getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr	= pImgNtHdrs->OptionalHeader;

	// we can get the optional header like this as well																								
	// PIMAGE_OPTIONAL_HEADER	pImgOptHdr	= (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	// getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	// getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	// getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	// looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){
		// getting the name of the function
		CHAR* pFunctionName		= (CHAR*)(pBase + FunctionNameArray[i]);
		
		// getting the address of the function through its ordinal
		PVOID pFunctionAddress	= (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
		
		// searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0){
			// printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return pFunctionAddress;
		}
		
		// printf("[ %0.4d ] NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
	}


	return NULL;
}





int main() {

	printf("[+] Original GetProcAddress : 0x%p \n", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtAllocateVirtualMemory"));
	printf("[+] GetProcAddress Replacement : 0x%p \n", GetProcAddressReplacement(GetModuleHandleA("NTDLL.DLL"), "NtAllocateVirtualMemory"));

	return 0;

}


