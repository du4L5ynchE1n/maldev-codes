#include <Windows.h>
#include <stdio.h>

// "Structs.h" defines some structs from <winternl.h>, so if both included there will be redefinition errors
// to use winternl instead, comment the following (#include "Structs.h")


#include "Structs.h"

#ifndef STRUCTS
#include <winternl.h>
#endif // !STRUCTS

// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))



// function helper that takes 2 strings
// convert them to lower case strings
// compare them, and return true if both are equal
// and false otherwise
BOOL IsStringEqual (IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR	lStr1	[MAX_PATH],
			lStr2	[MAX_PATH];

	int		len1	= lstrlenW(Str1),
			len2	= lstrlenW(Str2);

	int		i		= 0,
			j		= 0;

	// checking - we dont want to overflow our buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++){
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating


	// converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating


	// comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}



// function that replaces GetModuleHandle
// it uses pointers to enumerate in the dlls  
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {

	// getting peb
#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb		= (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb		= (PEB*)(__readfsdword(0x30));
#endif

	// geting Ldr
	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)(pPeb->Ldr);
	// getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte		= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	
	while (pDte) {
		
		// if not null
		if (pDte->FullDllName.Length != NULL) {

			// check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS

			}

			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}
		
		// next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}





// function that replaces GetModuleHandle
// it uses head and node to enumerate in the dlls (doubly linked list concept)
// if you are not familiar with doubly linked lists its ok, you have the above implemantation
// that is more friendly

HMODULE GetModuleHandleReplacement2(IN LPCWSTR szModuleName) {

#ifdef _WIN64
	PPEB					pPeb				= (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb				= (PEB*)(__readfsdword(0x30));
#endif

	PLDR_DATA_TABLE_ENTRY	pDte				= (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);
	
	// getting the head of the linked list ( used to get the node & to check the end of the list)
	PLIST_ENTRY				pListHead			= (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
	// getting the node of the linked list
	PLIST_ENTRY				pListNode			= (PLIST_ENTRY)pListHead->Flink;

	do
	{
		if (pDte->FullDllName.Length != NULL) {
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS
			}

			//wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);

			// updating pDte to point to the next PLDR_DATA_TABLE_ENTRY in the linked list
			pDte = (PLDR_DATA_TABLE_ENTRY)(pListNode->Flink);

			// updating the node variable to be the next node in the linked list
			pListNode = (PLIST_ENTRY)pListNode->Flink;

		}

	// when the node is equal to the head, we reached the end of the linked list, so we break out of the loop
	} while (pListNode != pListHead);



	return NULL;
}










int main() {

	

	printf("[i] Original 0x%p \n", GetModuleHandleW(L"NTDLL.DLL"));

	printf("[i] Replacement 0x%p \n", GetModuleHandleReplacement(L"NTDLL.DLL"));
	printf("[i] Replacement 2 0x%p \n", GetModuleHandleReplacement2(L"NTDLL.DLL"));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;

}
































