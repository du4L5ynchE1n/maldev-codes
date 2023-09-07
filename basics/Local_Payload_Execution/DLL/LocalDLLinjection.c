#include <Windows.h>
#include <stdio.h>

//LocalDllinjection.exe .\LocalExecute.dll
int main(int argc, char* argv[]) {

	// Checking the command line arguments
	if (argc < 2) {
		printf("[!] Missing Argument; Dll Payload To Run \n");
		return -1;
	}

	printf("[i] Injecting \"%s\" To The Local Process Of Pid: %d \n", argv[1], GetCurrentProcessId());


	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
	printf("[+] Loading Dll ... ");
	if (LoadLibraryA(argv[1]) == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE ! \n");



	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
