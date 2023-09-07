// dllmain.c : Defines the entry point for the DLL application.
#include <Windows.h>
#include <stdio.h>

//exported function declared with extern __declspec(dllexport)
extern __declspec(dllexport) void HelloUser() {
    char buffer[256];
    DWORD bufferSize = sizeof(buffer);

    if (GetUserNameA(buffer, &bufferSize)) {
        char message[256];
        sprintf_s(message, sizeof(message), "Hello, %s!", buffer);
        MessageBoxA(NULL, message, "Username Message", MB_OK);
    }
    else {
        printf("Failed to retrieve username. Error code: %lu\n", GetLastError());
    }
}
BOOL APIENTRY DllMain(
    HANDLE hModule,             // Handle to DLL module
    DWORD ul_reason_for_call,   // Reason for calling function
    LPVOID lpReserved           // Reserved
) {

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        // Do something here
        break;
    case DLL_THREAD_ATTACH: // A process is creating a new thread.
        // Do something here
        break;
    case DLL_THREAD_DETACH: // A thread exits normally.
        // Do something here
        break;
    case DLL_PROCESS_DETACH: // A process unloads the DLL.
        // Do something here
        break;
    }
    return TRUE;
}
