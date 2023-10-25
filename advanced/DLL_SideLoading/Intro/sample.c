#include <Windows.h>


extern __declspec(dllexport) PVOID DtcMainExt() {
    MessageBoxA(NULL, "This DLL is Side-Loaded!", "Success!", MB_OK | MB_ICONEXCLAMATION);
    return NULL;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved){

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

