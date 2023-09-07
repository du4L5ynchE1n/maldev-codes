#include <Windows.h>
#include <stdio.h>

typedef void (WINAPI* HelloUserFunctionPointer)();

int main() {
    // Load the DLL and get a handle
    HMODULE hModule = LoadLibraryA("C:\\Users\\Administrator\\source\\repos\\MalDevDll\\x64\\Debug\\MalDevDll.dll");
    if (hModule == NULL) {
        printf("Failed to load DLL. Error code: %d\n", GetLastError());
        return 1;
    }

    // Get a function pointer to the exported function by finding it's address
    HelloUserFunctionPointer helloUser = (HelloUserFunctionPointer)GetProcAddress(hModule, "HelloUser");
    if (helloUser != NULL) {
        // Call the exported function
        helloUser();
    }
    else {
        printf("Failed to locate function. Error code: %d\n", GetLastError());
    }

    // Unload the DLL
    FreeLibrary(hModule);

    return 0;
}
