#include <stdio.h>
#include <Windows.h>

int main() {
    // Specify the desired access rights to the process
    DWORD desiredAccess = PROCESS_QUERY_INFORMATION;

    // Set to TRUE to open the process with the specified access rights
    BOOL inheritHandle = FALSE;

    // Get the process ID of the target process (you can find the process ID using tools like Task Manager)
    DWORD processId = 6088; // Replace with the actual process ID

    // Open the process
    HANDLE hProcess = OpenProcess(desiredAccess, inheritHandle, processId);
    if (hProcess == NULL) {
        fprintf(stderr, "Failed to open process. Error code: %lu\n", GetLastError());
        return 1;
    }

    // Get the process ID from the handle (this is just to demonstrate usage)
    DWORD retrievedProcessId = GetProcessId(hProcess);
    printf("Retrieved process ID: %lu\n", retrievedProcessId);

    // Close the process handle
    CloseHandle(hProcess);

    return 0;
}
