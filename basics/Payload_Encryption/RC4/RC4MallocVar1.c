// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>


// Reference - https://www.oryx-embedded.com/doc/rc4_8c_source.html

typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;




void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	//Check parameters
	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		// Randomize the permutations using the supplied key
		j = (j + context->s[i] + key[i % length]) % 256;

		// Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}


void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// If the input and output are valid
		if (input != NULL && output != NULL)
		{
			// XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			// Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
}


unsigned char shellcode[] = { 
	"This is very spooky stuff, doing rc4 encryption !" 
};

unsigned char key[] = { 
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};




int main() {
	// Intializing the struct
	Rc4Context ctx = { 0 };
	rc4Init(&ctx, key, sizeof(key));


	// Encryption
	unsigned char* Ciphertext = (unsigned char*)malloc(strlen(shellcode) * sizeof(int)); // Allocating and cleaning [this is the output of the encryption]
	ZeroMemory(Ciphertext, strlen(shellcode) * sizeof(int));
	rc4Cipher(&ctx, shellcode, Ciphertext, strlen(shellcode));
	printf("[i] Ciphertext : 0x%p \n", Ciphertext);
	
	
	printf("[#] Press <Enter> To Decrypt...");
	getchar();


	// Intializing the struct, in case of any errors / changes in the structure's bytes
	rc4Init(&ctx, key, sizeof(key));


	// Decryption
	unsigned char* PlainText = (unsigned char*)malloc(strlen(shellcode) * sizeof(int)); // Allocating and cleaning [this is the output of the decryption]
	ZeroMemory(PlainText, strlen(shellcode) * sizeof(int));
	rc4Cipher(&ctx, Ciphertext, PlainText, strlen(shellcode));

	// Printing the shellcode's string
	printf("[i] PlainText : \"%s\" \n", (char*)PlainText);



	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	free(Ciphertext);
	free(PlainText);
	return 0;

}

