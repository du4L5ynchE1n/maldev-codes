/*

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97
    f5d3d58503b9699de785895a96fdbaaf
    43b1cd7f598ece23881b00e3ed030688
    7b0c785e27e8ad3f8223207104725dd4


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h> // CBC mode, for memset
#include "aes.h"
#include <stdio.h>
#include <Windows.h>

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
#define Nk 8
#define Nr 14
#elif defined(AES192) && (AES192 == 1)
#define Nk 6
#define Nr 12
#else
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.
#endif

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];



// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static uint8_t sbox[] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0xA4, 0xCF, 0x10, 0xAA, 0xDC, 0xD2, 0x8D, 0x32, 0x0C, 0x52, 0x6E, 0xC1, 0x90, 0x0D, 0xF0, 0x0C,
        0xAF, 0xBF, 0x69, 0xDB, 0xC3, 0x59, 0x90, 0x4A, 0xA2, 0x51, 0xD2, 0x15, 0x72, 0x2F, 0xC9, 0xC3,
        0xAE, 0x3A, 0x20, 0x41, 0xE7, 0x11, 0x4E, 0x2E, 0xC3, 0x99, 0xB6, 0xF8, 0x9B, 0xB6, 0xEB, 0x4E,
        0x7E, 0xA2, 0x1E, 0x63, 0xBE, 0xAF, 0x05, 0x4D, 0xBD, 0x1D, 0x05, 0x92, 0x51, 0xC9, 0x39, 0xCE,
        0x0A, 0x9A, 0xEB, 0xA9, 0x7C, 0xBF, 0x74, 0x19, 0xB0, 0xCC, 0xEA, 0xE0, 0x20, 0x09, 0x41, 0x5E,
        0x08, 0xAB, 0x65, 0xD0, 0x80, 0x5A, 0x88, 0x5B, 0xBD, 0x71, 0xB1, 0xBC, 0x3A, 0xF6, 0xB6, 0x44,
        0x6B, 0xEC, 0xB3, 0x3C, 0xF0, 0x2A, 0xE2, 0xAB, 0xFC, 0x1B, 0xF5, 0x43, 0x03, 0x35, 0x75, 0xC6,
        0x8B, 0xF8, 0x3A, 0xEA, 0xAF, 0x3D, 0x9E, 0xCC, 0xBC, 0x61, 0x60, 0x2E, 0x95, 0x8F, 0x49, 0x3C,
        0x46, 0xB7, 0x10, 0xF5, 0x98, 0x24, 0x23, 0xC6, 0xEA, 0x1E, 0x9C, 0xCA, 0x58, 0x0E, 0x10, 0x99,
        0x0E, 0x5B, 0x14, 0xA6, 0x47, 0x17, 0x30, 0x2E, 0x7F, 0xEE, 0x6F, 0xAE, 0xD1, 0xDB, 0x7B, 0x61,
        0x0E, 0xB9, 0x81, 0x09, 0x50, 0xC1, 0x97, 0x3B, 0x13, 0xFD, 0x15, 0x80, 0x66, 0xA9, 0xB7, 0x70,
        0x0D, 0xA6, 0xED, 0x36, 0xF7, 0xB0, 0x73, 0x09, 0xCA, 0x6F, 0xF4, 0x3D, 0xDF, 0x75, 0x2B, 0x78,
        0x00, 0x96, 0xAE, 0x95, 0x1F, 0xBF, 0x73, 0x75, 0x8F, 0x0C, 0x5A, 0xA6, 0xA9, 0x4A, 0xB7, 0xD9,
        0x79, 0xD4, 0xDB, 0xBC, 0x13, 0x79, 0x93, 0x33, 0xC1, 0x93, 0x6E, 0xB9, 0x51, 0x7B, 0x12, 0x1B,
        0x91, 0x42, 0x76, 0x9A, 0xD2, 0xDA, 0x97, 0x53, 0x28, 0x79, 0x56, 0xC7, 0x77, 0xB7, 0xDF, 0xE3,
        0xDF, 0xA8, 0x63, 0x63, 0x65, 0xBD, 0x38, 0x0D, 0x7C, 0x39, 0x8B, 0x36, 0xB0, 0x83, 0x01, 0x19
 };

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static uint8_t rsbox[] = {
        0x95, 0xBA, 0x0D, 0x04, 0x1E, 0x8F, 0x47, 0xCF, 0x83, 0x13, 0xAA, 0x74, 0xEF, 0x29, 0x8C, 0x81,
        0x19, 0xDE, 0x99, 0x24, 0xA2, 0x2F, 0x28, 0x3D, 0x3B, 0x0B, 0x33, 0xFE, 0x2A, 0x55, 0x52, 0xC8,
        0x4D, 0xBC, 0x27, 0x55, 0x77, 0xEC, 0x9A, 0xDF, 0x19, 0x70, 0xC6, 0x02, 0xA8, 0x94, 0x19, 0x15,
        0x72, 0x4B, 0x9C, 0xC6, 0x8E, 0xE0, 0x24, 0x65, 0xCC, 0x54, 0x27, 0x39, 0xD7, 0x65, 0x5A, 0x9E,
        0x71, 0xE1, 0x31, 0xD7, 0xE1, 0xB9, 0xB6, 0xAF, 0x36, 0x53, 0x60, 0x9F, 0x54, 0x8F, 0xD8, 0x48,
        0x37, 0x0A, 0x2D, 0x6D, 0x5D, 0x4B, 0x80, 0xDA, 0x89, 0xAF, 0x49, 0xD2, 0xD7, 0x37, 0x73, 0x0F,
        0x2B, 0xDB, 0xB2, 0xC7, 0x3F, 0xDB, 0x02, 0x24, 0x4E, 0x06, 0xAF, 0x39, 0xEB, 0xBA, 0xAF, 0x68,
        0x0A, 0x77, 0x64, 0xEA, 0xF7, 0x9F, 0xA9, 0x3B, 0xC1, 0x78, 0x07, 0x0C, 0x84, 0x63, 0x30, 0x85,
        0xB1, 0x2A, 0x12, 0x58, 0x88, 0xD4, 0xBB, 0x3B, 0xB9, 0x4B, 0x2D, 0x39, 0xCC, 0xE7, 0xEF, 0x99,
        0xF8, 0x76, 0x2F, 0x58, 0x82, 0x90, 0x95, 0x23, 0xDB, 0xF9, 0xE0, 0x52, 0x13, 0xF0, 0xAF, 0xD4,
        0xA9, 0x7A, 0xA1, 0x72, 0x04, 0xEE, 0x76, 0xEE, 0xBE, 0x99, 0xDB, 0xEC, 0x5D, 0x24, 0xED, 0x12,
        0x16, 0x38, 0xE4, 0x10, 0xBC, 0xB7, 0x44, 0x80, 0x3C, 0xE2, 0xC0, 0x29, 0xC2, 0xC2, 0xDF, 0x84,
        0xA5, 0x33, 0x23, 0x88, 0x8B, 0x1E, 0x00, 0x82, 0xD6, 0xC3, 0x3E, 0xE0, 0xC5, 0x77, 0xD0, 0x0C,
        0x69, 0xBB, 0x11, 0x73, 0x42, 0xCF, 0x2F, 0x30, 0x8D, 0x43, 0x43, 0x9F, 0x44, 0x73, 0x93, 0x6A,
        0xD0, 0x5A, 0xD5, 0xC6, 0x15, 0x29, 0xEC, 0x77, 0x7B, 0x8C, 0x6A, 0x12, 0x3A, 0xB1, 0x6E, 0x5D,
        0x44, 0x22, 0xEE, 0x10, 0x60, 0x2C, 0xAC, 0x43, 0xDC, 0xC9, 0xB2, 0x5A, 0x55, 0xF6, 0xB6, 0x72 };
#endif

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static uint8_t Rcon[] = {
  0x4A, 0xB2, 0x65, 0xD5, 0x26, 0xA9, 0xC2, 0xB7, 0xBC, 0x48, 0x3F };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 *
 * "Only the first some of these constants are actually used � up to rcon[10] for AES-128 (as 11 round keys are needed),
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


 /*****************************************************************************/
 /* Private functions:                                                        */
 /*****************************************************************************/
 /*
 static uint8_t getSBoxValue(uint8_t num)
 {
   return sbox[num];
 }
 */
#define getSBoxValue(num) (sbox[(num)])

 // This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
    unsigned i, j, k;
    uint8_t tempa[4]; // Used for the column/row operations

    // The first round key is the key itself.
    for (i = 0; i < Nk; ++i)
    {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = Nk; i < Nb * (Nr + 1); ++i)
    {
        {
            k = (i - 1) * 4;
            tempa[0] = RoundKey[k + 0];
            tempa[1] = RoundKey[k + 1];
            tempa[2] = RoundKey[k + 2];
            tempa[3] = RoundKey[k + 3];

        }

        if (i % Nk == 0)
        {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }

            // SubWord() is a function that takes a four-byte input word and 
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            {
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }

            tempa[0] = tempa[0] ^ Rcon[i / Nk];
        }
#if defined(AES256) && (AES256 == 1)
        if (i % Nk == 4)
        {
            // Function Subword()
            {
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }
        }
#endif
        j = i * 4; k = (i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}


void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
    KeyExpansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
    KeyExpansion(ctx->RoundKey, key);
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
        }
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
    uint8_t temp;

    // Rotate first row 1 columns to left  
    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left  
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
    }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^
        ((y >> 1 & 1) * xtime(x)) ^
        ((y >> 2 & 1) * xtime(xtime(x))) ^
        ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
        ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
}
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i)
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = getSBoxInvert((*state)[j][i]);
        }
    }
}

static void InvShiftRows(state_t* state)
{
    uint8_t temp;

    // Rotate first row 1 columns to right  
    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    // Rotate second row 2 columns to right 
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without MixColumns()
    for (round = 1; ; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        if (round == Nr) {
            break;
        }
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }
    // Add round key to last round
    AddRoundKey(Nr, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(Nr, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without InvMixColumn()
    for (round = (Nr - 1); ; --round)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, RoundKey);
        if (round == 0) {
            break;
        }
        InvMixColumns(state);
    }

}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

/*
    - pShellcode : Base address of the payload to encrypt
    - sShellcodeSize : The size of the payload
    - bKey : A random array of bytes of specific size
    - sKeySize : The size of the key
*/

VOID XorFunction(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
    for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
        if (j > sKeySize) {
            j = 0;
        }
        pShellcode[i] = pShellcode[i] ^ bKey[j];
    }
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

    printf("unsigned char %s[] = {", Name);

    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0) {
            printf("\n\t");
        }
        if (i < Size - 1) {
            printf("0x%0.2X, ", Data[i]);
        }
        else {
            printf("0x%0.2X ", Data[i]);
        }
    }

    printf("};\n\n\n");

}

// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

    for (int i = 0; i < sSize; i++) {
        pByte[i] = (BYTE)rand() % 0xFF;
    }
}

VOID DecryptAesArrays(){

    unsigned char randomKey[] = {
        0xC7, 0xB3, 0x67, 0xD1, 0x2E, 0xB9, 0xE2, 0xF7, 0x3C, 0x53, 0x09, 0xEA, 0x6E, 0xDA, 0x5B, 0x7A,
        0x65, 0x3D, 0xA0, 0xA6, 0x39, 0x00, 0xD7, 0xBA, 0x0F, 0x85, 0x70, 0xBA, 0xEE, 0x8B, 0xBB, 0x03 };

    XorFunction(sbox, sizeof(sbox), randomKey, sizeof(randomKey));
    XorFunction(rsbox, sizeof(rsbox), randomKey, sizeof(randomKey));
    XorFunction(Rcon, sizeof(Rcon), randomKey, sizeof(randomKey));

};

VOID PrintAesArrays() {

    PrintHexData("sbox", sbox, sizeof(sbox));
    PrintHexData("rsbox", rsbox, sizeof(rsbox));
    PrintHexData("Rcon", Rcon, sizeof(Rcon));
}


#if defined(ECB) && (ECB == 1)


void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
    // The next function call encrypts the PlainText with the Key using AES algorithm.
    Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
    // The next function call decrypts the PlainText with the Key using AES algorithm.
    InvCipher((state_t*)buf, ctx->RoundKey);
}


#endif // #if defined(ECB) && (ECB == 1)





#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
    uint8_t i;
    for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
    {
        buf[i] ^= Iv[i];
    }
}

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
    size_t i;
    uint8_t* Iv = ctx->Iv;
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        XorWithIv(buf, Iv);
        Cipher((state_t*)buf, ctx->RoundKey);
        Iv = buf;
        buf += AES_BLOCKLEN;
    }
    /* store Iv in ctx for next call */
    memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
    size_t i;
    uint8_t storeNextIv[AES_BLOCKLEN];
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        memcpy(storeNextIv, buf, AES_BLOCKLEN);
        InvCipher((state_t*)buf, ctx->RoundKey);
        XorWithIv(buf, ctx->Iv);
        memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }

}

#endif // #if defined(CBC) && (CBC == 1)



#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
    uint8_t buffer[AES_BLOCKLEN];

    size_t i;
    int bi;
    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
    {
        if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
        {

            memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((state_t*)buffer, ctx->RoundKey);

            /* Increment Iv and handle overflow */
            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
            {
                /* inc will overflow */
                if (ctx->Iv[bi] == 255)
                {
                    ctx->Iv[bi] = 0;
                    continue;
                }
                ctx->Iv[bi] += 1;
                break;
            }
            bi = 0;
        }

        buf[i] = (buf[i] ^ buffer[bi]);
    }
}

#endif // #if defined(CTR) && (CTR == 1)
