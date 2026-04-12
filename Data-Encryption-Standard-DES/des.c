#include <stdio.h>
#include <string.h>
#include <stdint.h>

//Initial Permutation Table
static const int init_permutation_table[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

//Reversing the Initial Permutation Table
static const int inverse_init_permutation_table[] ={
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25 
};

// Expansion Table for each round - confusion
// 32 bits of right half converted to 48 bits by using certain bits multiple times
static const int expansion_table[] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

//Permutation Table for each round - diffusion
static const int permute_table[] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

// Key Schedule - Permutated Choice 1
// dropping 8 parity bits to get 56 bit key and shifting 64 bit key
static const int PC1[] = {
    //C half
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    //D half
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

// left Shift order for 16 rounds of key generation
// 1, 2, 9, 16 th rounds use 1 bit left shift, rest use 2 bits left shift 
static const int shifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Key Schedule - Permutated Choice 2
// selecting 48 bits from 56 bit sub key(c+d) to be used in each round
static const int PC2[] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

// 8 S-Boxes (Substitution Boxes) - only non linear part of DES, used for confusion
// 8 S-Boxes, each takes 6 bit i/p and gives 4 bit o/p, so total 48 bit i/p gives 32 bit o/p
// Each s box has 4(0-3 in binary) rows and 16 columns(0-15 in binary)
// Row is 1st & 6th bit of input, column is 2nd to 5th bit of input
// for eg, 101010 i/p, row = 10(2 in decimal), column = 0101(5 in decimal) so output is sbox[row][column]
static const int SBOX[8][4][16] = {
    // S1
    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
     {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
    // S2
    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
    // S3
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
     {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
     {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
     {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
    // S4
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
    // S5
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
     {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
     {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
     {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
    // S6
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
     {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
     {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
     {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
    // S7
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
    // S8
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

// Function to perform permutation based on a given table
// used in initial permutation, inverse initial permutation, expansion and round permutation
uint64_t permute(uint64_t input, const int *table, int input_size, int n) {
    uint64_t output = 0;
    for(int i = 0; i<n; i++){
        int pos = table[i] -1;
        uint64_t bit = (input >> (input_size - pos -1)) & 1;
        output = (output << 1) | bit;
    }
    return output;
}

// Function to perform left circular shift - used in key generation
uint32_t left_shift(uint32_t val, int shift) {
    return ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
}

// function to convert 8 bytes to 64 bit uint64_t integer 
uint64_t bytes_to_u64(const uint8_t *x) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | x[i];
    return v;
}

// function to convert 64 bit uint64_t integer back to 8 bytes
void u64_to_bytes(uint64_t v, uint8_t *x) {
    for (int i = 7; i >= 0; i--) {
        x[i] = v & 0xFF;
        v >>= 8;
    }
}

// Function to generate 16 round keys from the main key
void generate_round_keys(uint64_t key, uint64_t round_keys[16]) {
    // Apply PC1 to get 56 bit key
    uint64_t key56 = permute(key, PC1, 64, 56);

    // Split into two halves
    uint32_t C = (key56 >> 28) & 0x0FFFFFFF; // Left half
    uint32_t D = key56 & 0x0FFFFFFF; // Right half

    for(int i = 0; i < 16; i++) {
        // rotate halves according to shift schedule
        C = left_shift(C, shifts[i]);
        D = left_shift(D, shifts[i]);

        // Combine halves and apply PC2 to get round key
        uint64_t combined_key = ((uint64_t)C << 28) | D;
        round_keys[i] = permute(combined_key, PC2, 56, 48);
    }
}

// Round function for every round of DES
// expand -> xor with Ki -> sbox substitution -> permutation
uint32_t feistel_f(uint32_t R, uint64_t Ki) {
    // Expansion
    uint64_t expanded_R = permute(R, expansion_table, 32, 48);

    // XOR with round key
    uint64_t xored = expanded_R ^ Ki;

    // S-Box substitution
    uint32_t output = 0;
    for(int i = 0; i < 8; i++) {
        int six_bits = (xored >> (42 - 6*i)) & 0x3F; // Get 6 bits for current S-Box
        int row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01); // Row from 1st and 6th bit
        int col = (six_bits >> 1) & 0x0F; // Column from middle 4 bits
        output = (output << 4) | SBOX[i][row][col]; // Append S-Box output
    }

    // Permutation
    return permute(output, permute_table, 32, 32);
}

// Function to encrypt a 64 bit block using DES - CORE BLOCK OF DES
uint64_t des_encrypt(uint64_t plaintext, uint64_t round_keys[16], int encrypt) {
    
    //Initial Permutation
    uint64_t ip = permute(plaintext, init_permutation_table, 64, 64);

    //Split into two halves
    uint32_t L = (ip >> 32) & 0xFFFFFFFF;
    uint32_t R =  ip & 0xFFFFFFFF;

    //16 Feistel Rounds
    for (int i = 0; i < 16; i++) {
        uint64_t Ki = encrypt ? round_keys[i] : round_keys[15 - i];
        uint32_t new_R = L ^ feistel_f(R, Ki); // left-half xored with output of round function
        L = R; // old right becomes new left
        R = new_R;
    }

    //Swap halves
    uint64_t combined = ((uint64_t)R << 32) | L;

    // reversing the initial permutation
    return permute(combined, inverse_init_permutation_table, 64, 64);
}

// Encrypts a plaintext string using DES with PKCS#5 padding
void des_encrypt_string(const char *plaintext, uint64_t key, uint8_t *out, int *out_len){
     uint64_t round_keys[16];
     generate_round_keys(key, round_keys);

    int len = strlen(plaintext);
    int padded_len = ((len / 8) + 1) * 8;
    uint8_t padded[256] = {0};
    memcpy(padded, plaintext, len);

    //fill padding bytes with the pad value 
    uint8_t pad_val = padded_len - len;
    for (int i = len; i < padded_len; i++)
        padded[i] = pad_val;

    // Encrypt each 8-byte block independently 
    for (int i = 0; i < padded_len; i += 8) {
        uint64_t block  = bytes_to_u64(&padded[i]);
        uint64_t cipher = des_encrypt(block, round_keys, 1); 
        u64_to_bytes(cipher, &out[i]);
    }
    *out_len = padded_len;
};

//function that converts DES encrypted bytes back to string and removes padding
void des_decrypt_string(const uint8_t *ciphertext, int len, uint64_t key, char *out) {
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    uint8_t decrypted[256] = {0};

    // decryptas each 8-byte block independently
    for (int i = 0; i<len; i += 8) {
        uint64_t block = bytes_to_u64(&ciphertext[i]);
        uint64_t plain = des_encrypt(block, round_keys, 0); 
        u64_to_bytes(plain, &decrypted[i]);
    }

    // strips padding
    int pad_val  = decrypted[len - 1]; 
    int real_len= len - pad_val;
    memcpy(out, decrypted, real_len);
    out[real_len] = '\0';
}

int main() {
    const char *secret_msg = "DES encryption demo";
    uint64_t key = 0x0123456789ABCDEF; 
    uint8_t ciphertext[256];
    int ciphertext_len;

    des_encrypt_string(secret_msg, key, ciphertext, &ciphertext_len);

    printf("Ciphertext in hex: ");
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02X ", ciphertext[i]);
    printf("\n");

    char decrypted[256];
    des_decrypt_string(ciphertext, ciphertext_len, key, decrypted);
    printf("Decrypted text: %s\n", decrypted);

    return 0;
}

