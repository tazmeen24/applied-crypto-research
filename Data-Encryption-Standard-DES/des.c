#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "des.h"

// this is for permutation operation
uint64_t permute(uint64_t input, const int *table, int input_size, int n){
    uint64_t output = 0;
    for (int i = 0; i < n; i++){
        int pos = table[i] - 1;
        uint64_t shifted = (input >> (input_size-pos-1));
        uint64_t extracted = shifted & 1;
        output = (output << 1) | extracted;
    }
    return output;
}

// left shift or rotation, rotates bits by shift positions
uint32_t left_rotation(uint32_t val, int shift){
    uint32_t left = val << shift;
    uint32_t right = val >> (28 - shift);
    uint32_t result = left | right;
    return result & 0x0FFFFFFF;
}

uint64_t bytes_to_u64(const uint8_t *x){
    uint64_t v = 0;
    for (int i=0; i<8; i++){
        v = (v<<8);
        v |= x[i];
    }
    return v;
}

void u64_to_bytes(uint64_t v, uint8_t *x){
    for (int i=7; i>=0; i--){
        x[i] = v & 0xFF;
        v >>= 8;
    }
}

// this function is used to generate 16 round keys from the main key
void generate_sub_keys(uint64_t key, uint64_t round_keys[16]){
    uint64_t key56 = permute(key, PC1, 64, 56);

    uint32_t C = (key56 >> 28) & 0x0FFFFFFF;
    uint32_t D = key56 & 0x0FFFFFFF;

    printf("Round keys:\n");
    for (int round = 0; round < 16; round++){
        C = left_rotation(C, shifts[round]);
        D = left_rotation(D, shifts[round]);
        uint64_t combined = ((uint64_t)C << 28) | D;
        round_keys[round] = permute(combined, PC2, 56, 48);
        // this printf is for testing the generated round keys
        printf("Round key for round %2d : %012lX\n", round + 1, round_keys[round]);
    }
    printf("\n");
}

// feistel structure - round function
uint32_t feistel(uint32_t R, uint64_t K){
    uint64_t expanded_right_part = permute(R, expansion_table, 32, 48);
    uint64_t xored = expanded_right_part ^ K;
    uint32_t output = 0;

    for (int i = 0; i < 8; i++){
        int six_bits = (xored >> (42 - 6 * i)) & 0x3F;
        int row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
        int col = (six_bits >> 1) & 0x0F;
        output = (output << 4) | SBOX[i][row][col];
    }
    return permute(output, permute_table, 32, 32);
}

// encryption and decryption, option 1 for encryption, 0 for decryption
uint64_t des_encrypt(uint64_t plaintext, uint64_t round_keys[16], int encrypt){
    uint64_t permutated = permute(plaintext, init_permutation_table, 64, 64);
    uint32_t left = (permutated >> 32) & 0xFFFFFFFF;
    uint32_t right = permutated & 0xFFFFFFFF;

    for (int round = 0; round < 16; round++){
        uint64_t key;
        if (encrypt == 1){
            key = round_keys[round];
        }
        else{
            key = round_keys[15 - round];
        }
        uint32_t temp = right;
        right = left ^ feistel(right, key);
        left = temp;
    }
    uint64_t combined = ((uint64_t)right << 32) | left;
    return permute(combined, inverse_init_permutation_table, 64, 64);
}

// encrypts a plaintext string
void des_encrypt_str(const char *text, uint64_t round_keys[16], uint8_t *out, int *out_len){
    //generate_sub_keys(key, keys);
    int len = strlen(text);
    int total = ((len / 8) + 1) * 8;
    uint8_t data[256] = {0};

    for (int i = 0; i < len; i++)
        data[i] = text[i];

    int pad = total - len;
    for (int i = len; i < total; i++)
        data[i] = pad;

    for (int i = 0; i < total; i += 8){
        uint64_t block = bytes_to_u64(&data[i]);
        uint64_t enc = des_encrypt(block, round_keys, 1);
        u64_to_bytes(enc, &out[i]);
    }
    *out_len = total;
}

// decrypts the ciphertext
void des_decrypt_str(const uint8_t *cipher, int len, uint64_t round_keys[16], char *out){
    //generate_sub_keys(key, keys);
    uint8_t temp[256] = {0};

    for (int i = 0; i < len; i += 8){
        uint64_t block = bytes_to_u64(&cipher[i]);
        uint64_t decrypted = des_encrypt(block, round_keys, 0);
        u64_to_bytes(decrypted, &temp[i]);
    }

    int pad = temp[len - 1];
    int real_len = len - pad;
    for (int i = 0; i < real_len; i++)
    {
        out[i] = temp[i];
    }
    out[real_len] = '\0';
}

int main(){
    // msg we want to encrypt
    const char *secret_msg = "DES encryption demo";

    // sample 64 bit key for testing
    uint64_t key = 0x0123456789ABCDEF;
    
    printf("Original message: %s\n", secret_msg);
    printf("Key: %012lX\n\n", key);

    uint8_t ciphertext[256]; // buffer
    char decrypted[256];
    int ciphertext_len;

    uint64_t keys[16];
    generate_sub_keys(key, keys);

    des_encrypt_str(secret_msg, keys, ciphertext, &ciphertext_len); // encrypt
    des_decrypt_str(ciphertext, ciphertext_len, keys, decrypted); // decrypt

    printf("Ciphertext in hex: ");
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02X ", ciphertext[i]);
    printf("\n");

    printf("Decrypted text: %s\n", decrypted);

    return 0;
}


/*
Original message: DES encryption demo
Key: 000089ABCDEF

Round keys:
Round key for round  1 : 0000679B49A5
Round key for round  2 : 000059256A26
Round key for round  3 : 00008AB428D2
Round key for round  4 : 0000D2A58257
Round key for round  5 : 00000317A6C2
Round key for round  6 : 00001E3C8545
Round key for round  7 : 0000950AE4C6
Round key for round  8 : 0000386CE581
Round key for round  9 : 0000E926B839
Round key for round 10 : 000007631D72
Round key for round 11 : 0000830D893A
Round key for round 12 : 0000E5455C54
Round key for round 13 : 0000D04980FC
Round key for round 14 : 0000B681DC8D
Round key for round 15 : 0000050A16B5
Round key for round 16 : 000003B87032

Ciphertext in hex:
90 F6 4C AF 54 C0 D8 BD B8 0E 8F 36 22 9E CE 18 61 F9 9B 11 85 32 6A DE

Decrypted text: DES encryption demo
*/
