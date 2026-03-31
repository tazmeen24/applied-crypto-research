// PRESENT algorithm implementation in C

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Initializing S-boxes and Inverse S-boxes
uint8_t SBOX[16] = { 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
uint8_t SBOX_INV[16] = { 0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

// Permutation tables initialization
uint8_t PERM[64];
uint8_t PERM_INV[64];

// permutation tables using P(i)=(16*i)%63
void init_tables(){
    for (int i = 0; i < 63; i++)
        PERM[i] = (16 * i) % 63;
    PERM[63] = 63;
    for (int i = 0; i < 64; i++)
        PERM_INV[PERM[i]] = i;
}

// S-box for all 16 nibbles of the 64-bit state
uint64_t substitution(uint64_t state, uint8_t *box){
    uint64_t result = 0;
    for (int i = 0; i < 16; i++){
        int shift = 60 - 4 * i;
        result |= (uint64_t)box[(state >> shift) & 0xF] << shift;
    }
    return result;
}

// function moves each bit to its new position
uint64_t permutation(uint64_t state, uint8_t *perm){
    uint64_t result = 0;
    for (int i = 0; i < 64; i++){
        uint64_t bit = (state >> (63 - i)) & 1;
        result |= bit << (63 - perm[i]);
    }
    return result;
}

// function generates 32 round keys from the 80-bit master key
void key_schedule(uint16_t key_hi, uint64_t key_lo, uint64_t rk[32]){
    for (int round = 1; round <= 32; round++){
        // Extracts leftmost 64 bits as round key
        rk[round - 1] = ((uint64_t)key_hi << 48) | (key_lo >> 16);
        if (round == 32)
            break;
        // Rotate left by 61
        uint64_t top19 = ((uint64_t)key_hi << 3) | (key_lo >> 61);
        uint64_t bot61 = key_lo & 0x1FFFFFFFFFFFFFFFULL;
        key_hi = (uint16_t)(bot61 >> 45);
        key_lo = (bot61 << 19) | top19;
        // S-box the top 4 bits
        uint8_t top4 = key_hi >> 12;
        key_hi = (key_hi & 0x0FFF) | (SBOX[top4] << 12);
        // XOR round counter into bits 19 to 15
        key_lo ^= (uint64_t)round << 15;
    }
}

// Encrypting 64-bit block
uint64_t encrypt(uint64_t plaintext, uint16_t key_hi, uint64_t key_lo){
    uint64_t rk[32];
    key_schedule(key_hi, key_lo, rk);
    uint64_t state = plaintext;
    for (int r = 0; r < 31; r++) {
        state ^= rk[r]; // Combining the key using XOR
        state = substitution(state, SBOX); // Substitution
        state = permutation(state, PERM); // Permutation
    } return state ^ rk[31]; // Combining the final key using XOR 
}

// Decrypting 64-bit block
uint64_t decrypt(uint64_t ciphertext, uint16_t key_hi, uint64_t key_lo){
    uint64_t rk[32];
    key_schedule(key_hi, key_lo, rk);
    uint64_t state = ciphertext ^ rk[31]; // Undo final key XOR
    for (int r = 30; r >= 0; r--){
        state = permutation(state, PERM_INV); // Inverse Permutation
        state = substitution(state, SBOX_INV); // Inverse Substitution
        state ^= rk[r]; // Undo Key XOR
    } return state;
}

int main(){
    init_tables();
    uint64_t plaintext = 0x0123456789ABCDEF;
    uint16_t key_hi = 0x2026;
    uint64_t key_lo = 0x300320261843CAFE;
    uint64_t cipher = encrypt(plaintext, key_hi, key_lo);
    uint64_t decrypted = decrypt(cipher, key_hi, key_lo);
    printf("Plaintext : %016llX\n", plaintext);
    printf("Key : %04X%016llX\n", key_hi, key_lo);
    printf("Ciphertext : %016llX\n", cipher);
    printf("Decrypted : %016llX\n", decrypted);
    printf("Encryption And Decryption : %s\n", decrypted == plaintext ? "SUCCESSFULL" : "NOT SUCCESSFUL");
    return 0;
}
