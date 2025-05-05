/**
 * key_derivation.c - Implementation of simple password-based key derivation
 * 
 * This file implements a simplified password-based key derivation function
 * using only allowed libraries: stdio.h, stdlib.h, string.h, and math.h
 */

#include "encryption/key_derivation.h"
#include <stdlib.h>  /* For rand() */
#include <string.h>  /* For strlen(), memcpy(), memset() */

/* Debug printing support */
#ifdef KDF_DEBUG
#include <stdio.h> /* For printf in debug mode */
#define DEBUG_PRINT(...) printf("[KDF] " __VA_ARGS__)
#define PRINT_HEX(label, data, len) print_hex(label, data, len)

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("[KDF] %s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 4 == 0) printf(" ");
    }
    printf("\n");
}
#else
#define DEBUG_PRINT(...)
#define PRINT_HEX(label, data, len)
#endif

/**
 * Simple key derivation function - uses password and salt to derive a key
 * 
 * @param password   Input password
 * @param salt       Salt value 
 * @param salt_len   Length of salt
 * @param iterations Number of iterations for strengthening
 * @param output     Output buffer for derived key
 * @param output_len Length of output buffer
 */
static void derive_key(const char *password, const uint8_t *salt, size_t salt_len,
                      unsigned int iterations, uint8_t *output, size_t output_len) {
    size_t password_len = strlen(password);
    size_t i, j, k;
    uint8_t hash[256]; // Temporary buffer for hash calculation
    
    // Initialize hash with password
    for (i = 0; i < sizeof(hash); i++) {
        hash[i] = (i < password_len) ? password[i] : 0;
    }
    
    // Mix in salt if provided
    if (salt != NULL && salt_len > 0) {
        for (i = 0; i < salt_len; i++) {
            hash[i % sizeof(hash)] ^= salt[i];
        }
    }
    
    // Multiple rounds of mixing for strengthening
    for (i = 0; i < iterations; i++) {
        // Simple mixing function - rotate and XOR
        uint8_t prev = hash[0];
        uint8_t tmp;
        
        for (j = 0; j < sizeof(hash); j++) {
            tmp = hash[(j + 1) % sizeof(hash)];
            hash[(j + 1) % sizeof(hash)] = (hash[j] << 4) | (hash[j] >> 4);
            hash[j] ^= prev;
            prev = tmp;
            
            // Additional mixing every 16 bytes
            if ((j % 16) == 15) {
                for (k = j - 15; k <= j; k++) {
                    hash[k] ^= hash[(k + 7) % sizeof(hash)];
                }
            }
        }
        
        // Mix in the iteration count
        hash[i % sizeof(hash)] ^= (i & 0xFF);
        hash[(i + 1) % sizeof(hash)] ^= ((i >> 8) & 0xFF);
        hash[(i + 2) % sizeof(hash)] ^= ((i >> 16) & 0xFF);
        hash[(i + 3) % sizeof(hash)] ^= ((i >> 24) & 0xFF);
    }
    
    // Copy the result to the output
    for (i = 0; i < output_len; i++) {
        output[i] = hash[i % sizeof(hash)];
    }
    
    // Clear sensitive data
    memset(hash, 0, sizeof(hash));
}

int generate_salt(uint8_t *salt, size_t salt_len) {
    if (salt == NULL || salt_len == 0) {
        return -1;
    }
    
    static unsigned int seed = 0xA1A49B7E; // Arbitrary starting seed
    
    // Update seed using linear congruential generator
    for (size_t i = 0; i < salt_len; i++) {
        // LCG parameters from Numerical Recipes
        seed = seed * 1664525 + 1013904223;
        salt[i] = (uint8_t)(seed & 0xFF);
    }
    
    DEBUG_PRINT("Generated salt (%zu bytes)\n", salt_len);
    PRINT_HEX("Salt", salt, salt_len);
    
    return 0;
}

int derive_key_and_nonce(const char *password, 
                        const uint8_t *salt, size_t salt_len,
                        unsigned int iterations,
                        uint8_t *key, size_t key_len,
                        uint8_t *nonce, size_t nonce_len) {
    if (password == NULL || key == NULL || key_len == 0 ||
        nonce == NULL || nonce_len == 0) {
        return -1;
    }
    
    size_t total_len = key_len + nonce_len;
    uint8_t *derived = (uint8_t *)malloc(total_len);
    
    if (derived == NULL) {
        return -1;
    }
    
    DEBUG_PRINT("Deriving key and nonce from password (%zu chars)\n", strlen(password));
    DEBUG_PRINT("Using %u iterations\n", iterations);
    
    // Derive the combined key and nonce
    derive_key(password, salt, salt_len, iterations, derived, total_len);
    
    // Copy to output buffers
    memcpy(key, derived, key_len);
    memcpy(nonce, derived + key_len, nonce_len);
    
    PRINT_HEX("Derived key", key, key_len);
    PRINT_HEX("Derived nonce", nonce, nonce_len);
    
    // Clean up
    memset(derived, 0, total_len);
    free(derived);
    
    return 0;
}