/**
 * key_derivation.c - Implementation of simple password-based key derivation
 * 
 * This file implements a simplified password-based key derivation function
 * that is more secure than basic password stretching but still suitable for
 * educational purposes.
 * 
 * Only uses the following standard C libraries as required:
 * - stdio.h (only used in debug mode)
 * - stdlib.h (for rand() and srand())
 * - string.h (for strlen(), memcpy(), memset())
 * - math.h (not used in this file)
 */

#include "encryption/key_derivation.h"
#include <stdlib.h>  /* For rand() and srand() */
#include <string.h>  /* For strlen(), memcpy(), memset() */
#include <time.h>    /* For time() */

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
 * Simple hash mixing function
 * 
 * @param data      Pointer to data to hash
 * @param len       Length of data in bytes
 * @param state     Pointer to hash state (must be pre-initialized)
 * @param state_len Length of state in bytes
 */
static void mix_hash(const uint8_t *data, size_t len,
                    uint8_t *state, size_t state_len) {
    /* Initialize state mixing constants */
    const uint8_t constants[] = {
        0x67, 0xE6, 0x09, 0x6A, 0x85, 0xAE, 0x67, 0xBB,
        0x2B, 0xF8, 0x94, 0xFE, 0x72, 0xF3, 0x6E, 0x3C
    };
    const size_t num_constants = sizeof(constants) / sizeof(constants[0]);
    
    /* For each byte in data */
    for (size_t i = 0; i < len; i++) {
        /* Mix with state using byte-wise operations */
        for (size_t j = 0; j < state_len; j++) {
            uint8_t idx = (i + j) % num_constants;
            /* XOR with data, rotate bits, and add constant */
            state[j] ^= data[i];
            state[j] = (state[j] << 1) | (state[j] >> 7); /* Rotate left by 1 */
            state[j] ^= constants[idx];
            state[j] ^= (state[(j+1) % state_len] >> 4);
            state[j] ^= ((i * 7 + j * 13) & 0xFF); /* Mix in position */
        }
    }
}

int generate_salt(uint8_t *salt, size_t salt_len) {
    if (salt == NULL || salt_len == 0) {
        return -1;
    }
    
    /* Seed the random number generator if this is the first call */
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    
    /* Generate random bytes for salt */
    for (size_t i = 0; i < salt_len; i++) {
        salt[i] = (uint8_t)(rand() & 0xFF);
    }
    
    DEBUG_PRINT("Generated random salt (%zu bytes)\n", salt_len);
    PRINT_HEX("Salt", salt, salt_len);
    
    return 0;
}

int derive_key_and_nonce(const char *password, 
                        const uint8_t *salt, size_t salt_len,
                        unsigned int iterations,
                        uint8_t *key, size_t key_len,
                        uint8_t *nonce, size_t nonce_len) {
    size_t password_len;
    uint8_t *buffer = NULL;
    size_t buffer_len;
    
    if (password == NULL || key == NULL || key_len == 0 ||
        nonce == NULL || nonce_len == 0) {
        return -1;
    }
    
    password_len = strlen(password);
    if (password_len == 0) {
        return -1;
    }
    
    DEBUG_PRINT("Deriving key and nonce from password (%zu chars)\n", password_len);
    DEBUG_PRINT("Using %u iterations\n", iterations);
    
    /* Compute buffer size for mixing */
    buffer_len = key_len + nonce_len;
    
    /* Allocate temporary buffer */
    buffer = (uint8_t *)malloc(buffer_len);
    if (buffer == NULL) {
        return -1;
    }
    
    /* Initialize buffer with password */
    for (size_t i = 0; i < buffer_len; i++) {
        buffer[i] = password[i % password_len];
    }
    
    /* Mix in salt if provided */
    if (salt != NULL && salt_len > 0) {
        DEBUG_PRINT("Mixing in salt\n");
        mix_hash(salt, salt_len, buffer, buffer_len);
    }
    
    /* Perform multiple iterations of mixing */
    for (unsigned int i = 0; i < iterations; i++) {
        /* Mix in the current state to evolve it */
        mix_hash(buffer, buffer_len, buffer, buffer_len);
        
        /* Every 100 iterations, mix in the iteration count for extra variability */
        if (i % 100 == 0) {
            uint8_t iter_bytes[4];
            iter_bytes[0] = (i >> 24) & 0xFF;
            iter_bytes[1] = (i >> 16) & 0xFF;
            iter_bytes[2] = (i >> 8) & 0xFF;
            iter_bytes[3] = i & 0xFF;
            mix_hash(iter_bytes, sizeof(iter_bytes), buffer, buffer_len);
        }
    }
    
    /* Copy the result to output buffers */
    memcpy(key, buffer, key_len);
    memcpy(nonce, buffer + key_len, nonce_len);
    
    PRINT_HEX("Derived key", key, key_len);
    PRINT_HEX("Derived nonce", nonce, nonce_len);
    
    /* Clean up the sensitive data in the buffer */
    memset(buffer, 0, buffer_len);
    free(buffer);
    
    return 0;
}
