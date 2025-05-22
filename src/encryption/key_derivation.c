/**
 * key_derivation.c - Implementation of simple password-based key derivation
 * * This file implements a simplified password-based key derivation function
 * using only allowed libraries: stdio.h, stdlib.h, string.h, and math.h
 */

#include "encryption/key_derivation.h"
#include <stdlib.h> /* For rand() - though not used, srand() and time() would be for better randomness */
                    /* For this LCG, only stdlib.h is needed for malloc/free if used, but not for the LCG itself. */
#include <string.h> /* For strlen(), memcpy(), memset() */

/* Debug printing support */
#ifdef KDF_DEBUG
#include <stdio.h> /* For printf in debug mode */
#define DEBUG_PRINT(...) printf("[KDF] " __VA_ARGS__)
#define PRINT_HEX(label, data, len) print_hex(label, data, len)

// Replaced uint8_t with unsigned char, size_t with unsigned long
static void print_hex(const char *label, const unsigned char *data, unsigned long len)
{
    printf("[KDF] %s: ", label);
    for (unsigned long i = 0; i < len; i++)
    { // Replaced size_t with unsigned long
        printf("%02x", data[i]);
        if ((i + 1) % 4 == 0 && (i + 1) < len)
            printf(" ");
    }
    printf("\n");
}
#else
#define DEBUG_PRINT(...)
#define PRINT_HEX(label, data, len)
#endif

/**
 * Simple key derivation function - uses password and salt to derive a key
 * * @param password   Input password
 * @param salt       Salt value - Replaced uint8_t with unsigned char
 * @param salt_len   Length of salt - Replaced size_t with unsigned long
 * @param iterations Number of iterations for strengthening
 * @param output     Output buffer for derived key - Replaced uint8_t with unsigned char
 * @param output_len Length of output buffer - Replaced size_t with unsigned long
 */
// Replaced uint8_t with unsigned char, size_t with unsigned long
static void derive_key(const char *password, const unsigned char *salt, unsigned long salt_len,
                       unsigned int iterations, unsigned char *output, unsigned long output_len)
{
    unsigned long password_len = strlen(password); // Replaced size_t with unsigned long
    unsigned long i, j, k;                         // Replaced size_t with unsigned long
    unsigned char hash[256];                       // Temporary buffer for hash calculation - uint8_t equivalent

    // Initialize hash with password
    for (i = 0; i < sizeof(hash); i++)
    {
        hash[i] = (i < password_len) ? (unsigned char)password[i] : 0;
    }

    // Mix in salt if provided
    if (salt != NULL && salt_len > 0)
    {
        for (i = 0; i < salt_len; i++)
        {
            hash[i % sizeof(hash)] ^= salt[i];
        }
    }

    // Multiple rounds of mixing for strengthening
    for (i = 0; i < iterations; i++)
    {
        // Simple mixing function - rotate and XOR
        unsigned char prev = hash[0]; // uint8_t equivalent
        unsigned char tmp;            // uint8_t equivalent

        for (j = 0; j < sizeof(hash); j++)
        {
            tmp = hash[(j + 1) % sizeof(hash)];
            // Simulating byte rotation and XORing
            // (hash[j] << 4) | (hash[j] >> 4) is a nibble swap, not a full byte rotation.
            // A simple XOR with previous byte and a fixed value can be used.
            // For a more standard approach, a cryptographic hash function (like SHA-256) would be used here,
            // but that's not allowed. This is a custom, simple mixing.
            hash[(j + 1) % sizeof(hash)] = (unsigned char)((hash[j] << 3) | (hash[j] >> 5)); // Rotate left by 3
            hash[j] ^= prev ^ (unsigned char)(i & 0xFF);                                     // Mix with prev and iteration low byte
            prev = tmp;

            // Additional mixing every 16 bytes
            if ((j % 16) == 15)
            {
                for (k = j - 15; k <= j; k++)
                {
                    hash[k] ^= hash[(k + 7) % sizeof(hash)]; // XOR with another element
                }
            }
        }

        // Mix in the iteration count more thoroughly
        hash[i % sizeof(hash)] ^= (unsigned char)(i & 0xFF);
        hash[(i + 13) % sizeof(hash)] ^= (unsigned char)((i >> 8) & 0xFF); // Use different offsets
        hash[(i + 29) % sizeof(hash)] ^= (unsigned char)((i >> 16) & 0xFF);
        hash[(i + 47) % sizeof(hash)] ^= (unsigned char)((i >> 24) & 0xFF); // Assuming unsigned int is 32-bit
    }

    // Copy the result to the output
    // If output_len is larger than hash, repeat the hash.
    for (i = 0; i < output_len; i++)
    {
        output[i] = hash[i % sizeof(hash)];
    }

    // Clear sensitive data
    memset(hash, 0, sizeof(hash));
}

// Replaced uint8_t with unsigned char, size_t with unsigned long
int generate_salt(unsigned char *salt, unsigned long salt_len)
{
    if (salt == NULL || salt_len == 0)
    {
        return -1;
    }

    // Simple LCG for pseudo-randomness. For security, a CSPRNG is needed.
    // This is for illustrative purposes as `rand()` from `stdlib.h` is allowed.
    // To make it slightly better, we could seed it, e.g., with time if allowed, or a fixed value.
    // Since time.h is not allowed, we'll use a static seed that updates.
    static unsigned int lcg_seed = 0xA1A49B7E; // Arbitrary starting seed, could be improved
                                               // For reproducible tests, a fixed seed is fine.
                                               // For actual use, this needs a better source of randomness.

    for (unsigned long i = 0; i < salt_len; i++)
    { // Replaced size_t with unsigned long
        // LCG parameters (e.g., from Numerical Recipes or glibc)
        // Using common parameters: a = 1103515245, c = 12345
        lcg_seed = lcg_seed * 1103515245 + 12345;
        salt[i] = (unsigned char)((lcg_seed >> 16) & 0xFF); // Use some bits from the LCG
    }

    DEBUG_PRINT("Generated salt (%lu bytes)\n", salt_len); // Use %lu
    PRINT_HEX("Salt", salt, salt_len);

    return 0;
}

// Replaced uint8_t with unsigned char, size_t with unsigned long
int derive_key_and_nonce(const char *password,
                         const unsigned char *salt, unsigned long salt_len,
                         unsigned int iterations,
                         unsigned char *key, unsigned long key_len,
                         unsigned char *nonce, unsigned long nonce_len)
{
    if (password == NULL || key == NULL || key_len == 0 ||
        nonce == NULL || nonce_len == 0)
    {
        return -1;
    }

    unsigned long total_len = key_len + nonce_len;                        // Replaced size_t with unsigned long
    unsigned char *derived_material = (unsigned char *)malloc(total_len); // Replaced uint8_t with unsigned char

    if (derived_material == NULL)
    {
        DEBUG_PRINT("Error: malloc failed for derived_material.\n");
        return -1;
    }

    DEBUG_PRINT("Deriving key and nonce from password (%lu chars)\n", (unsigned long)strlen(password)); // Use %lu
    DEBUG_PRINT("Using %u iterations\n", iterations);
    if (salt && salt_len > 0)
    {
        PRINT_HEX("Using salt", salt, salt_len);
    }
    else
    {
        DEBUG_PRINT("No salt provided.\n");
    }

    // Derive the combined key and nonce material
    derive_key(password, salt, salt_len, iterations, derived_material, total_len);

    // Copy to output buffers
    memcpy(key, derived_material, key_len);
    memcpy(nonce, derived_material + key_len, nonce_len);

    PRINT_HEX("Derived key", key, key_len);
    PRINT_HEX("Derived nonce", nonce, nonce_len);

    // Clean up
    memset(derived_material, 0, total_len); // Clear sensitive data
    free(derived_material);

    return 0;
}
