/**
 * Simple password-based key derivation implementation
 */

#include "encryption/key_derivation.h"
#include <stdlib.h>
#include <string.h>

/**
 * Simple key derivation using password and salt
 */
static void derive_key(const char *password, const unsigned char *salt,
                       unsigned long salt_len, unsigned int iterations,
                       unsigned char *output, unsigned long output_len)
{
    unsigned long password_len = strlen(password);
    unsigned char hash[64]; // Smaller working buffer
    unsigned long i, j;

    // Initialise with password
    for (i = 0; i < sizeof(hash); i++)
    {
        hash[i] = (i < password_len) ? password[i] : 0;
    }

    // Mix in salt
    if (salt && salt_len > 0)
    {
        for (i = 0; i < salt_len; i++)
        {
            hash[i % sizeof(hash)] ^= salt[i];
        }
    }

    // Iterative mixing for key strengthening
    for (i = 0; i < iterations; i++)
    {
        for (j = 0; j < sizeof(hash); j++)
        {
            // Simple rotate and mix
            unsigned char next = hash[(j + 1) % sizeof(hash)];
            hash[j] = ((hash[j] << 1) | (hash[j] >> 7)) ^ next ^ (i & 0xFF);
        }
    }

    // Generate output by repeating hash as needed
    for (i = 0; i < output_len; i++)
    {
        output[i] = hash[i % sizeof(hash)];
    }

    // Clear sensitive data
    memset(hash, 0, sizeof(hash));
}

/**
 * Generate pseudo-random salt
 */
int generate_salt(unsigned char *salt, unsigned long salt_len)
{
    if (!salt || salt_len == 0)
        return -1;

    static unsigned int seed = 0x12345678;

    for (unsigned long i = 0; i < salt_len; i++)
    {
        seed = seed * 1103515245 + 12345; // Simple LCG
        salt[i] = (seed >> 16) & 0xFF;
    }

    return 0;
}

/**
 * Derive both key and nonce from password
 */
int derive_key_and_nonce(const char *password,
                         const unsigned char *salt, unsigned long salt_len,
                         unsigned int iterations,
                         unsigned char *key, unsigned long key_len,
                         unsigned char *nonce, unsigned long nonce_len)
{
    if (!password || !key || !nonce || key_len == 0 || nonce_len == 0)
    {
        return -1;
    }

    unsigned long total_len = key_len + nonce_len;
    unsigned char *material = malloc(total_len);

    if (!material)
        return -1;

    // Derive combined material
    derive_key(password, salt, salt_len, iterations, material, total_len);

    // Split into key and nonce
    memcpy(key, material, key_len);
    memcpy(nonce, material + key_len, nonce_len);

    // Clean up
    memset(material, 0, total_len);
    free(material);

    return 0;
}