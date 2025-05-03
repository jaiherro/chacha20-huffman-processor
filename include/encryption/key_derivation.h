/**
 * key_derivation.h - Header file for simple password-based key derivation
 * 
 * This header file provides function prototypes for deriving cryptographic
 * keys from passwords in a more secure manner than simple stretching.
 * 
 * Note: For production use, a standard algorithm like PBKDF2 would be preferred,
 * but this implementation uses a simplified approach suitable for educational purposes
 * while still being more secure than basic password stretching.
 * 
 * Allowed libraries: stdio.h, stdlib.h, string.h, math.h
 */

#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stddef.h>  /* For size_t */
#include <stdint.h>  /* For uint8_t, uint32_t */

/**
 * Derives a key and nonce from a password using a simplified PBKDF approach
 * 
 * @param password   The password to derive key and nonce from
 * @param salt       Optional salt value (can be NULL)
 * @param salt_len   Length of the salt in bytes
 * @param iterations Number of iterations to perform (higher = more secure, but slower)
 * @param key        Output buffer for the key (must be pre-allocated)
 * @param key_len    Length of the key to generate in bytes
 * @param nonce      Output buffer for the nonce (must be pre-allocated)
 * @param nonce_len  Length of the nonce to generate in bytes
 * @return           0 on success, -1 on failure
 */
int derive_key_and_nonce(const char *password, 
                        const uint8_t *salt, size_t salt_len,
                        unsigned int iterations,
                        uint8_t *key, size_t key_len,
                        uint8_t *nonce, size_t nonce_len);

/**
 * Generate a random salt for key derivation
 * 
 * @param salt      Output buffer for the salt (must be pre-allocated)
 * @param salt_len  Length of the salt to generate in bytes
 * @return          0 on success, -1 on failure
 */
int generate_salt(uint8_t *salt, size_t salt_len);

#endif /* KEY_DERIVATION_H */
