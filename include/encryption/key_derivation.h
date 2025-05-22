/**
 * key_derivation.h - Header file for simple password-based key derivation
 * * This header file provides function prototypes for deriving cryptographic
 * keys from passwords in a more secure manner than simple stretching.
 * * Note: For production use, a standard algorithm like PBKDF2 would be preferred,
 * but this implementation uses a simplified approach suitable for educational purposes
 * while still being more secure than basic password stretching.
 * * Allowed libraries: stdio.h, stdlib.h, string.h, math.h
 */

#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

/**
 * Derives a key and nonce from a password using a simplified PBKDF approach
 * * @param password   The password to derive key and nonce from
 * @param salt       Optional salt value (can be NULL) - Replaced uint8_t with unsigned char
 * @param salt_len   Length of the salt in bytes - Replaced size_t with unsigned long
 * @param iterations Number of iterations to perform (higher = more secure, but slower)
 * @param key        Output buffer for the key (must be pre-allocated) - Replaced uint8_t with unsigned char
 * @param key_len    Length of the key to generate in bytes - Replaced size_t with unsigned long
 * @param nonce      Output buffer for the nonce (must be pre-allocated) - Replaced uint8_t with unsigned char
 * @param nonce_len  Length of the nonce to generate in bytes - Replaced size_t with unsigned long
 * @return           0 on success, -1 on failure
 */
int derive_key_and_nonce(const char *password,
                         const unsigned char *salt, unsigned long salt_len,
                         unsigned int iterations,
                         unsigned char *key, unsigned long key_len,
                         unsigned char *nonce, unsigned long nonce_len);

/**
 * Generate a random salt for key derivation
 * * @param salt      Output buffer for the salt (must be pre-allocated) - Replaced uint8_t with unsigned char
 * @param salt_len  Length of the salt to generate in bytes - Replaced size_t with unsigned long
 * @return          0 on success, -1 on failure
 */
int generate_salt(unsigned char *salt, unsigned long salt_len);

#endif /* KEY_DERIVATION_H */
