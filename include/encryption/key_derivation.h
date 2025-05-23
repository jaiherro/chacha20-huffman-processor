/*
 * key_derivation.h - Password-based key derivation
 */

#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

/* Derive key and nonce from password using simplified PBKDF */
int derive_key_and_nonce(const char *password,
                         const unsigned char *salt, unsigned long salt_len,
                         unsigned int iterations,
                         unsigned char *key, unsigned long key_len,
                         unsigned char *nonce, unsigned long nonce_len);

/* Generate random salt */
int generate_salt(unsigned char *salt, unsigned long salt_len);

#endif /* KEY_DERIVATION_H */
