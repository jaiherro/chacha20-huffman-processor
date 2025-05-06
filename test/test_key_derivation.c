#include "encryption/key_derivation.h"
#include "encryption/chacha20.h" // For key/nonce sizes
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Test case 1: Basic key derivation and consistency check
static int test_kdf_basic_consistency(void) {
    const char *password = "correct horse battery staple";
    uint8_t salt[16];
    size_t salt_len = sizeof(salt);
    unsigned int iterations = 100; // Use fewer iterations for faster testing

    uint8_t key1[CHACHA20_KEY_SIZE];
    uint8_t nonce1[CHACHA20_NONCE_SIZE];
    uint8_t key2[CHACHA20_KEY_SIZE];
    uint8_t nonce2[CHACHA20_NONCE_SIZE];

    // Generate a salt
    int result = generate_salt(salt, salt_len);
    ASSERT_EQUAL_INT(0, result, "generate_salt failed");

    // Derive key/nonce first time
    result = derive_key_and_nonce(password, salt, salt_len, iterations,
                                  key1, sizeof(key1), nonce1, sizeof(nonce1));
    ASSERT_EQUAL_INT(0, result, "derive_key_and_nonce (1) failed");

    // Derive key/nonce second time with same inputs
    result = derive_key_and_nonce(password, salt, salt_len, iterations,
                                  key2, sizeof(key2), nonce2, sizeof(nonce2));
    ASSERT_EQUAL_INT(0, result, "derive_key_and_nonce (2) failed");

    // Verify consistency
    ASSERT_EQUAL_MEM(key1, key2, sizeof(key1), "Derived keys are not consistent");
    ASSERT_EQUAL_MEM(nonce1, nonce2, sizeof(nonce1), "Derived nonces are not consistent");

    return 1; // Success
}

// Test case 2: Check that different salts produce different keys/nonces
static int test_kdf_different_salts(void) {
    const char *password = "password123";
    uint8_t salt1[16], salt2[16];
    size_t salt_len = 16;
    unsigned int iterations = 50;

    uint8_t key1[CHACHA20_KEY_SIZE];
    uint8_t nonce1[CHACHA20_NONCE_SIZE];
    uint8_t key2[CHACHA20_KEY_SIZE];
    uint8_t nonce2[CHACHA20_NONCE_SIZE];

    // Generate two different salts
    ASSERT_EQUAL_INT(0, generate_salt(salt1, salt_len), "generate_salt (1) failed");
    // Simple way to ensure salt2 is different (could be improved)
    memcpy(salt2, salt1, salt_len);
    salt2[0] ^= 0xFF;
    ASSERT_TRUE(memcmp(salt1, salt2, salt_len) != 0, "Salts should be different");


    // Derive with salt1
    int result = derive_key_and_nonce(password, salt1, salt_len, iterations,
                                  key1, sizeof(key1), nonce1, sizeof(nonce1));
    ASSERT_EQUAL_INT(0, result, "derive_key_and_nonce (salt1) failed");

    // Derive with salt2
    result = derive_key_and_nonce(password, salt2, salt_len, iterations,
                                  key2, sizeof(key2), nonce2, sizeof(nonce2));
    ASSERT_EQUAL_INT(0, result, "derive_key_and_nonce (salt2) failed");

    // Verify keys/nonces are different
    ASSERT_TRUE(memcmp(key1, key2, sizeof(key1)) != 0, "Keys derived with different salts are the same");
    ASSERT_TRUE(memcmp(nonce1, nonce2, sizeof(nonce1)) != 0, "Nonces derived with different salts are the same");

    return 1; // Success
}

// Test case 3: Check that different passwords produce different keys/nonces
static int test_kdf_different_passwords(void) {
    const char *passwordA = "passwordA";
    const char *passwordB = "passwordB";
    uint8_t salt[16];
    size_t salt_len = 16;
    unsigned int iterations = 50;

    uint8_t keyA[CHACHA20_KEY_SIZE];
    uint8_t nonceA[CHACHA20_NONCE_SIZE];
    uint8_t keyB[CHACHA20_KEY_SIZE];
    uint8_t nonceB[CHACHA20_NONCE_SIZE];

    // Generate salt
    ASSERT_EQUAL_INT(0, generate_salt(salt, salt_len), "generate_salt failed");

    // Derive with passwordA
    int result = derive_key_and_nonce(passwordA, salt, salt_len, iterations,
                                  keyA, sizeof(keyA), nonceA, sizeof(nonceA));
    ASSERT_EQUAL_INT(0, result, "derive_key_and_nonce (pw A) failed");

    // Derive with passwordB
    result = derive_key_and_nonce(passwordB, salt, salt_len, iterations,
                                  keyB, sizeof(keyB), nonceB, sizeof(nonceB));
    ASSERT_EQUAL_INT(0, result, "derive_key_and_nonce (pw B) failed");

    // Verify keys/nonces are different
    ASSERT_TRUE(memcmp(keyA, keyB, sizeof(keyA)) != 0, "Keys derived with different passwords are the same");
    ASSERT_TRUE(memcmp(nonceA, nonceB, sizeof(nonceA)) != 0, "Nonces derived with different passwords are the same");

    return 1; // Success
}

// Test case 4: generate_salt basic functionality
static int test_generate_salt(void) {
    uint8_t salt1[16];
    uint8_t salt2[16];
    size_t salt_len = 16;

    int result = generate_salt(salt1, salt_len);
    ASSERT_EQUAL_INT(0, result, "generate_salt (1) failed");

    result = generate_salt(salt2, salt_len);
    ASSERT_EQUAL_INT(0, result, "generate_salt (2) failed");

    // Check that subsequent calls produce different salts (highly likely with the LCG)
    ASSERT_TRUE(memcmp(salt1, salt2, salt_len) != 0, "Subsequent calls to generate_salt produced identical salts");

    // Test with different length
    uint8_t salt3[32];
    result = generate_salt(salt3, 32);
     ASSERT_EQUAL_INT(0, result, "generate_salt (3) failed");

    return 1; // Success
}


// Function to run all key derivation tests
int run_key_derivation_tests(void) {
    START_TEST_SUITE("Key Derivation");

    RUN_TEST(test_kdf_basic_consistency);
    RUN_TEST(test_kdf_different_salts);
    RUN_TEST(test_kdf_different_passwords);
    RUN_TEST(test_generate_salt);
    // Add more tests as needed

    END_TEST_SUITE();
}
