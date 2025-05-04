#include "test_utils.h"
#include "encryption/key_derivation.h"
#include "encryption/chacha20.h" // For key/nonce sizes
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy, memset

#define TEST_ITERATIONS 100 // Use fewer iterations for speed in tests

// Test that the same inputs produce the same outputs
static int test_kdf_consistency() {
    const char *password = "testPassword123";
    uint8_t salt[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
    size_t key_len = CHACHA20_KEY_SIZE;
    size_t nonce_len = CHACHA20_NONCE_SIZE;

    uint8_t key1[CHACHA20_KEY_SIZE], nonce1[CHACHA20_NONCE_SIZE];
    uint8_t key2[CHACHA20_KEY_SIZE], nonce2[CHACHA20_NONCE_SIZE];

    int res1 = derive_key_and_nonce(password, salt, sizeof(salt), TEST_ITERATIONS, key1, key_len, nonce1, nonce_len);
    if (!check_equal_int(0, res1, "First KDF call failed")) return 0;

    int res2 = derive_key_and_nonce(password, salt, sizeof(salt), TEST_ITERATIONS, key2, key_len, nonce2, nonce_len);
     if (!check_equal_int(0, res2, "Second KDF call failed")) return 0;


    int key_ok = check_equal_mem(key1, key2, key_len, "Derived keys are not consistent");
    int nonce_ok = check_equal_mem(nonce1, nonce2, nonce_len, "Derived nonces are not consistent");

    // Clear sensitive data
    memset(key1, 0, key_len); memset(nonce1, 0, nonce_len);
    memset(key2, 0, key_len); memset(nonce2, 0, nonce_len);

    return key_ok && nonce_ok;
}

// Test that different passwords produce different outputs
static int test_kdf_diff_password() {
    const char *password_a = "testPassword_A";
    const char *password_b = "testPassword_B"; // Different password
    uint8_t salt[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
    size_t key_len = CHACHA20_KEY_SIZE;
    size_t nonce_len = CHACHA20_NONCE_SIZE;

    uint8_t key_a[CHACHA20_KEY_SIZE], nonce_a[CHACHA20_NONCE_SIZE];
    uint8_t key_b[CHACHA20_KEY_SIZE], nonce_b[CHACHA20_NONCE_SIZE];

    int res_a = derive_key_and_nonce(password_a, salt, sizeof(salt), TEST_ITERATIONS, key_a, key_len, nonce_a, nonce_len);
    int res_b = derive_key_and_nonce(password_b, salt, sizeof(salt), TEST_ITERATIONS, key_b, key_len, nonce_b, nonce_len);

    if (!check_equal_int(0, res_a, "KDF call A failed") || !check_equal_int(0, res_b, "KDF call B failed")) return 0;

    int key_diff = check_different_mem(key_a, key_b, key_len, "Keys derived from different passwords are the same");
    int nonce_diff = check_different_mem(nonce_a, nonce_b, nonce_len, "Nonces derived from different passwords are the same");

    memset(key_a, 0, key_len); memset(nonce_a, 0, nonce_len);
    memset(key_b, 0, key_len); memset(nonce_b, 0, nonce_len);

    return key_diff && nonce_diff;
}

// Test salt generation
static int test_kdf_generate_salt() {
    size_t salt_len = 16;
    uint8_t salt1[16], salt2[16];

    int res1 = generate_salt(salt1, salt_len);
    if (!check_equal_int(0, res1, "generate_salt call 1 failed")) return 0;

    int res2 = generate_salt(salt2, salt_len);
    if (!check_equal_int(0, res2, "generate_salt call 2 failed")) return 0;

    // Salts should be different (extremely high probability)
    int diff_ok = check_different_mem(salt1, salt2, salt_len, "Generated salts are identical");

    return diff_ok;
}


// Test suite runner for Key Derivation tests
void run_key_derivation_tests() {
    TEST_START("Key Derivation");
    RUN_TEST(test_kdf_consistency);
    RUN_TEST(test_kdf_diff_password);
    RUN_TEST(test_kdf_generate_salt);
    // Add more tests: different salts, different iteration counts, NULL inputs (should fail)
    TEST_END("Key Derivation");
}