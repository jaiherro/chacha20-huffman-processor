/**
 * test_key_derivation.c - Key derivation tests
 */

#include "encryption/key_derivation.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>

/* Test basic key derivation */
static int test_key_derivation_basic(void)
{
    printf("  - Basic key derivation... ");

    const char   *password = "testpassword123";
    unsigned char salt[16];
    unsigned char key1[32], key2[32];
    unsigned char nonce1[12], nonce2[12];

    /* Generate salt */
    ASSERT_EQUAL(generate_salt(salt, sizeof(salt)), 0,
                 "Salt generation failed");

    /* Derive key and nonce */
    ASSERT_EQUAL(derive_key_and_nonce(password, salt, sizeof(salt), 1000, key1,
                                      sizeof(key1), nonce1, sizeof(nonce1)),
                 0, "Key derivation failed");

    /* Derive again with same parameters */
    ASSERT_EQUAL(derive_key_and_nonce(password, salt, sizeof(salt), 1000, key2,
                                      sizeof(key2), nonce2, sizeof(nonce2)),
                 0, "Second key derivation failed");

    /* Should produce same results */
    ASSERT_MEM_EQUAL(key1, key2, sizeof(key1), "Keys don't match");
    ASSERT_MEM_EQUAL(nonce1, nonce2, sizeof(nonce1), "Nonces don't match");

    printf("PASS\n");
    return TEST_PASS;
}

/* Test different passwords produce different keys */
static int test_key_derivation_uniqueness(void)
{
    printf("  - Key uniqueness... ");

    unsigned char salt[16];
    unsigned char key1[32], key2[32];
    unsigned char nonce1[12], nonce2[12];

    generate_salt(salt, sizeof(salt));

    /* Different passwords */
    ASSERT_EQUAL(derive_key_and_nonce("password1", salt, sizeof(salt), 1000,
                                      key1, sizeof(key1), nonce1,
                                      sizeof(nonce1)),
                 0, "First derivation failed");

    ASSERT_EQUAL(derive_key_and_nonce("password2", salt, sizeof(salt), 1000,
                                      key2, sizeof(key2), nonce2,
                                      sizeof(nonce2)),
                 0, "Second derivation failed");

    /* Keys should be different */
    ASSERT_TRUE(memcmp(key1, key2, sizeof(key1)) != 0,
                "Different passwords should produce different keys");

    printf("PASS\n");
    return TEST_PASS;
}

/* Test salt generation uniqueness */
static int test_salt_generation(void)
{
    printf("  - Salt generation uniqueness... ");

    unsigned char salt1[16], salt2[16], salt3[16];

    ASSERT_EQUAL(generate_salt(salt1, sizeof(salt1)), 0,
                 "Salt1 generation failed");
    ASSERT_EQUAL(generate_salt(salt2, sizeof(salt2)), 0,
                 "Salt2 generation failed");
    ASSERT_EQUAL(generate_salt(salt3, sizeof(salt3)), 0,
                 "Salt3 generation failed");

    /* Salts should be different (with very high probability) */
    ASSERT_TRUE(memcmp(salt1, salt2, sizeof(salt1)) != 0 ||
                    memcmp(salt2, salt3, sizeof(salt2)) != 0,
                "Salts should be unique");

    printf("PASS\n");
    return TEST_PASS;
}

int run_key_derivation_tests(void)
{
    printf("\n--- Key Derivation Tests ---\n");

    if (test_key_derivation_basic() != TEST_PASS)
        return TEST_FAIL;
    if (test_key_derivation_uniqueness() != TEST_PASS)
        return TEST_FAIL;
    if (test_salt_generation() != TEST_PASS)
        return TEST_FAIL;

    printf("Key derivation tests: ALL PASSED\n");
    return TEST_PASS;
}