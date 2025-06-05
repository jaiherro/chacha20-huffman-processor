/**
 * test_key_derivation.c - Key derivation function tests
 */

#include "test_utils.h"
#include "encryption/key_derivation.h"
#include <string.h>
#include <stdio.h>

static int test_key_derivation_basic(void)
{
    printf("  Testing basic key derivation...\n");

    const char *password = "test_password_123";
    unsigned char salt[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    unsigned char key[32];
    unsigned char nonce[12];

    int result = derive_key_and_nonce(password, salt, 16, 1000, key, 32, nonce,
                                      12);
    ASSERT_EQUAL(result, 0, "Key derivation should succeed");

    // Key and nonce should not be all zeros
    unsigned char zero_key[32] = { 0 };
    unsigned char zero_nonce[12] = { 0 };

    ASSERT_MEM_NOT_EQUAL(key, zero_key, 32, "Key should not be all zeros");
    ASSERT_MEM_NOT_EQUAL(nonce, zero_nonce, 12, "Nonce should not be all zeros");

    return TEST_PASS;
}

static int test_key_derivation_consistency(void)
{
    printf("  Testing key derivation consistency...\n");

    const char *password = "consistent_password";
    unsigned char salt[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 };
    unsigned char key1[32], key2[32];
    unsigned char nonce1[12], nonce2[12];

    // Derive keys twice with same parameters
    int result1 = derive_key_and_nonce(password, salt, 16, 1000, key1, 32,
                                       nonce1, 12);
    int result2 = derive_key_and_nonce(password, salt, 16, 1000, key2, 32,
                                       nonce2, 12);

    ASSERT_EQUAL(result1, 0, "First key derivation should succeed");
    ASSERT_EQUAL(result2, 0, "Second key derivation should succeed");

    // Results should be identical
    ASSERT_MEM_EQUAL(key1, key2, 32, "Keys should be consistent");
    ASSERT_MEM_EQUAL(nonce1, nonce2, 12, "Nonces should be consistent");

    return TEST_PASS;
}

static int test_key_derivation_different_passwords(void)
{
    printf("  Testing key derivation with different passwords...\n");

    const char *password1 = "password_one";
    const char *password2 = "password_two";
    unsigned char salt[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    unsigned char key1[32], key2[32];
    unsigned char nonce1[12], nonce2[12];

    int result1 = derive_key_and_nonce(password1, salt, 16, 1000, key1, 32,
                                       nonce1, 12);
    int result2 = derive_key_and_nonce(password2, salt, 16, 1000, key2, 32,
                                       nonce2, 12);

    ASSERT_EQUAL(result1, 0, "First key derivation should succeed");
    ASSERT_EQUAL(result2, 0, "Second key derivation should succeed");

    // Results should be different
    ASSERT_MEM_NOT_EQUAL(key1, key2, 32, "Keys should be different");
    ASSERT_MEM_NOT_EQUAL(nonce1, nonce2, 12, "Nonces should be different");

    return TEST_PASS;
}

static int test_key_derivation_different_salts(void)
{
    printf("  Testing key derivation with different salts...\n");

    const char *password = "same_password";
    unsigned char salt1[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    unsigned char salt2[16] = { 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
                                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
    unsigned char key1[32], key2[32];
    unsigned char nonce1[12], nonce2[12];

    int result1 = derive_key_and_nonce(password, salt1, 16, 1000, key1, 32,
                                       nonce1, 12);
    int result2 = derive_key_and_nonce(password, salt2, 16, 1000, key2, 32,
                                       nonce2, 12);

    ASSERT_EQUAL(result1, 0, "First key derivation should succeed");
    ASSERT_EQUAL(result2, 0, "Second key derivation should succeed");

    // Results should be different due to different salts
    ASSERT_MEM_NOT_EQUAL(key1, key2, 32, "Keys should be different with different salts");
    ASSERT_MEM_NOT_EQUAL(nonce1, nonce2, 12, "Nonces should be different with different salts");

    return TEST_PASS;
}

static int test_key_derivation_null_inputs(void)
{
    printf("  Testing key derivation with null inputs...\n");

    const char *password = "test_password";
    unsigned char salt[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    unsigned char key[32];
    unsigned char nonce[12];

    // Test null password
    int result = derive_key_and_nonce(NULL, salt, 16, 1000, key, 32, nonce, 12);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null password");

    // Test null salt
    result = derive_key_and_nonce(password, NULL, 16, 1000, key, 32, nonce, 12);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null salt");

    // Test null key
    result = derive_key_and_nonce(password, salt, 16, 1000, NULL, 32, nonce, 12);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null key");

    // Test null nonce
    result = derive_key_and_nonce(password, salt, 16, 1000, key, 32, NULL, 12);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null nonce");

    return TEST_PASS;
}

static int test_salt_generation(void)
{
    printf("  Testing salt generation...\n");

    unsigned char salt1[16];
    unsigned char salt2[16];
    unsigned char zero_salt[16] = { 0 };

    // Generate two salts
    int result1 = generate_salt(salt1, 16);
    int result2 = generate_salt(salt2, 16);

    ASSERT_EQUAL(result1, 0, "First salt generation should succeed");
    ASSERT_EQUAL(result2, 0, "Second salt generation should succeed");

    // Salts should not be all zeros
    ASSERT_MEM_NOT_EQUAL(salt1, zero_salt, 16, "Salt1 should not be all zeros");
    ASSERT_MEM_NOT_EQUAL(salt2, zero_salt, 16, "Salt2 should not be all zeros");

    // Salts should be different (very high probability)
    ASSERT_MEM_NOT_EQUAL(salt1, salt2, 16, "Generated salts should be different");

    return TEST_PASS;
}

static int test_salt_generation_null_input(void)
{
    printf("  Testing salt generation with null input...\n");

    int result = generate_salt(NULL, 16);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null salt buffer");

    return TEST_PASS;
}

static int test_key_derivation_edge_cases(void)
{
    printf("  Testing key derivation edge cases...\n");

    const char *password = "test";
    unsigned char salt[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    unsigned char key[32];
    unsigned char nonce[12];

    // Test with zero iterations
    int result = derive_key_and_nonce(password, salt, 16, 0, key, 32, nonce, 12);
    ASSERT_NOT_EQUAL(result, 0, "Should reject zero iterations");

    // Test with minimal valid iterations
    result = derive_key_and_nonce(password, salt, 16, 1, key, 32, nonce, 12);
    ASSERT_EQUAL(result, 0, "Should accept minimal iterations");

    // Test with zero salt length
    result = derive_key_and_nonce(password, salt, 0, 1000, key, 32, nonce, 12);
    ASSERT_NOT_EQUAL(result, 0, "Should reject zero salt length");

    // Test with zero key length
    result = derive_key_and_nonce(password, salt, 16, 1000, key, 0, nonce, 12);
    ASSERT_NOT_EQUAL(result, 0, "Should reject zero key length");

    // Test with zero nonce length
    result = derive_key_and_nonce(password, salt, 16, 1000, key, 32, nonce, 0);
    ASSERT_NOT_EQUAL(result, 0, "Should reject zero nonce length");

    return TEST_PASS;
}

int run_key_derivation_tests(void)
{
    printf("Running key derivation tests...\n");

    if (test_key_derivation_basic() != TEST_PASS)
        return TEST_FAIL;
    if (test_key_derivation_consistency() != TEST_PASS)
        return TEST_FAIL;
    if (test_key_derivation_different_passwords() != TEST_PASS)
        return TEST_FAIL;
    if (test_key_derivation_different_salts() != TEST_PASS)
        return TEST_FAIL;
    if (test_key_derivation_null_inputs() != TEST_PASS)
        return TEST_FAIL;
    if (test_salt_generation() != TEST_PASS)
        return TEST_FAIL;
    if (test_salt_generation_null_input() != TEST_PASS)
        return TEST_FAIL;
    if (test_key_derivation_edge_cases() != TEST_PASS)
        return TEST_FAIL;

    printf("All key derivation tests passed!\n\n");
    return TEST_PASS;
}