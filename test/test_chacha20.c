/**
 * test_chacha20.c - ChaCha20 encryption tests including RFC 8439 test vectors
 */

#include "test_utils.h"
#include "encryption/chacha20.h"
#include <string.h>
#include <stdio.h>

// RFC 8439 test vector
static int test_chacha20_rfc8439_vector(void)
{
    printf("  Testing ChaCha20 RFC 8439 test vector...\n");

    // RFC 8439 test vector
    unsigned char key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    unsigned char nonce[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };

    unsigned char plaintext[114] = {
        "Ladies and Gentlemen of the class of '99: If I could offer you only "
        "one tip for the future, sunscreen would be it."
    };

    unsigned char expected_ciphertext[114] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28,
        0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5,
        0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
        0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
        0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed,
        0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d
    };

    chacha20_ctx ctx;
    unsigned char ciphertext[114];

    // Initialize ChaCha20 with RFC test vector
    int result = chacha20_init(&ctx, key, nonce, 1);
    ASSERT_EQUAL(result, 0, "ChaCha20 initialization should succeed");

    // Encrypt plaintext
    result = chacha20_process(&ctx, plaintext, ciphertext, 114);
    ASSERT_EQUAL(result, 0, "ChaCha20 encryption should succeed");

    // Compare with expected ciphertext
    ASSERT_MEM_EQUAL(ciphertext, expected_ciphertext, 114,
                     "Ciphertext should match RFC 8439 test vector");

    // Test decryption (ChaCha20 is symmetric)
    chacha20_ctx ctx2;
    unsigned char decrypted[114];

    result = chacha20_init(&ctx2, key, nonce, 1);
    ASSERT_EQUAL(result, 0, "ChaCha20 re-initialization should succeed");

    result = chacha20_process(&ctx2, ciphertext, decrypted, 114);
    ASSERT_EQUAL(result, 0, "ChaCha20 decryption should succeed");

    ASSERT_MEM_EQUAL(decrypted, plaintext, 114,
                     "Decrypted text should match original plaintext");

    chacha20_cleanup(&ctx);
    chacha20_cleanup(&ctx2);

    return TEST_PASS;
}

static int test_chacha20_basic_functionality(void)
{
    printf("  Testing ChaCha20 basic functionality...\n");

    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char plaintext[64] = "This is a test message for ChaCha20 encryption and decryption!";
    unsigned char ciphertext[64];
    unsigned char decrypted[64];

    // Initialize key and nonce
    memset(key, 0x42, 32);
    memset(nonce, 0x24, 12);

    chacha20_ctx ctx;

    // Test initialization
    int result = chacha20_init(&ctx, key, nonce, 0);
    ASSERT_EQUAL(result, 0, "ChaCha20 initialization should succeed");

    // Test encryption
    result = chacha20_process(&ctx, plaintext, ciphertext, 64);
    ASSERT_EQUAL(result, 0, "ChaCha20 encryption should succeed");

    // Ciphertext should be different from plaintext
    ASSERT_MEM_NOT_EQUAL(ciphertext, plaintext, 64,
                         "Ciphertext should differ from plaintext");

    // Test decryption (reinitialize context)
    result = chacha20_init(&ctx, key, nonce, 0);
    ASSERT_EQUAL(result, 0, "ChaCha20 re-initialization should succeed");

    result = chacha20_process(&ctx, ciphertext, decrypted, 64);
    ASSERT_EQUAL(result, 0, "ChaCha20 decryption should succeed");

    // Decrypted should match original plaintext
    ASSERT_MEM_EQUAL(decrypted, plaintext, 64,
                     "Decrypted text should match original");

    chacha20_cleanup(&ctx);

    return TEST_PASS;
}

static int test_chacha20_empty_input(void)
{
    printf("  Testing ChaCha20 with empty input...\n");

    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char empty_buffer[1];

    memset(key, 0x11, 32);
    memset(nonce, 0x22, 12);

    chacha20_ctx ctx;
    int result = chacha20_init(&ctx, key, nonce, 0);
    ASSERT_EQUAL(result, 0, "ChaCha20 initialization should succeed");

    // Test with zero-length input
    result = chacha20_process(&ctx, empty_buffer, empty_buffer, 0);
    ASSERT_EQUAL(result, 0, "ChaCha20 should handle zero-length input");

    chacha20_cleanup(&ctx);

    return TEST_PASS;
}

static int test_chacha20_large_input(void)
{
    printf("  Testing ChaCha20 with large input...\n");

    unsigned char key[32];
    unsigned char nonce[12];
    size_t size = 1024;
    unsigned char *plaintext = malloc(size);
    unsigned char *ciphertext = malloc(size);
    unsigned char *decrypted = malloc(size);

    if (!plaintext || !ciphertext || !decrypted)
        {
            free(plaintext);
            free(ciphertext);
            free(decrypted);
            printf("    FAIL: Memory allocation failed\n");
            return TEST_FAIL;
        }

    // Fill with test pattern
    for (size_t i = 0; i < size; i++)
        {
            plaintext[i] = (unsigned char)(i & 0xFF);
        }

    memset(key, 0x33, 32);
    memset(nonce, 0x44, 12);

    chacha20_ctx ctx;
    int result = chacha20_init(&ctx, key, nonce, 0);
    ASSERT_EQUAL(result, 0, "ChaCha20 initialization should succeed");

    result = chacha20_process(&ctx, plaintext, ciphertext, size);
    ASSERT_EQUAL(result, 0, "ChaCha20 large encryption should succeed");

    // Reinitialize for decryption
    result = chacha20_init(&ctx, key, nonce, 0);
    ASSERT_EQUAL(result, 0, "ChaCha20 re-initialization should succeed");

    result = chacha20_process(&ctx, ciphertext, decrypted, size);
    ASSERT_EQUAL(result, 0, "ChaCha20 large decryption should succeed");

    ASSERT_MEM_EQUAL(decrypted, plaintext, size,
                     "Large decrypted text should match original");

    chacha20_cleanup(&ctx);
    free(plaintext);
    free(ciphertext);
    free(decrypted);

    return TEST_PASS;
}

static int test_chacha20_null_inputs(void)
{
    printf("  Testing ChaCha20 with null inputs...\n");

    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char buffer[64];

    memset(key, 0x55, 32);
    memset(nonce, 0x66, 12);

    chacha20_ctx ctx;

    // Test null key
    int result = chacha20_init(&ctx, NULL, nonce, 0);
    ASSERT_NOT_EQUAL(result, 0, "ChaCha20 should reject null key");

    // Test null nonce
    result = chacha20_init(&ctx, key, NULL, 0);
    ASSERT_NOT_EQUAL(result, 0, "ChaCha20 should reject null nonce");

    // Test valid initialization
    result = chacha20_init(&ctx, key, nonce, 0);
    ASSERT_EQUAL(result, 0, "ChaCha20 initialization should succeed");

    // Test null input buffer
    result = chacha20_process(&ctx, NULL, buffer, 64);
    ASSERT_NOT_EQUAL(result, 0, "ChaCha20 should reject null input");

    // Test null output buffer
    result = chacha20_process(&ctx, buffer, NULL, 64);
    ASSERT_NOT_EQUAL(result, 0, "ChaCha20 should reject null output");

    chacha20_cleanup(&ctx);

    return TEST_PASS;
}

int run_chacha20_tests(void)
{
    printf("Running ChaCha20 tests...\n");

    if (test_chacha20_rfc8439_vector() != TEST_PASS)
        return TEST_FAIL;
    if (test_chacha20_basic_functionality() != TEST_PASS)
        return TEST_FAIL;
    if (test_chacha20_empty_input() != TEST_PASS)
        return TEST_FAIL;
    if (test_chacha20_large_input() != TEST_PASS)
        return TEST_FAIL;
    if (test_chacha20_null_inputs() != TEST_PASS)
        return TEST_FAIL;

    printf("All ChaCha20 tests passed!\n\n");
    return TEST_PASS;
}