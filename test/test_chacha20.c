/**
 * test_chacha20.c - ChaCha20 encryption tests
 */

#include "encryption/chacha20.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>

// RFC 8439 test vector
static int test_chacha20_rfc8439_vector(void)
{
    printf("  - RFC 8439 test vector... ");

    unsigned char key[32]
        = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    unsigned char nonce[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };

    unsigned char plaintext[]
        = "Ladies and Gentlemen of the class of '99: "
          "If I could offer you only one tip for the future, "
          "sunscreen would be it.";

    unsigned char expected_ciphertext[]
        = { 0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07,
            0x28, 0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43,
            0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9,
            0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab,
            0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52,
            0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca,
            0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a,
            0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
            0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b,
            0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78,
            0x5e, 0x42, 0x87, 0x4d };

    chacha20_ctx ctx;
    unsigned char output[sizeof(plaintext) - 1];

    ASSERT_EQUAL(chacha20_init(&ctx, key, nonce, 1), 0, "ChaCha20 init failed");

    ASSERT_EQUAL(
        chacha20_process(&ctx, plaintext, output, sizeof(plaintext) - 1), 0,
        "ChaCha20 process failed");

    ASSERT_MEM_EQUAL(output, expected_ciphertext, sizeof(expected_ciphertext),
                     "Ciphertext doesn't match RFC 8439 test vector");

    chacha20_cleanup(&ctx);
    printf("PASS\n");
    return TEST_PASS;
}

// Test encryption/decryption symmetry
static int test_chacha20_symmetry(void)
{
    printf("  - Encryption/decryption symmetry... ");

    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char nonce[12] = "012345678901";
    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    unsigned char ciphertext[sizeof(plaintext)];
    unsigned char decrypted[sizeof(plaintext)];

    chacha20_ctx ctx;

    // Encrypt
    ASSERT_EQUAL(chacha20_init(&ctx, key, nonce, 0), 0, "Encrypt init failed");
    ASSERT_EQUAL(
        chacha20_process(&ctx, plaintext, ciphertext, sizeof(plaintext)), 0,
        "Encryption failed");
    chacha20_cleanup(&ctx);

    // Decrypt
    ASSERT_EQUAL(chacha20_init(&ctx, key, nonce, 0), 0, "Decrypt init failed");
    ASSERT_EQUAL(
        chacha20_process(&ctx, ciphertext, decrypted, sizeof(plaintext)), 0,
        "Decryption failed");
    chacha20_cleanup(&ctx);

    ASSERT_MEM_EQUAL(decrypted, plaintext, sizeof(plaintext),
                     "Decrypted text doesn't match original");

    printf("PASS\n");
    return TEST_PASS;
}

// Test with empty input
static int test_chacha20_empty_input(void)
{
    printf("  - Empty input handling... ");

    unsigned char key[32] = { 0 };
    unsigned char nonce[12] = { 0 };
    unsigned char output[1];

    chacha20_ctx ctx;

    ASSERT_EQUAL(chacha20_init(&ctx, key, nonce, 0), 0, "Init failed");
    ASSERT_EQUAL(chacha20_process(&ctx, NULL, output, 0), 0,
                 "Empty input processing failed");

    chacha20_cleanup(&ctx);
    printf("PASS\n");
    return TEST_PASS;
}

int run_chacha20_tests(void)
{
    printf("\n--- ChaCha20 Tests ---\n");

    if (test_chacha20_rfc8439_vector() != TEST_PASS)
        return TEST_FAIL;
    if (test_chacha20_symmetry() != TEST_PASS)
        return TEST_FAIL;
    if (test_chacha20_empty_input() != TEST_PASS)
        return TEST_FAIL;

    printf("ChaCha20 tests: ALL PASSED\n");
    return TEST_PASS;
}