#include "encryption/chacha20.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
// #include <stdint.h> // Removed
#include <stdio.h> // For sscanf

// Helper function to convert hex string to byte array
// Replaced uint8_t with unsigned char, size_t with unsigned long
static int hex_to_bytes(const char *hex_str, unsigned char *bytes, unsigned long max_len)
{
    unsigned long hex_len = strlen(hex_str); // Replaced size_t with unsigned long
    if (hex_len % 2 != 0)
        return -1;                        // Must be even length
    unsigned long byte_len = hex_len / 2; // Replaced size_t with unsigned long
    if (byte_len > max_len)
        return -1; // Buffer too small

    for (unsigned long i = 0; i < byte_len; i++)
    {                          // Replaced size_t with unsigned long
        unsigned int byte_val; // Temp for sscanf
        if (sscanf(hex_str + 2 * i, "%2x", &byte_val) != 1)
        {
            return -1; // Invalid hex character
        }
        bytes[i] = (unsigned char)byte_val;
    }
    return (int)byte_len; // Return as int, but it's a count
}

// Test case 1: RFC 8439 Test Vector 1 (Section 2.4.2)
// Encrypting 114 bytes of zeros
static int test_chacha20_rfc8439_vector1(void)
{
    // Key (256 bits / 32 bytes)
    unsigned char key[CHACHA20_KEY_SIZE]; // Replaced uint8_t with unsigned char
    const char *key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    ASSERT_EQUAL_INT(CHACHA20_KEY_SIZE, hex_to_bytes(key_hex, key, sizeof(key)), "Failed to parse key hex");

    // Nonce (96 bits / 12 bytes)
    unsigned char nonce[CHACHA20_NONCE_SIZE];           // Replaced uint8_t with unsigned char
    const char *nonce_hex = "000000000000004a00000000"; // Note: RFC uses 64-bit nonce + counter, here adapted for 96-bit nonce
    ASSERT_EQUAL_INT(CHACHA20_NONCE_SIZE, hex_to_bytes(nonce_hex, nonce, sizeof(nonce)), "Failed to parse nonce hex");

    // Initial Counter
    unsigned int counter = 1; // As per RFC 8439, replaced uint32_t with unsigned int

    // Plaintext (114 zeros)
    unsigned long input_len = 114;                                                        // Replaced size_t with unsigned long
    unsigned char *plaintext = (unsigned char *)calloc(input_len, sizeof(unsigned char)); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(plaintext, "Failed to allocate plaintext buffer");

    // Expected Ciphertext (first 64 bytes shown in RFC)
    unsigned char expected_ciphertext_prefix[64]; // Replaced uint8_t with unsigned char
    const char *expected_hex_prefix = "76b8e0ada0f13d90405d6ae55854e6cf3309d0513806c9f5466939a3c5d857a3"
                                      "d4318aae34600c1b1ccdd11ace4f8259d1619cc8578ca4b9";
    ASSERT_EQUAL_INT(64, hex_to_bytes(expected_hex_prefix, expected_ciphertext_prefix, sizeof(expected_ciphertext_prefix)), "Failed to parse expected ciphertext hex");

    // Allocate output buffer
    unsigned char *ciphertext = (unsigned char *)malloc(input_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(ciphertext, "Failed to allocate ciphertext buffer");

    // Initialize ChaCha20 context
    chacha20_ctx ctx;
    int result = chacha20_init(&ctx, key, nonce, counter);
    ASSERT_EQUAL_INT(0, result, "chacha20_init failed");

    // Encrypt
    result = chacha20_process(&ctx, plaintext, ciphertext, input_len);
    ASSERT_EQUAL_INT(0, result, "chacha20_process (encrypt) failed");

    // Verify the first 64 bytes of ciphertext
    ASSERT_EQUAL_MEM(expected_ciphertext_prefix, ciphertext, 64, "Ciphertext prefix mismatch (RFC Vector 1)");

    // Decrypt (should yield original plaintext)
    unsigned char *decrypted = (unsigned char *)malloc(input_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(decrypted, "Failed to allocate decrypted buffer");

    // Re-initialize context for decryption
    result = chacha20_init(&ctx, key, nonce, counter);
    ASSERT_EQUAL_INT(0, result, "chacha20_init (decrypt) failed");

    result = chacha20_process(&ctx, ciphertext, decrypted, input_len);
    ASSERT_EQUAL_INT(0, result, "chacha20_process (decrypt) failed");

    // Verify decrypted data matches original plaintext
    ASSERT_EQUAL_MEM(plaintext, decrypted, input_len, "Decrypted data mismatch (RFC Vector 1)");

    // Cleanup
    chacha20_cleanup(&ctx);
    free(plaintext);
    free(ciphertext);
    free(decrypted);
    return 1; // Success
}

// Test case 2: Basic encryption/decryption with non-zero data
static int test_chacha20_basic(void)
{
    unsigned char key[CHACHA20_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, // Replaced uint8_t with unsigned char
                                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
                                            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
    unsigned char nonce[CHACHA20_NONCE_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Replaced uint8_t with unsigned char
                                                0x08, 0x09, 0x0a, 0x0b};
    unsigned int counter = 42; // Replaced uint32_t with unsigned int

    const char *input_str = "This is a secret message.";
    unsigned char *plaintext = (unsigned char *)input_str; // Replaced uint8_t with unsigned char
    unsigned long input_len = strlen(input_str);           // Replaced size_t with unsigned long

    unsigned char *ciphertext = (unsigned char *)malloc(input_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(ciphertext, "Failed to allocate ciphertext buffer");
    unsigned char *decrypted = (unsigned char *)malloc(input_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(decrypted, "Failed to allocate decrypted buffer");

    chacha20_ctx ctx;

    // Encrypt
    int result = chacha20_init(&ctx, key, nonce, counter);
    ASSERT_EQUAL_INT(0, result, "chacha20_init failed (encrypt)");
    result = chacha20_process(&ctx, plaintext, ciphertext, input_len);
    ASSERT_EQUAL_INT(0, result, "chacha20_process failed (encrypt)");
    chacha20_cleanup(&ctx); // Clean up context

    // Ensure ciphertext is different from plaintext
    if (input_len > 0)
    { // Avoid memcmp on zero length
        ASSERT_TRUE(memcmp(plaintext, ciphertext, input_len) != 0, "Ciphertext is same as plaintext");
    }

    // Decrypt
    result = chacha20_init(&ctx, key, nonce, counter);
    ASSERT_EQUAL_INT(0, result, "chacha20_init failed (decrypt)");
    result = chacha20_process(&ctx, ciphertext, decrypted, input_len);
    ASSERT_EQUAL_INT(0, result, "chacha20_process failed (decrypt)");
    chacha20_cleanup(&ctx); // Clean up context

    // Verify decrypted data matches original plaintext
    ASSERT_EQUAL_MEM(plaintext, decrypted, input_len, "Decrypted data mismatch");

    free(ciphertext);
    free(decrypted);
    return 1; // Success
}

// Test case 3: Processing data larger than one block
static int test_chacha20_multi_block(void)
{
    unsigned char key[CHACHA20_KEY_SIZE] = {0};     // Simple key // Replaced uint8_t with unsigned char
    unsigned char nonce[CHACHA20_NONCE_SIZE] = {0}; // Simple nonce // Replaced uint8_t with unsigned char
    unsigned int counter = 1;                       // Replaced uint32_t with unsigned int

    unsigned long input_len = CHACHA20_BLOCK_SIZE * 3 + 10;        // More than 3 blocks // Replaced size_t with unsigned long
    unsigned char *plaintext = (unsigned char *)malloc(input_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(plaintext, "Failed to allocate plaintext buffer");
    // Fill with some pattern
    for (unsigned long i = 0; i < input_len; ++i)
    {                                            // Replaced size_t with unsigned long
        plaintext[i] = (unsigned char)(i % 256); // Replaced uint8_t with unsigned char
    }

    unsigned char *ciphertext = (unsigned char *)malloc(input_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(ciphertext, "Failed to allocate ciphertext buffer");
    unsigned char *decrypted = (unsigned char *)malloc(input_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(decrypted, "Failed to allocate decrypted buffer");

    chacha20_ctx ctx;

    // Encrypt
    int result = chacha20_init(&ctx, key, nonce, counter);
    ASSERT_EQUAL_INT(0, result, "chacha20_init failed (encrypt multi-block)");
    result = chacha20_process(&ctx, plaintext, ciphertext, input_len);
    ASSERT_EQUAL_INT(0, result, "chacha20_process failed (encrypt multi-block)");
    chacha20_cleanup(&ctx);

    // Decrypt
    result = chacha20_init(&ctx, key, nonce, counter);
    ASSERT_EQUAL_INT(0, result, "chacha20_init failed (decrypt multi-block)");
    result = chacha20_process(&ctx, ciphertext, decrypted, input_len);
    ASSERT_EQUAL_INT(0, result, "chacha20_process failed (decrypt multi-block)");
    chacha20_cleanup(&ctx);

    // Verify
    ASSERT_EQUAL_MEM(plaintext, decrypted, input_len, "Decrypted data mismatch (multi-block)");

    free(plaintext);
    free(ciphertext);
    free(decrypted);
    return 1; // Success
}

// Function to run all encryption tests
int run_encryption_tests(void)
{
    START_TEST_SUITE("ChaCha20 Encryption");

    RUN_TEST(test_chacha20_rfc8439_vector1);
    RUN_TEST(test_chacha20_basic);
    RUN_TEST(test_chacha20_multi_block);
    // Add more tests, potentially including other RFC vectors if needed

    END_TEST_SUITE();
}
