#include "test_utils.h"
#include "encryption/chacha20.h"
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy, memset

// Test vector from RFC 8439, Section 2.4.2
static int test_chacha20_rfc8439_block() {
    chacha20_ctx ctx;
    uint8_t key[CHACHA20_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[CHACHA20_NONCE_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    uint32_t counter = 1;

    uint8_t expected_keystream[CHACHA20_BLOCK_SIZE] = {
        0xe4, 0xe7, 0xf1, 0x10, 0x09, 0x13, 0x56, 0x91,
        0x61, 0x15, 0x8c, 0xc4, 0x08, 0x88, 0x3c, 0x86,
        0x94, 0x97, 0xf7, 0x17, 0x01, 0x2d, 0x8c, 0x5e,
        0xae, 0x34, 0x0b, 0x41, 0xf8, 0xd5, 0x67, 0x42,
        0xd1, 0x80, 0x01, 0x2c, 0x4e, 0x3e, 0xa0, 0xca,
        0x2e, 0x7b, 0x0f, 0x09, 0x1b, 0xc0, 0x15, 0x99,
        0x23, 0x59, 0xf5, 0x63, 0xd5, 0xc6, 0x71, 0x32,
        0x8b, 0x83, 0xc8, 0x36, 0x18, 0x73, 0x9f, 0x5e
    };

    int init_ok = check_equal_int(0, chacha20_init(&ctx, key, nonce, counter), "ChaCha20 init failed");
    if (!init_ok) return 0;

    // The first call to process will generate the block internally if position is maxed
    // Or call chacha20_block directly for testing just the block function
    ctx.position = CHACHA20_BLOCK_SIZE; // Force block generation
    int block_ok = check_equal_int(0, chacha20_block(&ctx), "ChaCha20 block generation failed");
     if (!block_ok) { chacha20_cleanup(&ctx); return 0; }

    int mem_ok = check_equal_mem(expected_keystream, ctx.keystream, CHACHA20_BLOCK_SIZE, "RFC 8439 Keystream mismatch");

    chacha20_cleanup(&ctx); // Important to clear sensitive data
    return mem_ok;
}

// Test encryption/decryption cycle
static int test_chacha20_encrypt_decrypt() {
    chacha20_ctx enc_ctx, dec_ctx;
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint32_t counter = 42; // Arbitrary counter start

    // Generate some random key/nonce for the test (replace with fixed if needed)
    for (int i = 0; i < CHACHA20_KEY_SIZE; ++i) key[i] = rand() % 256;
    for (int i = 0; i < CHACHA20_NONCE_SIZE; ++i) nonce[i] = rand() % 256;

    const char *plaintext_str = "This is a test message that is longer than one block to test state.";
    size_t len = strlen(plaintext_str);
    uint8_t *plaintext = (uint8_t *)plaintext_str;
    uint8_t *ciphertext = (uint8_t *)malloc(len);
    uint8_t *decrypted = (uint8_t *)malloc(len);

    if (!check_not_null(ciphertext, "Malloc ciphertext failed") ||
        !check_not_null(decrypted, "Malloc decrypted failed")) {
        free(ciphertext); free(decrypted); return 0;
    }

    // --- Encryption ---
    int init_ok = check_equal_int(0, chacha20_init(&enc_ctx, key, nonce, counter), "Encrypt Init failed");
    if (!init_ok) { free(ciphertext); free(decrypted); chacha20_cleanup(&enc_ctx); return 0; }

    int enc_ok = check_equal_int(0, chacha20_process(&enc_ctx, plaintext, ciphertext, len), "Encryption process failed");
     if (!enc_ok) { free(ciphertext); free(decrypted); chacha20_cleanup(&enc_ctx); return 0; }

    // Ensure plaintext and ciphertext are different
    int diff_ok = check_different_mem(plaintext, ciphertext, len, "Plaintext and Ciphertext are identical");
    if (!diff_ok) { free(ciphertext); free(decrypted); chacha20_cleanup(&enc_ctx); return 0; }


    // --- Decryption ---
    init_ok = check_equal_int(0, chacha20_init(&dec_ctx, key, nonce, counter), "Decrypt Init failed"); // Use same key/nonce/counter
    if (!init_ok) { free(ciphertext); free(decrypted); chacha20_cleanup(&enc_ctx); chacha20_cleanup(&dec_ctx); return 0; }

    int dec_ok = check_equal_int(0, chacha20_process(&dec_ctx, ciphertext, decrypted, len), "Decryption process failed");
    if (!dec_ok) { free(ciphertext); free(decrypted); chacha20_cleanup(&enc_ctx); chacha20_cleanup(&dec_ctx); return 0; }


    // --- Verification ---
    int mem_ok = check_equal_mem(plaintext, decrypted, len, "Decrypted text does not match original plaintext");

    // Cleanup
    chacha20_cleanup(&enc_ctx);
    chacha20_cleanup(&dec_ctx);
    free(ciphertext);
    free(decrypted);

    return mem_ok;
}


// Test suite runner for ChaCha20 tests
void run_chacha20_tests() {
    TEST_START("ChaCha20 Encryption");
    RUN_TEST(test_chacha20_rfc8439_block);
    RUN_TEST(test_chacha20_encrypt_decrypt);
    // Add more tests: different counters, different lengths, null inputs (should fail)
    TEST_END("ChaCha20 Encryption");
}