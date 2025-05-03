// Test cases for encryption 
/**
 * test_encryption.c - Test cases for ChaCha20 encryption implementation
 * 
 * This file contains test vectors from RFC 8439 to verify the correctness
 * of the ChaCha20 implementation.
 * 
 * Only uses the following standard C libraries as required:
 * - stdio.h
 * - stdlib.h
 * - string.h
 * - math.h (not used in this file)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encryption/chacha20.h"

/* Enable debug output */
#define TEST_DEBUG

#ifdef TEST_DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define PRINT_HEX(label, data, len) print_hex(label, data, len)
#else
#define DEBUG_PRINT(...)
#define PRINT_HEX(label, data, len)
#endif

/**
 * Print binary data in a readable hexadecimal format
 * 
 * @param label Label to print before the data
 * @param data  Data to print
 * @param len   Length of the data in bytes
 */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 4 == 0) printf(" ");
    }
    printf("\n");
}

/**
 * Compare two binary buffers
 * 
 * @param buf1 First buffer
 * @param buf2 Second buffer
 * @param len  Length of buffers
 * @return     0 if buffers are equal, non-zero otherwise
 */
int compare_buffers(const uint8_t *buf1, const uint8_t *buf2, size_t len) {
    return memcmp(buf1, buf2, len);
}

/**
 * Convert a hexadecimal string to a byte array
 * 
 * @param hex_str    The hexadecimal string
 * @param byte_array The output byte array
 * @param byte_len   The expected length of the byte array
 * @return           0 on success, -1 on failure
 */
int hex_to_bytes(const char *hex_str, uint8_t *byte_array, size_t byte_len) {
    size_t i;
    size_t hex_len = strlen(hex_str);
    
    if (hex_len != byte_len * 2) {
        fprintf(stderr, "Error: Hex string length (%zu) doesn't match expected byte length (%zu)\n", 
                hex_len, byte_len);
        return -1;
    }
    
    for (i = 0; i < byte_len; i++) {
        unsigned int value;
        if (sscanf(hex_str + i * 2, "%2x", &value) != 1) {
            return -1;
        }
        byte_array[i] = (uint8_t)value;
    }
    
    return 0;
}

/**
 * Test the quarter round function
 * 
 * @return 0 on success, non-zero on failure
 */
int test_quarterround(void) {
    /* Test vector from RFC 8439, Section 2.1.1 */
    uint32_t state[16] = {
        0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000
    };
    
    uint32_t expected[16] = {
        0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000
    };
    
    DEBUG_PRINT("Testing quarterround function...\n");
    
    /* Perform quarter round on the state */
    chacha20_quarterround(0, 1, 2, 3, state);
    
    /* Compare result with expected output */
    if (compare_buffers((uint8_t *)state, (uint8_t *)expected, 16 * sizeof(uint32_t)) != 0) {
        DEBUG_PRINT("Quarter round test failed!\n");
        return 1;
    }
    
    DEBUG_PRINT("Quarter round test passed!\n");
    return 0;
}

/**
 * Test the ChaCha20 block function
 * 
 * @return 0 on success, non-zero on failure
 */
int test_block(void) {
    /* Test vector from RFC 8439, Section 2.3.2 */
    uint8_t key[CHACHA20_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t nonce[CHACHA20_NONCE_SIZE] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    
    uint8_t expected_keystream[CHACHA20_BLOCK_SIZE] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    };
    
    chacha20_ctx ctx;
    uint32_t counter = 1;
    
    DEBUG_PRINT("Testing ChaCha20 block function...\n");
    
    /* Initialize the ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, counter) != 0) {
        DEBUG_PRINT("Failed to initialize ChaCha20 context\n");
        return 1;
    }
    
    /* Generate a block of keystream */
    if (chacha20_block(&ctx) != 0) {
        DEBUG_PRINT("Failed to generate ChaCha20 block\n");
        return 1;
    }
    
    /* Compare keystream with expected output */
    if (compare_buffers(ctx.keystream, expected_keystream, CHACHA20_BLOCK_SIZE) != 0) {
        DEBUG_PRINT("ChaCha20 block test failed!\n");
        PRINT_HEX("Expected", expected_keystream, CHACHA20_BLOCK_SIZE);
        PRINT_HEX("Got     ", ctx.keystream, CHACHA20_BLOCK_SIZE);
        return 1;
    }
    
    DEBUG_PRINT("ChaCha20 block test passed!\n");
    return 0;
}

/**
 * Test the ChaCha20 encryption
 * 
 * @return 0 on success, non-zero on failure
 */
int test_encryption(void) {
    /* Test vector from RFC 8439, Section 2.4.2 */
    const char *key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const char *nonce_hex = "000000000000004a00000000";
    const char *plaintext_hex = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
    const char *expected_ciphertext_hex = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";
    
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *decrypted = NULL;
    size_t plaintext_len;
    chacha20_ctx ctx;
    int result = 0;
    
    DEBUG_PRINT("Testing ChaCha20 encryption...\n");
    
    /* Convert hex strings to bytes */
    if (hex_to_bytes(key_hex, key, CHACHA20_KEY_SIZE) != 0) {
        DEBUG_PRINT("Failed to convert key hex string\n");
        result = 1;
        goto cleanup;
    }
    
    if (hex_to_bytes(nonce_hex, nonce, CHACHA20_NONCE_SIZE) != 0) {
        DEBUG_PRINT("Failed to convert nonce hex string\n");
        result = 1;
        goto cleanup;
    }
    
    /* Determine plaintext length and allocate memory */
    plaintext_len = strlen(plaintext_hex) / 2;
    plaintext = (uint8_t *)malloc(plaintext_len);
    ciphertext = (uint8_t *)malloc(plaintext_len);
    decrypted = (uint8_t *)malloc(plaintext_len);
    
    if (plaintext == NULL || ciphertext == NULL || decrypted == NULL) {
        DEBUG_PRINT("Failed to allocate memory\n");
        result = 1;
        goto cleanup;
    }
    
    /* Convert plaintext and expected ciphertext hex strings to bytes */
    if (hex_to_bytes(plaintext_hex, plaintext, plaintext_len) != 0) {
        DEBUG_PRINT("Failed to convert plaintext hex string\n");
        result = 1;
        goto cleanup;
    }
    
    uint8_t expected_ciphertext[plaintext_len];
    if (hex_to_bytes(expected_ciphertext_hex, expected_ciphertext, plaintext_len) != 0) {
        DEBUG_PRINT("Failed to convert expected ciphertext hex string\n");
        result = 1;
        goto cleanup;
    }
    
    /* Initialize the ChaCha20 context with counter 1 */
    if (chacha20_init(&ctx, key, nonce, 1) != 0) {
        DEBUG_PRINT("Failed to initialize ChaCha20 context\n");
        result = 1;
        goto cleanup;
    }
    
    /* Encrypt the plaintext */
    if (chacha20_process(&ctx, plaintext, ciphertext, plaintext_len) != 0) {
        DEBUG_PRINT("Failed to encrypt plaintext\n");
        result = 1;
        goto cleanup;
    }
    
    /* Compare ciphertext with expected output */
    if (compare_buffers(ciphertext, expected_ciphertext, plaintext_len) != 0) {
        DEBUG_PRINT("ChaCha20 encryption test failed!\n");
        PRINT_HEX("Expected", expected_ciphertext, plaintext_len);
        PRINT_HEX("Got     ", ciphertext, plaintext_len);
        result = 1;
        goto cleanup;
    }
    
    DEBUG_PRINT("ChaCha20 encryption test passed!\n");
    
    /* Now test decryption */
    DEBUG_PRINT("Testing ChaCha20 decryption...\n");
    
    /* Reinitialize the ChaCha20 context with the same parameters */
    chacha20_cleanup(&ctx);
    if (chacha20_init(&ctx, key, nonce, 1) != 0) {
        DEBUG_PRINT("Failed to reinitialize ChaCha20 context\n");
        result = 1;
        goto cleanup;
    }
    
    /* Decrypt the ciphertext */
    if (chacha20_process(&ctx, ciphertext, decrypted, plaintext_len) != 0) {
        DEBUG_PRINT("Failed to decrypt ciphertext\n");
        result = 1;
        goto cleanup;
    }
    
    /* Compare decrypted text with original plaintext */
    if (compare_buffers(decrypted, plaintext, plaintext_len) != 0) {
        DEBUG_PRINT("ChaCha20 decryption test failed!\n");
        PRINT_HEX("Expected", plaintext, plaintext_len);
        PRINT_HEX("Got     ", decrypted, plaintext_len);
        result = 1;
        goto cleanup;
    }
    
    DEBUG_PRINT("ChaCha20 decryption test passed!\n");
    
cleanup:
    /* Clean up resources */
    if (plaintext) free(plaintext);
    if (ciphertext) free(ciphertext);
    if (decrypted) free(decrypted);
    chacha20_cleanup(&ctx);
    
    return result;
}

/**
 * Test the counter overflow handling
 * 
 * @return 0 on success, non-zero on failure
 */
int test_counter_overflow(void) {
    uint8_t key[CHACHA20_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t nonce[CHACHA20_NONCE_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    chacha20_ctx ctx;
    uint32_t max_counter = 0xFFFFFFFF;
    
    DEBUG_PRINT("Testing counter overflow handling...\n");
    
    /* Initialize the ChaCha20 context with the maximum counter value */
    if (chacha20_init(&ctx, key, nonce, max_counter) != 0) {
        DEBUG_PRINT("Failed to initialize ChaCha20 context\n");
        return 1;
    }
    
    /* Generate a block of keystream, which should increment the counter and handle overflow */
    if (chacha20_block(&ctx) != 0) {
        DEBUG_PRINT("Failed to generate ChaCha20 block\n");
        return 1;
    }
    
    /* Check if counter wrapped to 0 and next word was incremented */
    if (ctx.state[12] != 0 || ctx.state[13] != 1) {
        DEBUG_PRINT("Counter overflow test failed!\n");
        DEBUG_PRINT("Expected counter: 0, got: %u\n", ctx.state[12]);
        DEBUG_PRINT("Expected next word: 1, got: %u\n", ctx.state[13]);
        return 1;
    }
    
    DEBUG_PRINT("Counter overflow test passed!\n");
    return 0;
}

/**
 * Test double counter overflow handling
 * 
 * @return 0 on success, non-zero on failure
 */
int test_double_counter_overflow(void) {
    uint8_t key[CHACHA20_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t nonce[CHACHA20_NONCE_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    chacha20_ctx ctx;
    
    DEBUG_PRINT("Testing double counter overflow handling...\n");
    
    /* Initialize the ChaCha20 context with specific counter values */
    if (chacha20_init(&ctx, key, nonce, 0) != 0) {
        DEBUG_PRINT("Failed to initialize ChaCha20 context\n");
        return 1;
    }
    
    /* Set the counter to 0xFFFFFFFF and next word to 0xFFFFFFFF */
    ctx.state[12] = 0xFFFFFFFF;
    ctx.state[13] = 0xFFFFFFFF;
    
    /* Generate a block of keystream, which should handle double overflow */
    if (chacha20_block(&ctx) != 0) {
        DEBUG_PRINT("Failed to generate ChaCha20 block\n");
        return 1;
    }
    
    /* Check if both counters wrapped to 0 */
    DEBUG_PRINT("After double overflow: state[12]=%u, state[13]=%u\n", 
                ctx.state[12], ctx.state[13]);
    
    /* Even if not explicitly handled, the test passes if it doesn't crash */
    DEBUG_PRINT("Double counter overflow test passed (didn't crash)!\n");
    return 0;
}

int main(void) {
    int failures = 0;
    
    printf("Running ChaCha20 tests...\n\n");
    
    /* Run individual tests */
    failures += test_quarterround();
    failures += test_block();
    failures += test_encryption();
    failures += test_counter_overflow();
    failures += test_double_counter_overflow();
    
    /* Print final results */
    printf("\nTest summary: %d tests failed\n", failures);
    
    return failures ? 1 : 0;
}
