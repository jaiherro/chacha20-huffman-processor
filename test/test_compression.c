#include "compression/huffman.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Test case 1: Basic compression and decompression
static int test_huffman_basic(void) {
    const char *input_str = "this is a test string with repeated characters";
    uint8_t *input = (uint8_t *)input_str;
    size_t input_len = strlen(input_str);

    size_t output_max_len = huffman_worst_case_size(input_len);
    uint8_t *output = (uint8_t *)malloc(output_max_len);
    ASSERT_NOT_NULL(output, "Failed to allocate output buffer");

    size_t compressed_len;
    int result = huffman_compress(input, input_len, output, output_max_len, &compressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_compress failed");
    ASSERT_TRUE(compressed_len > 0, "Compressed length should be > 0");
    // Basic check: compression should ideally reduce size for this repetitive string
    ASSERT_TRUE(compressed_len < input_len + 10, "Compression didn't reduce size significantly");

    size_t decompressed_max_len = input_len + 1; // Should be exactly input_len
    uint8_t *decompressed = (uint8_t *)malloc(decompressed_max_len);
    ASSERT_NOT_NULL(decompressed, "Failed to allocate decompressed buffer");

    size_t decompressed_len;
    result = huffman_decompress(output, compressed_len, decompressed, decompressed_max_len, &decompressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_decompress failed");
    ASSERT_EQUAL_INT(input_len, decompressed_len, "Decompressed length mismatch");
    ASSERT_EQUAL_MEM(input, decompressed, input_len, "Decompressed data mismatch");

    free(output);
    free(decompressed);
    return 1; // Success
}

// Test case 2: Empty input
static int test_huffman_empty(void) {
    uint8_t input[] = "";
    size_t input_len = 0;

    size_t output_max_len = huffman_worst_case_size(input_len);
    uint8_t *output = (uint8_t *)malloc(output_max_len > 0 ? output_max_len : 1); // Avoid malloc(0)
    ASSERT_NOT_NULL(output, "Failed to allocate output buffer");

    size_t compressed_len;
    int result = huffman_compress(input, input_len, output, output_max_len, &compressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_compress failed for empty input");
    ASSERT_EQUAL_INT(0, compressed_len, "Compressed length should be 0 for empty input");

    size_t decompressed_max_len = 1; // Should be 0
    uint8_t *decompressed = (uint8_t *)malloc(decompressed_max_len);
    ASSERT_NOT_NULL(decompressed, "Failed to allocate decompressed buffer");

    size_t decompressed_len;
    result = huffman_decompress(output, compressed_len, decompressed, decompressed_max_len, &decompressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_decompress failed for empty input");
    ASSERT_EQUAL_INT(0, decompressed_len, "Decompressed length should be 0 for empty input");

    free(output);
    free(decompressed);
    return 1; // Success
}

// Test case 3: Input with a single character repeated
static int test_huffman_single_char(void) {
    const char *input_str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint8_t *input = (uint8_t *)input_str;
    size_t input_len = strlen(input_str);

    size_t output_max_len = huffman_worst_case_size(input_len);
    uint8_t *output = (uint8_t *)malloc(output_max_len);
    ASSERT_NOT_NULL(output, "Failed to allocate output buffer");

    size_t compressed_len;
    int result = huffman_compress(input, input_len, output, output_max_len, &compressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_compress failed for single char");
    ASSERT_TRUE(compressed_len > 0, "Compressed length should be > 0");
    // Compression should be very effective here
    ASSERT_TRUE(compressed_len < input_len / 2, "Compression ineffective for single char");

    size_t decompressed_max_len = input_len + 1;
    uint8_t *decompressed = (uint8_t *)malloc(decompressed_max_len);
    ASSERT_NOT_NULL(decompressed, "Failed to allocate decompressed buffer");

    size_t decompressed_len;
    result = huffman_decompress(output, compressed_len, decompressed, decompressed_max_len, &decompressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_decompress failed for single char");
    ASSERT_EQUAL_INT(input_len, decompressed_len, "Decompressed length mismatch for single char");
    ASSERT_EQUAL_MEM(input, decompressed, input_len, "Decompressed data mismatch for single char");

    free(output);
    free(decompressed);
    return 1; // Success
}

// Test case 4: Input with all unique characters (worst case for Huffman)
static int test_huffman_unique_chars(void) {
    uint8_t input[256];
    size_t input_len = 256;
    for (size_t i = 0; i < input_len; ++i) {
        input[i] = (uint8_t)i;
    }

    size_t output_max_len = huffman_worst_case_size(input_len);
    uint8_t *output = (uint8_t *)malloc(output_max_len);
    ASSERT_NOT_NULL(output, "Failed to allocate output buffer");

    size_t compressed_len;
    int result = huffman_compress(input, input_len, output, output_max_len, &compressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_compress failed for unique chars");
    ASSERT_TRUE(compressed_len > 0, "Compressed length should be > 0");
    // Compression will likely increase size due to tree overhead
    ASSERT_TRUE(compressed_len > input_len, "Compression didn't increase size for unique chars");

    size_t decompressed_max_len = input_len + 1;
    uint8_t *decompressed = (uint8_t *)malloc(decompressed_max_len);
    ASSERT_NOT_NULL(decompressed, "Failed to allocate decompressed buffer");

    size_t decompressed_len;
    result = huffman_decompress(output, compressed_len, decompressed, decompressed_max_len, &decompressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_decompress failed for unique chars");
    ASSERT_EQUAL_INT(input_len, decompressed_len, "Decompressed length mismatch for unique chars");
    ASSERT_EQUAL_MEM(input, decompressed, input_len, "Decompressed data mismatch for unique chars");

    free(output);
    free(decompressed);
    return 1; // Success
}


// Function to run all compression tests
int run_compression_tests(void) {
    START_TEST_SUITE("Huffman Compression");

    RUN_TEST(test_huffman_basic);
    RUN_TEST(test_huffman_empty);
    RUN_TEST(test_huffman_single_char);
    RUN_TEST(test_huffman_unique_chars);
    // Add more tests as needed

    END_TEST_SUITE();
}
