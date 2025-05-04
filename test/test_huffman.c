#include "test_utils.h"
#include "compression/huffman.h"
#include <stdlib.h> // For malloc, free
#include <string.h> // For memcpy, memset

// Test compressing and decompressing a simple string
static int test_huffman_basic() {
    const char *original_str = "AAAAABBBCCCDDE";
    uint8_t input[15];
    memcpy(input, original_str, 14);
    input[14] = '\0'; // Ensure null termination if needed, though not strictly necessary for binary data
    size_t input_len = 14;

    size_t max_compressed_len = huffman_worst_case_size(input_len);
    uint8_t *compressed_data = (uint8_t *)malloc(max_compressed_len);
    uint8_t *decompressed_data = (uint8_t *)malloc(input_len + 1); // +1 for safety/null term
    if (!check_not_null(compressed_data, "Malloc compressed_data failed") ||
        !check_not_null(decompressed_data, "Malloc decompressed_data failed")) {
        free(compressed_data); free(decompressed_data); return 0;
    }

    size_t compressed_len = 0;
    int result = huffman_compress(input, input_len, compressed_data, max_compressed_len, &compressed_len);
    if (!check_equal_int(0, result, "huffman_compress returned error") ||
        !check(compressed_len > 0, "Compressed length should be > 0") ||
        !check(compressed_len <= max_compressed_len, "Compressed length exceeds worst case")) {
        free(compressed_data); free(decompressed_data); return 0;
    }

    size_t decompressed_len = 0;
    result = huffman_decompress(compressed_data, compressed_len, decompressed_data, input_len, &decompressed_len);
    if (!check_equal_int(0, result, "huffman_decompress returned error") ||
        !check_equal_size(input_len, decompressed_len, "Decompressed length mismatch")) {
        free(compressed_data); free(decompressed_data); return 0;
    }

    int mem_ok = check_equal_mem(input, decompressed_data, input_len, "Decompressed data mismatch");

    free(compressed_data);
    free(decompressed_data);
    return mem_ok;
}

// Test with empty input
static int test_huffman_empty() {
    uint8_t input[] = "";
    size_t input_len = 0;
    size_t max_compressed_len = huffman_worst_case_size(input_len) + 10; // Generous buffer
    uint8_t *compressed_data = (uint8_t *)malloc(max_compressed_len);
    uint8_t *decompressed_data = (uint8_t *)malloc(1); // Minimal buffer for empty output
    if (!check_not_null(compressed_data, "Malloc compressed_data failed") ||
        !check_not_null(decompressed_data, "Malloc decompressed_data failed")) {
        free(compressed_data); free(decompressed_data); return 0;
    }

    size_t compressed_len = 0;
    int result = huffman_compress(input, input_len, compressed_data, max_compressed_len, &compressed_len);
     if (!check_equal_int(0, result, "huffman_compress (empty) returned error") ||
         !check_equal_size(0, compressed_len, "Compressed length for empty input should be 0")) {
         free(compressed_data); free(decompressed_data); return 0;
     }

    // Decompressing empty data should also result in empty data
    size_t decompressed_len = 0;
    // Note: The implementation might store metadata even for empty compression,
    // adjust the check below based on actual behaviour. If compress outputs 0 bytes,
    // decompress should handle 0 byte input gracefully.
    result = huffman_decompress(compressed_data, compressed_len, decompressed_data, 0, &decompressed_len);
     if (!check_equal_int(0, result, "huffman_decompress (empty) returned error") ||
         !check_equal_size(0, decompressed_len, "Decompressed length for empty input should be 0")) {
         free(compressed_data); free(decompressed_data); return 0;
     }

    free(compressed_data);
    free(decompressed_data);
    return 1; // Success
}

// Test with input containing all identical bytes
static int test_huffman_all_same() {
    size_t input_len = 100;
    uint8_t *input = (uint8_t *)malloc(input_len);
    if (!check_not_null(input, "Malloc input failed")) return 0;
    memset(input, 'X', input_len); // Fill with 'X'

    size_t max_compressed_len = huffman_worst_case_size(input_len);
    uint8_t *compressed_data = (uint8_t *)malloc(max_compressed_len);
    uint8_t *decompressed_data = (uint8_t *)malloc(input_len);
    if (!check_not_null(compressed_data, "Malloc compressed_data failed") ||
        !check_not_null(decompressed_data, "Malloc decompressed_data failed")) {
        free(input); free(compressed_data); free(decompressed_data); return 0;
    }

    size_t compressed_len = 0;
    int result = huffman_compress(input, input_len, compressed_data, max_compressed_len, &compressed_len);
    if (!check_equal_int(0, result, "huffman_compress (all same) returned error") ||
        !check(compressed_len > 0 && compressed_len < input_len, "Compressed length should be smaller for uniform data")) {
         // Allow leeway, it won't be *tiny* due to header, but should be significantly less than input_len.
        free(input); free(compressed_data); free(decompressed_data); return 0;
    }

    size_t decompressed_len = 0;
    result = huffman_decompress(compressed_data, compressed_len, decompressed_data, input_len, &decompressed_len);
    if (!check_equal_int(0, result, "huffman_decompress (all same) returned error") ||
        !check_equal_size(input_len, decompressed_len, "Decompressed length mismatch (all same)")) {
        free(input); free(compressed_data); free(decompressed_data); return 0;
    }

    int mem_ok = check_equal_mem(input, decompressed_data, input_len, "Decompressed data mismatch (all same)");

    free(input);
    free(compressed_data);
    free(decompressed_data);
    return mem_ok;
}


// Test suite runner for Huffman tests
void run_huffman_tests() {
    TEST_START("Huffman Compression");
    RUN_TEST(test_huffman_basic);
    RUN_TEST(test_huffman_empty);
    RUN_TEST(test_huffman_all_same);
    // Add more tests: e.g., single character input, all byte values, large input
    TEST_END("Huffman Compression");
}