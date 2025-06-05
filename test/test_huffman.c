/**
 * test_huffman.c - Huffman compression and decompression tests
 */

#include "test_utils.h"
#include "compression/huffman.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int test_huffman_basic_compression(void)
{
    printf("  Testing basic Huffman compression...\n");

    const char *test_content = "hello world hello world hello world";
    const char *input_file = "test_huffman_input.txt";
    const char *compressed_file = "test_huffman_compressed.huf";
    const char *decompressed_file = "test_huffman_decompressed.txt";

    // Create test input file
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create test input file");

    // Test compression
    int result = huffman_compress_file(input_file, compressed_file, 1);
    ASSERT_EQUAL(result, 0, "Huffman compression should succeed");
    ASSERT_TRUE(file_exists(compressed_file), "Compressed file should exist");

    // Test decompression
    result = huffman_stream_decompress_file(compressed_file, decompressed_file, 1);
    ASSERT_EQUAL(result, 0, "Huffman decompression should succeed");
    ASSERT_TRUE(file_exists(decompressed_file), "Decompressed file should exist");

    // Compare original and decompressed files
    ASSERT_EQUAL(compare_files(input_file, decompressed_file), 0,
                 "Decompressed file should match original");

    return TEST_PASS;
}

static int test_huffman_empty_file(void)
{
    printf("  Testing Huffman compression with empty file...\n");

    const char *input_file = "test_huffman_empty.txt";
    const char *compressed_file = "test_huffman_empty.huf";
    const char *decompressed_file = "test_huffman_empty_out.txt";

    // Create empty test file
    ASSERT_EQUAL(create_test_file(input_file, "", 0), 0,
                 "Should create empty test file");

    // Test compression of empty file
    int result = huffman_compress_file(input_file, compressed_file, 1);
    ASSERT_EQUAL(result, 0, "Empty file compression should succeed");

    // Test decompression
    result = huffman_stream_decompress_file(compressed_file, decompressed_file, 1);
    ASSERT_EQUAL(result, 0, "Empty file decompression should succeed");

    // Compare files
    ASSERT_EQUAL(compare_files(input_file, decompressed_file), 0,
                 "Empty decompressed file should match original");

    return TEST_PASS;
}

static int test_huffman_single_character(void)
{
    printf("  Testing Huffman compression with single character...\n");

    const char *test_content = "aaaaaaaaaa";
    const char *input_file = "test_huffman_single.txt";
    const char *compressed_file = "test_huffman_single.huf";
    const char *decompressed_file = "test_huffman_single_out.txt";

    // Create test file with repeated character
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create test input file");

    // Test compression
    int result = huffman_compress_file(input_file, compressed_file, 1);
    ASSERT_EQUAL(result, 0, "Single character compression should succeed");

    // Test decompression
    result = huffman_stream_decompress_file(compressed_file, decompressed_file, 1);
    ASSERT_EQUAL(result, 0, "Single character decompression should succeed");

    // Compare files
    ASSERT_EQUAL(compare_files(input_file, decompressed_file), 0,
                 "Single character decompressed file should match original");

    return TEST_PASS;
}

static int test_huffman_binary_data(void)
{
    printf("  Testing Huffman compression with binary data...\n");

    // Create binary test data
    unsigned char binary_data[256];
    for (int i = 0; i < 256; i++)
        {
            binary_data[i] = (unsigned char)i;
        }

    const char *input_file = "test_huffman_binary.bin";
    const char *compressed_file = "test_huffman_binary.huf";
    const char *decompressed_file = "test_huffman_binary_out.bin";

    // Create test file with binary data
    ASSERT_EQUAL(create_test_file(input_file, (char *)binary_data, 256), 0,
                 "Should create binary test file");

    // Test compression
    int result = huffman_compress_file(input_file, compressed_file, 1);
    ASSERT_EQUAL(result, 0, "Binary data compression should succeed");

    // Test decompression
    result = huffman_stream_decompress_file(compressed_file, decompressed_file, 1);
    ASSERT_EQUAL(result, 0, "Binary data decompression should succeed");

    // Compare files
    ASSERT_EQUAL(compare_files(input_file, decompressed_file), 0,
                 "Binary decompressed file should match original");

    return TEST_PASS;
}

static int test_huffman_large_file(void)
{
    printf("  Testing Huffman compression with large file...\n");

    size_t data_size = 10000;
    char *large_data = malloc(data_size);
    ASSERT_NOT_NULL(large_data, "Should allocate memory for large test data");

    // Fill with repeating pattern for good compression
    for (size_t i = 0; i < data_size; i++)
        {
            large_data[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[i % 26];
        }

    const char *input_file = "test_huffman_large.txt";
    const char *compressed_file = "test_huffman_large.huf";
    const char *decompressed_file = "test_huffman_large_out.txt";

    // Create large test file
    ASSERT_EQUAL(create_test_file(input_file, large_data, data_size), 0,
                 "Should create large test file");

    // Test compression
    int result = huffman_compress_file(input_file, compressed_file, 1);
    ASSERT_EQUAL(result, 0, "Large file compression should succeed");

    // Test decompression
    result = huffman_stream_decompress_file(compressed_file, decompressed_file, 1);
    ASSERT_EQUAL(result, 0, "Large file decompression should succeed");

    // Compare files
    ASSERT_EQUAL(compare_files(input_file, decompressed_file), 0,
                 "Large decompressed file should match original");

    free(large_data);
    return TEST_PASS;
}

static int test_huffman_streaming_context(void)
{
    printf("  Testing Huffman streaming context operations...\n");

    huffman_stream_context ctx;

    // Test initialization
    int result = huffman_stream_init(&ctx);
    ASSERT_EQUAL(result, 0, "Stream context initialization should succeed");

    // Test cleanup
    huffman_stream_cleanup(&ctx);

    return TEST_PASS;
}

static int test_huffman_worst_case_size(void)
{
    printf("  Testing Huffman worst case size calculation...\n");

    unsigned long input_size = 1000;
    unsigned long worst_case = huffman_worst_case_size(input_size);

    // Worst case should be larger than input size due to overhead
    ASSERT_TRUE(worst_case > input_size, "Worst case size should be larger than input");

    // Test with zero input
    worst_case = huffman_worst_case_size(0);
    ASSERT_TRUE(worst_case > 0, "Worst case for zero input should account for headers");

    return TEST_PASS;
}

static int test_huffman_nonexistent_file(void)
{
    printf("  Testing Huffman compression with nonexistent file...\n");

    const char *nonexistent_file = "this_file_does_not_exist.txt";
    const char *output_file = "test_huffman_output.huf";

    // Should fail gracefully
    int result = huffman_compress_file(nonexistent_file, output_file, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should fail with nonexistent input file");

    return TEST_PASS;
}

static int test_huffman_corrupted_file(void)
{
    printf("  Testing Huffman decompression with corrupted file...\n");

    const char *corrupted_content = "This is not a valid Huffman compressed file";
    const char *corrupted_file = "test_huffman_corrupted.huf";
    const char *output_file = "test_huffman_corrupted_out.txt";

    // Create fake compressed file
    ASSERT_EQUAL(create_test_file(corrupted_file, corrupted_content, strlen(corrupted_content)), 0,
                 "Should create corrupted test file");

    // Should fail gracefully
    int result = huffman_stream_decompress_file(corrupted_file, output_file, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should fail with corrupted compressed file");

    return TEST_PASS;
}

int run_huffman_tests(void)
{
    printf("Running Huffman compression tests...\n");

    if (test_huffman_basic_compression() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_empty_file() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_single_character() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_binary_data() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_large_file() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_streaming_context() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_worst_case_size() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_nonexistent_file() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_corrupted_file() != TEST_PASS)
        return TEST_FAIL;

    printf("All Huffman compression tests passed!\n\n");
    return TEST_PASS;
}