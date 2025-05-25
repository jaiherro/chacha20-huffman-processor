/**
 * test_huffman.c - Huffman compression tests
 */

#include "compression/huffman.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_INPUT_FILE "test_input.tmp"
#define TEST_COMPRESSED_FILE "test_compressed.tmp"
#define TEST_OUTPUT_FILE "test_output.tmp"

/* Helper function to create test file with content */
static int create_test_file(const char *filename, const unsigned char *content,
                            size_t size)
{
    FILE *file = fopen(filename, "wb");
    if (!file)
        return -1;

    if (size > 0 && fwrite(content, 1, size, file) != size)
        {
            fclose(file);
            return -1;
        }

    fclose(file);
    return 0;
}

/* Helper function to read file content */
static int read_test_file(const char *filename, unsigned char *buffer,
                          size_t buffer_size, size_t *bytes_read)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
        return -1;

    *bytes_read = fread(buffer, 1, buffer_size, file);
    fclose(file);
    return 0;
}

/* Helper function to get file size */
static long get_test_file_size(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
        return -1;

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fclose(file);
    return size;
}

/* Helper function to clean up test files */
static void cleanup_test_files(void)
{
    remove(TEST_INPUT_FILE);
    remove(TEST_COMPRESSED_FILE);
    remove(TEST_OUTPUT_FILE);
}

/* Test basic compression/decompression symmetry */
static int test_huffman_basic_symmetry(void)
{
    printf("  - Basic compression/decompression symmetry... ");

    const unsigned char test_data[]
        = "The quick brown fox jumps over the lazy dog. This is a test of "
          "Huffman compression with repeated characters and words.";
    size_t test_size = sizeof(test_data) - 1; // Exclude null terminator
    unsigned char output_buffer[1024];
    size_t output_size;

    cleanup_test_files();

    /* Create test input file */
    ASSERT_EQUAL(create_test_file(TEST_INPUT_FILE, test_data, test_size), 0,
                 "Failed to create test input file");

    /* Compress the file */
    ASSERT_EQUAL(
        huffman_compress_file(TEST_INPUT_FILE, TEST_COMPRESSED_FILE, 1), 0,
        "Huffman compression failed");

    /* Decompress the file */
    ASSERT_EQUAL(huffman_stream_decompress_file(TEST_COMPRESSED_FILE,
                                                TEST_OUTPUT_FILE, 1),
                 0, "Huffman decompression failed");

    /* Read the output and compare */
    ASSERT_EQUAL(read_test_file(TEST_OUTPUT_FILE, output_buffer,
                                sizeof(output_buffer), &output_size),
                 0, "Failed to read decompressed file");

    ASSERT_EQUAL(output_size, test_size,
                 "Decompressed size doesn't match original");
    ASSERT_MEM_EQUAL(output_buffer, test_data, test_size,
                     "Decompressed content doesn't match original");

    cleanup_test_files();
    printf("PASS\n");
    return TEST_PASS;
}

/* Test empty file handling */
static int test_huffman_empty_file(void)
{
    printf("  - Empty file handling... ");

    cleanup_test_files();

    /* Create empty test file */
    ASSERT_EQUAL(create_test_file(TEST_INPUT_FILE, NULL, 0), 0,
                 "Failed to create empty test file");

    /* Compress empty file */
    ASSERT_EQUAL(
        huffman_compress_file(TEST_INPUT_FILE, TEST_COMPRESSED_FILE, 1), 0,
        "Failed to compress empty file");

    /* Decompress empty file */
    ASSERT_EQUAL(huffman_stream_decompress_file(TEST_COMPRESSED_FILE,
                                                TEST_OUTPUT_FILE, 1),
                 0, "Failed to decompress empty file");

    /* Verify output file is empty */
    long output_size = get_test_file_size(TEST_OUTPUT_FILE);
    ASSERT_EQUAL(output_size, 0, "Decompressed empty file should be empty");

    cleanup_test_files();
    printf("PASS\n");
    return TEST_PASS;
}

/* Test single character file */
static int test_huffman_single_character(void)
{
    printf("  - Single character compression... ");

    const unsigned char test_data[] = "A";
    size_t test_size = 1;
    unsigned char output_buffer[16];
    size_t output_size;

    cleanup_test_files();

    ASSERT_EQUAL(create_test_file(TEST_INPUT_FILE, test_data, test_size), 0,
                 "Failed to create single character test file");

    ASSERT_EQUAL(
        huffman_compress_file(TEST_INPUT_FILE, TEST_COMPRESSED_FILE, 1), 0,
        "Single character compression failed");

    ASSERT_EQUAL(huffman_stream_decompress_file(TEST_COMPRESSED_FILE,
                                                TEST_OUTPUT_FILE, 1),
                 0, "Single character decompression failed");

    ASSERT_EQUAL(read_test_file(TEST_OUTPUT_FILE, output_buffer,
                                sizeof(output_buffer), &output_size),
                 0, "Failed to read single character output");

    ASSERT_EQUAL(output_size, test_size,
                 "Single character output size mismatch");
    ASSERT_MEM_EQUAL(output_buffer, test_data, test_size,
                     "Single character content mismatch");

    cleanup_test_files();
    printf("PASS\n");
    return TEST_PASS;
}

/* Test highly repetitive data */
static int test_huffman_repetitive_data(void)
{
    printf("  - Repetitive data compression... ");

    unsigned char test_data[1000];
    memset(test_data, 'A',
           sizeof(test_data)); /* All A's should compress very well */
    unsigned char output_buffer[1000];
    size_t output_size;

    cleanup_test_files();

    ASSERT_EQUAL(
        create_test_file(TEST_INPUT_FILE, test_data, sizeof(test_data)), 0,
        "Failed to create repetitive test file");

    ASSERT_EQUAL(
        huffman_compress_file(TEST_INPUT_FILE, TEST_COMPRESSED_FILE, 1), 0,
        "Repetitive data compression failed");

    /* Check that compression actually reduced size significantly */
    long original_size = get_test_file_size(TEST_INPUT_FILE);
    long compressed_size = get_test_file_size(TEST_COMPRESSED_FILE);
    ASSERT_TRUE(compressed_size < original_size / 2,
                "Repetitive data should compress significantly");

    ASSERT_EQUAL(huffman_stream_decompress_file(TEST_COMPRESSED_FILE,
                                                TEST_OUTPUT_FILE, 1),
                 0, "Repetitive data decompression failed");

    ASSERT_EQUAL(read_test_file(TEST_OUTPUT_FILE, output_buffer,
                                sizeof(output_buffer), &output_size),
                 0, "Failed to read repetitive output");

    ASSERT_EQUAL(output_size, sizeof(test_data),
                 "Repetitive output size mismatch");
    ASSERT_MEM_EQUAL(output_buffer, test_data, sizeof(test_data),
                     "Repetitive content mismatch");

    cleanup_test_files();
    printf("PASS\n");
    return TEST_PASS;
}

/* Test diverse character set */
static int test_huffman_diverse_data(void)
{
    printf("  - Diverse character set compression... ");

    /* Create data with all possible byte values */
    unsigned char test_data[256];
    for (int i = 0; i < 256; i++)
        {
            test_data[i] = (unsigned char)i;
        }

    unsigned char output_buffer[256];
    size_t output_size;

    cleanup_test_files();

    ASSERT_EQUAL(
        create_test_file(TEST_INPUT_FILE, test_data, sizeof(test_data)), 0,
        "Failed to create diverse test file");

    ASSERT_EQUAL(
        huffman_compress_file(TEST_INPUT_FILE, TEST_COMPRESSED_FILE, 1), 0,
        "Diverse data compression failed");

    ASSERT_EQUAL(huffman_stream_decompress_file(TEST_COMPRESSED_FILE,
                                                TEST_OUTPUT_FILE, 1),
                 0, "Diverse data decompression failed");

    ASSERT_EQUAL(read_test_file(TEST_OUTPUT_FILE, output_buffer,
                                sizeof(output_buffer), &output_size),
                 0, "Failed to read diverse output");

    ASSERT_EQUAL(output_size, sizeof(test_data),
                 "Diverse output size mismatch");
    ASSERT_MEM_EQUAL(output_buffer, test_data, sizeof(test_data),
                     "Diverse content mismatch");

    cleanup_test_files();
    printf("PASS\n");
    return TEST_PASS;
}

/* Test streaming context operations */
static int test_huffman_streaming_context(void)
{
    printf("  - Streaming context operations... ");

    huffman_stream_context ctx;
    const unsigned char test_data[] = "Hello, streaming world!";
    size_t test_size = sizeof(test_data) - 1;

    cleanup_test_files();

    /* Test context initialisation */
    ASSERT_EQUAL(huffman_stream_init(&ctx), 0, "Context initialisation failed");

    /* Create test file */
    ASSERT_EQUAL(create_test_file(TEST_INPUT_FILE, test_data, test_size), 0,
                 "Failed to create streaming test file");

    /* Test frequency counting */
    ASSERT_EQUAL(huffman_stream_count_frequencies(&ctx, TEST_INPUT_FILE), 0,
                 "Frequency counting failed");

    /* Verify input size was recorded */
    ASSERT_EQUAL(ctx.input_size, test_size,
                 "Input size not recorded correctly");
    ASSERT_EQUAL(ctx.pass, 1, "Pass number not updated correctly");

    /* Test encoding preparation */
    ASSERT_EQUAL(huffman_stream_prepare_encoding(&ctx), 0,
                 "Encoding preparation failed");
    ASSERT_EQUAL(ctx.pass, 2, "Pass number not updated after preparation");
    ASSERT_TRUE(ctx.tree != NULL, "Huffman tree not created");

    /* Test compression */
    ASSERT_EQUAL(huffman_stream_compress_file(&ctx, TEST_INPUT_FILE,
                                              TEST_COMPRESSED_FILE, 1),
                 0, "Streaming compression failed");

    /* Clean up context */
    huffman_stream_cleanup(&ctx);

    /* Verify decompression still works */
    ASSERT_EQUAL(huffman_stream_decompress_file(TEST_COMPRESSED_FILE,
                                                TEST_OUTPUT_FILE, 1),
                 0, "Decompression after context cleanup failed");

    cleanup_test_files();
    printf("PASS\n");
    return TEST_PASS;
}

/* Test error conditions */
static int test_huffman_error_conditions(void)
{
    printf("  - Error condition handling... ");

    huffman_stream_context ctx;

    /* Test NULL parameter handling */
    ASSERT_TRUE(huffman_stream_init(NULL) != 0, "Should reject NULL context");
    ASSERT_TRUE(huffman_compress_file(NULL, "output", 1) != 0,
                "Should reject NULL input file");
    ASSERT_TRUE(huffman_compress_file("input", NULL, 1) != 0,
                "Should reject NULL output file");
    ASSERT_TRUE(huffman_stream_decompress_file(NULL, "output", 1) != 0,
                "Should reject NULL input for decompression");
    ASSERT_TRUE(huffman_stream_decompress_file("input", NULL, 1) != 0,
                "Should reject NULL output for decompression");

    /* Test operations on non-existent files */
    cleanup_test_files();
    ASSERT_TRUE(
        huffman_compress_file("nonexistent_file.txt", TEST_COMPRESSED_FILE, 1)
            != 0,
        "Should fail on non-existent input file");
    ASSERT_TRUE(huffman_stream_decompress_file("nonexistent_compressed.huf",
                                               TEST_OUTPUT_FILE, 1)
                    != 0,
                "Should fail on non-existent compressed file");

    /* Test context operations in wrong order */
    huffman_stream_init(&ctx);
    ASSERT_TRUE(huffman_stream_prepare_encoding(&ctx) != 0,
                "Should fail prepare without frequency count");
    ASSERT_TRUE(huffman_stream_compress_file(&ctx, "nonexistent", "output", 1)
                    != 0,
                "Should fail compress without preparation");
    huffman_stream_cleanup(&ctx);

    printf("PASS\n");
    return TEST_PASS;
}

/* Test worst-case size calculation */
static int test_huffman_worst_case_size(void)
{
    printf("  - Worst-case size calculation... ");

    unsigned long test_sizes[] = { 0, 1, 100, 1000, 10000 };
    size_t num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);

    for (size_t i = 0; i < num_tests; i++)
        {
            unsigned long worst_case = huffman_worst_case_size(test_sizes[i]);
            ASSERT_TRUE(worst_case >= test_sizes[i],
                        "Worst case should be at least input size");
            ASSERT_TRUE(worst_case > 0 || test_sizes[i] == 0,
                        "Worst case should be positive for non-zero input");
        }

    printf("PASS\n");
    return TEST_PASS;
}

/* Test binary data compression */
static int test_huffman_binary_data(void)
{
    printf("  - Binary data compression... ");

    /* Create binary test data with some patterns */
    unsigned char test_data[512];
    for (int i = 0; i < 512; i++)
        {
            test_data[i]
                = (unsigned char)(i
                                  % 17); /* Some repetition but not too much */
        }

    unsigned char output_buffer[512];
    size_t output_size;

    cleanup_test_files();

    ASSERT_EQUAL(
        create_test_file(TEST_INPUT_FILE, test_data, sizeof(test_data)), 0,
        "Failed to create binary test file");

    ASSERT_EQUAL(
        huffman_compress_file(TEST_INPUT_FILE, TEST_COMPRESSED_FILE, 1), 0,
        "Binary data compression failed");

    ASSERT_EQUAL(huffman_stream_decompress_file(TEST_COMPRESSED_FILE,
                                                TEST_OUTPUT_FILE, 1),
                 0, "Binary data decompression failed");

    ASSERT_EQUAL(read_test_file(TEST_OUTPUT_FILE, output_buffer,
                                sizeof(output_buffer), &output_size),
                 0, "Failed to read binary output");

    ASSERT_EQUAL(output_size, sizeof(test_data), "Binary output size mismatch");
    ASSERT_MEM_EQUAL(output_buffer, test_data, sizeof(test_data),
                     "Binary content mismatch");

    cleanup_test_files();
    printf("PASS\n");
    return TEST_PASS;
}

int run_huffman_tests(void)
{
    printf("\n--- Huffman Compression Tests ---\n");

    if (test_huffman_basic_symmetry() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_empty_file() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_single_character() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_repetitive_data() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_diverse_data() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_streaming_context() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_error_conditions() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_worst_case_size() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_binary_data() != TEST_PASS)
        return TEST_FAIL;

    printf("Huffman compression tests: ALL PASSED\n");

    /* Final cleanup */
    cleanup_test_files();

    return TEST_PASS;
}