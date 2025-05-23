/**
 * test_huffman.c - Huffman compression tests
 */

#include "test_utils.h"
#include "compression/huffman.h"
#include <string.h>
#include <stdlib.h>

/* Test basic compression/decompression */
static int test_huffman_basic(void)
{
    printf("  - Basic compression/decompression... ");

    unsigned char input[] = "AAAAAABBBBBCCCCDDDEEF";
    unsigned char compressed[1024];
    unsigned char decompressed[1024];
    unsigned long compressed_len, decompressed_len;

    /* Compress */
    ASSERT_EQUAL(huffman_compress(input, sizeof(input) - 1, compressed,
                                  sizeof(compressed), &compressed_len),
                 0,
                 "Compression failed");

    /* Verify compression occurred */
    ASSERT_TRUE(compressed_len < sizeof(input) - 1,
                "Compressed size should be smaller than input");

    /* Decompress */
    ASSERT_EQUAL(huffman_decompress(compressed, compressed_len, decompressed,
                                    sizeof(decompressed), &decompressed_len),
                 0,
                 "Decompression failed");

    /* Verify correctness */
    ASSERT_EQUAL(decompressed_len, sizeof(input) - 1,
                 "Decompressed size mismatch");
    ASSERT_MEM_EQUAL(decompressed, input, sizeof(input) - 1,
                     "Decompressed data mismatch");

    printf("PASS\n");
    return TEST_PASS;
}

/* Test with repetitive data */
static int test_huffman_repetitive(void)
{
    printf("  - Repetitive data compression... ");

    unsigned char input[256];
    unsigned char compressed[512];
    unsigned char decompressed[256];
    unsigned long compressed_len, decompressed_len;

    /* Create repetitive pattern */
    for (int i = 0; i < 256; i++)
    {
        input[i] = 'A' + (i % 4);
    }

    ASSERT_EQUAL(huffman_compress(input, sizeof(input), compressed,
                                  sizeof(compressed), &compressed_len),
                 0,
                 "Compression failed");

    ASSERT_TRUE(compressed_len < sizeof(input),
                "Should achieve compression on repetitive data");

    ASSERT_EQUAL(huffman_decompress(compressed, compressed_len, decompressed,
                                    sizeof(decompressed), &decompressed_len),
                 0,
                 "Decompression failed");

    ASSERT_EQUAL(decompressed_len, sizeof(input), "Size mismatch");
    ASSERT_MEM_EQUAL(decompressed, input, sizeof(input), "Data mismatch");

    printf("PASS\n");
    return TEST_PASS;
}

/* Test edge cases */
static int test_huffman_edge_cases(void)
{
    printf("  - Edge cases... ");

    unsigned char single_byte[] = "X";
    unsigned char empty_input[1];
    unsigned char compressed[128];
    unsigned char decompressed[128];
    unsigned long compressed_len, decompressed_len;

    /* Single byte */
    ASSERT_EQUAL(huffman_compress(single_byte, 1, compressed,
                                  sizeof(compressed), &compressed_len),
                 0,
                 "Single byte compression failed");

    ASSERT_EQUAL(huffman_decompress(compressed, compressed_len, decompressed,
                                    sizeof(decompressed), &decompressed_len),
                 0,
                 "Single byte decompression failed");

    ASSERT_EQUAL(decompressed_len, 1, "Single byte size mismatch");
    ASSERT_EQUAL(decompressed[0], 'X', "Single byte data mismatch");

    /* Empty input */
    ASSERT_EQUAL(huffman_compress(empty_input, 0, compressed,
                                  sizeof(compressed), &compressed_len),
                 0,
                 "Empty compression failed");
    ASSERT_EQUAL(compressed_len, 0, "Empty compression should produce no output");

    printf("PASS\n");
    return TEST_PASS;
}

int run_huffman_tests(void)
{
    printf("\n--- Huffman Compression Tests ---\n");

    if (test_huffman_basic() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_repetitive() != TEST_PASS)
        return TEST_FAIL;
    if (test_huffman_edge_cases() != TEST_PASS)
        return TEST_FAIL;

    printf("Huffman tests: ALL PASSED\n");
    return TEST_PASS;
}