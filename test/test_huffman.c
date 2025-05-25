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

/* Test streaming compression */
static int test_huffman_streaming(void)
{
    printf("  - Streaming file compression... ");

    const char *test_input = "test_input.tmp";
    const char *test_compressed = "test_compressed.tmp";
    const char *test_decompressed = "test_decompressed.tmp";

    /* Create test input file */
    FILE *f = fopen(test_input, "wb");
    if (!f)
    {
        printf("FAIL (could not create test file)\n");
        return TEST_FAIL;
    }

    /* Write test data */
    const char *test_data = "AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFF";
    size_t data_len = strlen(test_data);

    /* Write the data multiple times to make it larger */
    for (int i = 0; i < 100; i++)
    {
        if (fwrite(test_data, 1, data_len, f) != data_len)
        {
            fclose(f);
            printf("FAIL (could not write test data)\n");
            return TEST_FAIL;
        }
    }
    fclose(f); /* Test streaming compression */
    ASSERT_EQUAL(huffman_compress_file(test_input, test_compressed, 1), 0,
                 "Streaming compression failed");

    /* Test streaming decompression */
    ASSERT_EQUAL(huffman_stream_decompress_file(test_compressed, test_decompressed, 1), 0,
                 "Streaming decompression failed");

    /* Verify the decompressed file matches the original */
    FILE *original = fopen(test_input, "rb");
    FILE *decompressed = fopen(test_decompressed, "rb");

    if (!original || !decompressed)
    {
        if (original)
            fclose(original);
        if (decompressed)
            fclose(decompressed);
        printf("FAIL (could not open files for verification)\n");
        return TEST_FAIL;
    }

    /* Compare files byte by byte */
    int ch1, ch2;
    do
    {
        ch1 = fgetc(original);
        ch2 = fgetc(decompressed);
        if (ch1 != ch2)
        {
            fclose(original);
            fclose(decompressed);
            printf("FAIL (decompressed file doesn't match original)\n");
            return TEST_FAIL;
        }
    } while (ch1 != EOF);

    fclose(original);
    fclose(decompressed);

    /* Clean up test files */
    remove(test_input);
    remove(test_compressed);
    remove(test_decompressed);

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
    if (test_huffman_streaming() != TEST_PASS)
        return TEST_FAIL;

    printf("Huffman tests: ALL PASSED\n");
    return TEST_PASS;
}