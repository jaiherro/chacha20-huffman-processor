#include "compression/huffman.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
// #include <stdint.h> // Removed

// Test case 1: Basic compression and decompression
static int test_huffman_basic(void)
{
    const char *input_str = "this is a test string with repeated characters";
    unsigned char *input = (unsigned char *)input_str; // Replaced uint8_t with unsigned char
    unsigned long input_len = strlen(input_str);       // Replaced size_t with unsigned long

    unsigned long output_max_len = huffman_worst_case_size(input_len); // Replaced size_t with unsigned long
    unsigned char *output = (unsigned char *)malloc(output_max_len);   // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(output, "Failed to allocate output buffer");

    unsigned long compressed_len; // Replaced size_t with unsigned long
    int result = huffman_compress(input, input_len, output, output_max_len, &compressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_compress failed");
    ASSERT_TRUE(compressed_len > 0 || input_len == 0, "Compressed length should be > 0 (unless input is empty)");
    // Basic check: compression should ideally reduce size for this repetitive string
    if (input_len > 0)
    {                                                                                                                                           // Avoid issues with empty input string for this check
        ASSERT_TRUE(compressed_len < input_len + sizeof(unsigned long) + 256, "Compression didn't reduce size significantly or grew too much"); // header + tree overhead
    }

    unsigned long decompressed_max_len = input_len + 1;                                                         // Replaced size_t with unsigned long. Allow for null terminator if it were a string.
    unsigned char *decompressed = (unsigned char *)malloc(decompressed_max_len > 0 ? decompressed_max_len : 1); // Replaced uint8_t with unsigned char. Avoid malloc(0).
    ASSERT_NOT_NULL(decompressed, "Failed to allocate decompressed buffer");

    unsigned long decompressed_len;                                                                  // Replaced size_t with unsigned long
    result = huffman_decompress(output, compressed_len, decompressed, input_len, &decompressed_len); // Pass original input_len as max for output
    ASSERT_EQUAL_INT(0, result, "huffman_decompress failed");
    ASSERT_EQUAL_INT(input_len, decompressed_len, "Decompressed length mismatch");
    if (input_len > 0)
    { // Only compare memory if there's something to compare
        ASSERT_EQUAL_MEM(input, decompressed, input_len, "Decompressed data mismatch");
    }

    free(output);
    free(decompressed);
    return 1; // Success
}

// Test case 2: Empty input
static int test_huffman_empty(void)
{
    unsigned char input[] = "";  // Replaced uint8_t with unsigned char
    unsigned long input_len = 0; // Replaced size_t with unsigned long

    unsigned long output_max_len = huffman_worst_case_size(input_len);                        // Replaced size_t with unsigned long
    unsigned char *output = (unsigned char *)malloc(output_max_len > 0 ? output_max_len : 1); // Avoid malloc(0) // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(output, "Failed to allocate output buffer");

    unsigned long compressed_len; // Replaced size_t with unsigned long
    int result = huffman_compress(input, input_len, output, output_max_len, &compressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_compress failed for empty input");
    ASSERT_EQUAL_INT(0, compressed_len, "Compressed length should be 0 for empty input");

    unsigned long decompressed_max_len = 1;                                      // Should be 0, but allocate 1 to be safe // Replaced size_t with unsigned long
    unsigned char *decompressed = (unsigned char *)malloc(decompressed_max_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(decompressed, "Failed to allocate decompressed buffer");

    unsigned long decompressed_len; // Replaced size_t with unsigned long
    // For decompress, output_max_len should be the expected original size.
    // If original was empty, expected is 0.
    result = huffman_decompress(output, compressed_len, decompressed, 0, &decompressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_decompress failed for empty input");
    ASSERT_EQUAL_INT(0, decompressed_len, "Decompressed length should be 0 for empty input");

    free(output);
    free(decompressed);
    return 1; // Success
}

// Test case 3: Input with a single character repeated
static int test_huffman_single_char(void)
{
    const char *input_str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned char *input = (unsigned char *)input_str; // Replaced uint8_t with unsigned char
    unsigned long input_len = strlen(input_str);       // Replaced size_t with unsigned long

    unsigned long output_max_len = huffman_worst_case_size(input_len); // Replaced size_t with unsigned long
    unsigned char *output = (unsigned char *)malloc(output_max_len);   // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(output, "Failed to allocate output buffer");

    unsigned long compressed_len; // Replaced size_t with unsigned long
    int result = huffman_compress(input, input_len, output, output_max_len, &compressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_compress failed for single char");
    ASSERT_TRUE(compressed_len > 0, "Compressed length should be > 0 for single char input");
    // Compression should be very effective here
    // Header (original_size + tree) + 1 bit per original char (approx)
    // Tree for 1 symbol is small. Original_size is sizeof(unsigned long).
    // Data bits should be input_len * 1 (or few bits if tree is minimal)
    ASSERT_TRUE(compressed_len < input_len, "Compression ineffective for single char");

    unsigned long decompressed_max_len = input_len + 1;                          // Replaced size_t with unsigned long
    unsigned char *decompressed = (unsigned char *)malloc(decompressed_max_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(decompressed, "Failed to allocate decompressed buffer");

    unsigned long decompressed_len; // Replaced size_t with unsigned long
    result = huffman_decompress(output, compressed_len, decompressed, input_len, &decompressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_decompress failed for single char");
    ASSERT_EQUAL_INT(input_len, decompressed_len, "Decompressed length mismatch for single char");
    ASSERT_EQUAL_MEM(input, decompressed, input_len, "Decompressed data mismatch for single char");

    free(output);
    free(decompressed);
    return 1; // Success
}

// Test case 4: Input with all unique characters (worst case for Huffman)
static int test_huffman_unique_chars(void)
{
    unsigned char input[256];      // Replaced uint8_t with unsigned char
    unsigned long input_len = 256; // Replaced size_t with unsigned long
    for (unsigned long i = 0; i < input_len; ++i)
    {                                // Replaced size_t with unsigned long
        input[i] = (unsigned char)i; // Replaced uint8_t with unsigned char
    }

    unsigned long output_max_len = huffman_worst_case_size(input_len); // Replaced size_t with unsigned long
    unsigned char *output = (unsigned char *)malloc(output_max_len);   // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(output, "Failed to allocate output buffer");

    unsigned long compressed_len; // Replaced size_t with unsigned long
    int result = huffman_compress(input, input_len, output, output_max_len, &compressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_compress failed for unique chars");
    ASSERT_TRUE(compressed_len > 0, "Compressed length should be > 0 for unique chars input");
    // Compression will likely increase size due to tree overhead + original size storage
    // Each char code will be ~8 bits, plus tree.
    ASSERT_TRUE(compressed_len > input_len, "Compression didn't increase size as expected for unique chars");

    unsigned long decompressed_max_len = input_len + 1;                          // Replaced size_t with unsigned long
    unsigned char *decompressed = (unsigned char *)malloc(decompressed_max_len); // Replaced uint8_t with unsigned char
    ASSERT_NOT_NULL(decompressed, "Failed to allocate decompressed buffer");

    unsigned long decompressed_len; // Replaced size_t with unsigned long
    result = huffman_decompress(output, compressed_len, decompressed, input_len, &decompressed_len);
    ASSERT_EQUAL_INT(0, result, "huffman_decompress failed for unique chars");
    ASSERT_EQUAL_INT(input_len, decompressed_len, "Decompressed length mismatch for unique chars");
    ASSERT_EQUAL_MEM(input, decompressed, input_len, "Decompressed data mismatch for unique chars");

    free(output);
    free(decompressed);
    return 1; // Success
}

// Function to run all compression tests
int run_compression_tests(void)
{
    START_TEST_SUITE("Huffman Compression");

    RUN_TEST(test_huffman_basic);
    RUN_TEST(test_huffman_empty);
    RUN_TEST(test_huffman_single_char);
    RUN_TEST(test_huffman_unique_chars);
    // Add more tests as needed

    END_TEST_SUITE();
}
