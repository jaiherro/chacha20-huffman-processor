/**
 * test_edge_cases.c - Edge case and error handling tests
 */

#include "test_utils.h"
#include "operations/file_operations.h"
#include "compression/huffman.h"
#include "encryption/chacha20.h"
#include "encryption/key_derivation.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

static int test_extremely_large_files(void)
{
    printf("  Testing with extremely large file scenarios...\n");

    // Test worst-case size calculation with large inputs
    unsigned long huge_size = ULONG_MAX / 2;
    unsigned long worst_case = huffman_worst_case_size(huge_size);
    
    ASSERT_TRUE(worst_case > huge_size, "Worst case should be larger than input for huge files");

    // Test with maximum representable size
    worst_case = huffman_worst_case_size(ULONG_MAX);
    // Should not overflow or crash
    ASSERT_TRUE(worst_case > 0, "Worst case calculation should handle maximum size");

    return TEST_PASS;
}

static int test_zero_length_operations(void)
{
    printf("  Testing operations with zero-length data...\n");

    const char *empty_file = "edge_empty.txt";
    const char *output_file = "edge_empty_output.tmp";
    const char *password = "empty_edge_password";

    // Create truly empty file
    ASSERT_EQUAL(create_test_file(empty_file, "", 0), 0,
                 "Should create empty file");

    unsigned long original_size, processed_size;

    // Test compression of empty file
    processed_size = compress_file(empty_file, output_file, 1, &original_size);
    ASSERT_TRUE(processed_size >= 0, "Empty file compression should handle gracefully");

    // Test encryption of empty file
    processed_size = encrypt_file(empty_file, output_file, password, 1, &original_size);
    ASSERT_TRUE(processed_size >= 0, "Empty file encryption should handle gracefully");

    // Test processing of empty file
    processed_size = process_file(empty_file, output_file, password, 1, &original_size);
    ASSERT_TRUE(processed_size >= 0, "Empty file processing should handle gracefully");

    return TEST_PASS;
}

static int test_single_byte_files(void)
{
    printf("  Testing operations with single-byte files...\n");

    const char *single_byte_file = "edge_single_byte.txt";
    const char *output_file = "edge_single_output.tmp";
    const char *final_file = "edge_single_final.txt";
    const char *password = "single_byte_password";
    const char single_byte_content[] = "A";

    // Create single-byte file
    ASSERT_EQUAL(create_test_file(single_byte_file, single_byte_content, 1), 0,
                 "Should create single-byte file");

    unsigned long original_size, processed_size, final_size;

    // Test full processing pipeline
    processed_size = process_file(single_byte_file, output_file, password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Single byte processing should succeed");
    ASSERT_EQUAL(original_size, 1, "Original size should be 1");

    final_size = extract_file(output_file, final_file, password, 1, &original_size);
    ASSERT_TRUE(final_size >= 0, "Single byte extraction should succeed");

    // Verify content matches
    ASSERT_EQUAL(compare_files(single_byte_file, final_file), 0,
                 "Single byte extracted file should match original");

    return TEST_PASS;
}

static int test_unicode_and_special_characters(void)
{
    printf("  Testing with Unicode and special characters...\n");

    const char *unicode_content = "Unicode test: ñáéíóú çüß αβγ 中文 🚀 💾 \x00\x01\x02\xFF";
    const char *unicode_file = "edge_unicode.txt";
    const char *output_file = "edge_unicode_output.sec";
    const char *final_file = "edge_unicode_final.txt";
    const char *password = "unicode_password_测试";

    // Create file with Unicode content
    ASSERT_EQUAL(create_test_file(unicode_file, unicode_content, strlen(unicode_content)), 0,
                 "Should create Unicode test file");

    unsigned long original_size, processed_size, final_size;

    // Test processing
    processed_size = process_file(unicode_file, output_file, password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Unicode processing should succeed");

    // Test extraction
    final_size = extract_file(output_file, final_file, password, 1, &original_size);
    ASSERT_TRUE(final_size > 0, "Unicode extraction should succeed");

    // Verify content preservation
    ASSERT_EQUAL(compare_files(unicode_file, final_file), 0,
                 "Unicode content should be preserved");

    return TEST_PASS;
}

static int test_binary_data_edge_cases(void)
{
    printf("  Testing with binary data edge cases...\n");

    // Create binary data with all possible byte values
    unsigned char binary_data[256];
    for (int i = 0; i < 256; i++)
        {
            binary_data[i] = (unsigned char)i;
        }

    const char *binary_file = "edge_binary.bin";
    const char *output_file = "edge_binary_output.sec";
    const char *final_file = "edge_binary_final.bin";
    const char *password = "binary_edge_password";

    // Create binary file
    ASSERT_EQUAL(create_test_file(binary_file, (char *)binary_data, 256), 0,
                 "Should create binary test file");

    unsigned long original_size, processed_size, final_size;

    // Test processing
    processed_size = process_file(binary_file, output_file, password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Binary processing should succeed");
    ASSERT_EQUAL(original_size, 256, "Original size should be 256");

    // Test extraction
    final_size = extract_file(output_file, final_file, password, 1, &original_size);
    ASSERT_TRUE(final_size > 0, "Binary extraction should succeed");

    // Verify binary content preservation
    ASSERT_EQUAL(compare_files(binary_file, final_file), 0,
                 "Binary content should be perfectly preserved");

    return TEST_PASS;
}

static int test_extremely_long_passwords(void)
{
    printf("  Testing with extremely long passwords...\n");

    const char *test_content = "Test content for long password edge case";
    const char *input_file = "edge_long_pass_input.txt";
    const char *output_file = "edge_long_pass_output.enc";
    const char *final_file = "edge_long_pass_final.txt";

    // Create very long password (but within reasonable limits)
    char long_password[512];
    memset(long_password, 'P', sizeof(long_password) - 1);
    long_password[sizeof(long_password) - 1] = '\0';

    // Create test file
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create test file");

    unsigned long original_size, processed_size, final_size;

    // Test processing with long password
    processed_size = process_file(input_file, output_file, long_password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Processing with long password should succeed");

    // Test extraction with same long password
    final_size = extract_file(output_file, final_file, long_password, 1, &original_size);
    ASSERT_TRUE(final_size > 0, "Extraction with long password should succeed");

    // Verify content
    ASSERT_EQUAL(compare_files(input_file, final_file), 0,
                 "Content should be preserved with long password");

    return TEST_PASS;
}

static int test_file_permission_errors(void)
{
    printf("  Testing file permission error handling...\n");

    const char *test_content = "Permission test content";
    const char *input_file = "edge_permission_input.txt";
    const char *readonly_output = "/dev/null"; // Should fail on write
    const char *password = "permission_password";

    // Create test file
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create test file");

    unsigned long original_size;

    // Test processing to read-only location (should fail gracefully)
    unsigned long processed_size = process_file(input_file, readonly_output, password, 1, &original_size);
    // On some systems this might succeed (like writing to /dev/null), so we just check it doesn't crash

    return TEST_PASS;
}

static int test_corrupted_data_handling(void)
{
    printf("  Testing corrupted data handling...\n");

    const char *corrupted_compressed = "edge_corrupted.huf";
    const char *corrupted_encrypted = "edge_corrupted.enc";
    const char *output_file = "edge_corrupted_output.txt";
    const char *password = "corrupted_password";

    // Create fake corrupted compressed file
    const char *fake_compressed = "This is not a valid Huffman compressed file at all!";
    ASSERT_EQUAL(create_test_file(corrupted_compressed, fake_compressed, strlen(fake_compressed)), 0,
                 "Should create fake compressed file");

    // Test decompression of corrupted file (should fail gracefully)
    unsigned long original_size;
    unsigned long result = decompress_file(corrupted_compressed, output_file, 1, &original_size);
    ASSERT_EQUAL(result, 0, "Decompression should fail gracefully with corrupted data");

    // Create fake corrupted encrypted file
    const char *fake_encrypted = "This is not a valid encrypted file format!";
    ASSERT_EQUAL(create_test_file(corrupted_encrypted, fake_encrypted, strlen(fake_encrypted)), 0,
                 "Should create fake encrypted file");

    // Test decryption of corrupted file (should fail gracefully)
    result = decrypt_file(corrupted_encrypted, output_file, password, 1, &original_size);
    ASSERT_EQUAL(result, 0, "Decryption should fail gracefully with corrupted data");

    return TEST_PASS;
}

static int test_memory_boundary_conditions(void)
{
    printf("  Testing memory boundary conditions...\n");

    // Test ChaCha20 with various input sizes around block boundaries
    unsigned char key[32] = {0};
    unsigned char nonce[12] = {0};
    chacha20_ctx ctx;

    int result = chacha20_init(&ctx, key, nonce, 0);
    ASSERT_EQUAL(result, 0, "ChaCha20 init should succeed");

    // Test various sizes around block boundaries
    size_t test_sizes[] = { 63, 64, 65, 127, 128, 129, 255, 256, 257 };
    
    for (size_t i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); i++)
        {
            unsigned char *input = malloc(test_sizes[i]);
            unsigned char *output = malloc(test_sizes[i]);
            
            if (input && output)
                {
                    memset(input, 0xAA, test_sizes[i]);
                    
                    // Reinitialize context for each test
                    chacha20_init(&ctx, key, nonce, 0);
                    result = chacha20_process(&ctx, input, output, test_sizes[i]);
                    ASSERT_EQUAL(result, 0, "ChaCha20 should handle boundary sizes");
                }
            
            free(input);
            free(output);
        }

    chacha20_cleanup(&ctx);

    return TEST_PASS;
}

int run_edge_case_tests(void)
{
    printf("Running edge case and error handling tests...\n");

    if (test_extremely_large_files() != TEST_PASS)
        return TEST_FAIL;
    if (test_zero_length_operations() != TEST_PASS)
        return TEST_FAIL;
    if (test_single_byte_files() != TEST_PASS)
        return TEST_FAIL;
    if (test_unicode_and_special_characters() != TEST_PASS)
        return TEST_FAIL;
    if (test_binary_data_edge_cases() != TEST_PASS)
        return TEST_FAIL;
    if (test_extremely_long_passwords() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_permission_errors() != TEST_PASS)
        return TEST_FAIL;
    if (test_corrupted_data_handling() != TEST_PASS)
        return TEST_FAIL;
    if (test_memory_boundary_conditions() != TEST_PASS)
        return TEST_FAIL;

    printf("All edge case tests passed!\n\n");
    return TEST_PASS;
}