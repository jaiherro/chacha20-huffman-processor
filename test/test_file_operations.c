/**
 * test_file_operations.c - File operations tests
 */

#include "test_utils.h"
#include "operations/file_operations.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int test_compress_decompress_file(void)
{
    printf("  Testing file compression and decompression...\n");

    const char *test_content = "This is test content for compression testing. "
                               "It should compress and decompress correctly.";
    const char *input_file = "test_compress_input.txt";
    const char *compressed_file = "test_compress_output.huf";
    const char *decompressed_file = "test_decompress_output.txt";

    // Create test input file
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create test input file");

    unsigned long original_size, compressed_size;

    // Test compression
    compressed_size = compress_file(input_file, compressed_file, 1, &original_size);
    ASSERT_TRUE(compressed_size > 0, "Compression should succeed and return size");
    ASSERT_EQUAL(original_size, strlen(test_content), "Original size should match input");
    ASSERT_TRUE(file_exists(compressed_file), "Compressed file should exist");

    // Test decompression
    unsigned long decompressed_size;
    decompressed_size = decompress_file(compressed_file, decompressed_file, 1, &original_size);
    ASSERT_TRUE(decompressed_size > 0, "Decompression should succeed");
    ASSERT_TRUE(file_exists(decompressed_file), "Decompressed file should exist");

    // Compare original and decompressed files
    ASSERT_EQUAL(compare_files(input_file, decompressed_file), 0,
                 "Decompressed file should match original");

    return TEST_PASS;
}

static int test_encrypt_decrypt_file(void)
{
    printf("  Testing file encryption and decryption...\n");

    const char *test_content = "Secret message for encryption testing!";
    const char *password = "test_password_123";
    const char *input_file = "test_encrypt_input.txt";
    const char *encrypted_file = "test_encrypt_output.enc";
    const char *decrypted_file = "test_decrypt_output.txt";

    // Create test input file
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create test input file");

    unsigned long original_size, processed_size;

    // Test encryption
    processed_size = encrypt_file(input_file, encrypted_file, password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Encryption should succeed and return size");
    ASSERT_EQUAL(original_size, strlen(test_content), "Original size should match input");
    ASSERT_TRUE(file_exists(encrypted_file), "Encrypted file should exist");

    // Test decryption
    unsigned long decrypted_size;
    decrypted_size = decrypt_file(encrypted_file, decrypted_file, password, 1, &original_size);
    ASSERT_TRUE(decrypted_size > 0, "Decryption should succeed");
    ASSERT_TRUE(file_exists(decrypted_file), "Decrypted file should exist");

    // Compare original and decrypted files
    ASSERT_EQUAL(compare_files(input_file, decrypted_file), 0,
                 "Decrypted file should match original");

    return TEST_PASS;
}

static int test_process_extract_file(void)
{
    printf("  Testing file processing (compress + encrypt) and extraction...\n");

    const char *test_content = "This content will be compressed and encrypted together!";
    const char *password = "process_password_456";
    const char *input_file = "test_process_input.txt";
    const char *processed_file = "test_process_output.sec";
    const char *extracted_file = "test_extract_output.txt";

    // Create test input file
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create test input file");

    unsigned long original_size, processed_size;

    // Test processing (compress + encrypt)
    processed_size = process_file(input_file, processed_file, password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Processing should succeed and return size");
    ASSERT_EQUAL(original_size, strlen(test_content), "Original size should match input");
    ASSERT_TRUE(file_exists(processed_file), "Processed file should exist");

    // Test extraction (decrypt + decompress)
    unsigned long extracted_size;
    extracted_size = extract_file(processed_file, extracted_file, password, 1, &original_size);
    ASSERT_TRUE(extracted_size > 0, "Extraction should succeed");
    ASSERT_TRUE(file_exists(extracted_file), "Extracted file should exist");

    // Compare original and extracted files
    ASSERT_EQUAL(compare_files(input_file, extracted_file), 0,
                 "Extracted file should match original");

    return TEST_PASS;
}

static int test_wrong_password_decryption(void)
{
    printf("  Testing decryption with wrong password...\n");

    const char *test_content = "Secret content";
    const char *correct_password = "correct_password";
    const char *wrong_password = "wrong_password";
    const char *input_file = "test_wrong_pass_input.txt";
    const char *encrypted_file = "test_wrong_pass_encrypted.enc";
    const char *decrypted_file = "test_wrong_pass_decrypted.txt";

    // Create and encrypt file
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create test input file");

    unsigned long original_size, processed_size;
    processed_size = encrypt_file(input_file, encrypted_file, correct_password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Encryption should succeed");

    // Try to decrypt with wrong password
    unsigned long decrypted_size;
    decrypted_size = decrypt_file(encrypted_file, decrypted_file, wrong_password, 1, &original_size);
    ASSERT_EQUAL(decrypted_size, 0, "Decryption with wrong password should fail");

    return TEST_PASS;
}

static int test_file_operations_nonexistent_input(void)
{
    printf("  Testing file operations with nonexistent input...\n");

    const char *nonexistent_file = "this_file_does_not_exist.txt";
    const char *output_file = "test_output.tmp";
    const char *password = "test_password";
    unsigned long original_size;

    // Test compression with nonexistent file
    unsigned long result = compress_file(nonexistent_file, output_file, 1, &original_size);
    ASSERT_EQUAL(result, 0, "Compression should fail with nonexistent input");

    // Test encryption with nonexistent file
    result = encrypt_file(nonexistent_file, output_file, password, 1, &original_size);
    ASSERT_EQUAL(result, 0, "Encryption should fail with nonexistent input");

    // Test processing with nonexistent file
    result = process_file(nonexistent_file, output_file, password, 1, &original_size);
    ASSERT_EQUAL(result, 0, "Processing should fail with nonexistent input");

    return TEST_PASS;
}

static int test_empty_file_operations(void)
{
    printf("  Testing file operations with empty files...\n");

    const char *empty_file = "test_empty_input.txt";
    const char *output_file = "test_empty_output.tmp";
    const char *final_file = "test_empty_final.txt";
    const char *password = "empty_test_password";

    // Create empty file
    ASSERT_EQUAL(create_test_file(empty_file, "", 0), 0,
                 "Should create empty test file");

    unsigned long original_size, processed_size;

    // Test compression of empty file
    processed_size = compress_file(empty_file, output_file, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Empty file compression should succeed");

    // Test decompression
    unsigned long final_size = decompress_file(output_file, final_file, 1, &original_size);
    ASSERT_TRUE(final_size >= 0, "Empty file decompression should succeed");

    // Compare files
    ASSERT_EQUAL(compare_files(empty_file, final_file), 0,
                 "Empty decompressed file should match original");

    return TEST_PASS;
}

static int test_large_file_operations(void)
{
    printf("  Testing file operations with large files...\n");

    size_t data_size = 50000;
    char *large_data = malloc(data_size);
    ASSERT_NOT_NULL(large_data, "Should allocate memory for large test data");

    // Fill with pattern
    for (size_t i = 0; i < data_size; i++)
        {
            large_data[i] = (char)('A' + (i % 26));
        }

    const char *input_file = "test_large_input.txt";
    const char *processed_file = "test_large_processed.sec";
    const char *output_file = "test_large_output.txt";
    const char *password = "large_file_password";

    // Create large test file
    ASSERT_EQUAL(create_test_file(input_file, large_data, data_size), 0,
                 "Should create large test file");

    unsigned long original_size, processed_size;

    // Test processing
    processed_size = process_file(input_file, processed_file, password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Large file processing should succeed");
    ASSERT_EQUAL(original_size, data_size, "Original size should match input");

    // Test extraction
    unsigned long extracted_size = extract_file(processed_file, output_file, password, 1, &original_size);
    ASSERT_TRUE(extracted_size > 0, "Large file extraction should succeed");

    // Compare files
    ASSERT_EQUAL(compare_files(input_file, output_file), 0,
                 "Large extracted file should match original");

    free(large_data);
    return TEST_PASS;
}

int run_file_operations_tests(void)
{
    printf("Running file operations tests...\n");

    if (test_compress_decompress_file() != TEST_PASS)
        return TEST_FAIL;
    if (test_encrypt_decrypt_file() != TEST_PASS)
        return TEST_FAIL;
    if (test_process_extract_file() != TEST_PASS)
        return TEST_FAIL;
    if (test_wrong_password_decryption() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_operations_nonexistent_input() != TEST_PASS)
        return TEST_FAIL;
    if (test_empty_file_operations() != TEST_PASS)
        return TEST_FAIL;
    if (test_large_file_operations() != TEST_PASS)
        return TEST_FAIL;

    printf("All file operations tests passed!\n\n");
    return TEST_PASS;
}