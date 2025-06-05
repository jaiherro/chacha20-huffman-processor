/**
 * test_integration.c - Integration tests for end-to-end workflows
 */

#include "test_utils.h"
#include "operations/file_operations.h"
#include "operations/batch.h"
#include "utils/file_list.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int test_full_encrypt_decrypt_workflow(void)
{
    printf("  Testing full encrypt-decrypt workflow...\n");

    const char *original_content = "This is a comprehensive test of the encryption and decryption workflow. "
                                   "It includes various characters: !@#$%^&*()_+-=[]{}|;:,.<>? "
                                   "Numbers: 1234567890 and Unicode: ñáéíóú";
    const char *password = "integration_test_password_2023";
    const char *input_file = "integration_original.txt";
    const char *encrypted_file = "integration_encrypted.enc";
    const char *decrypted_file = "integration_decrypted.txt";

    // Create original file
    ASSERT_EQUAL(create_test_file(input_file, original_content, strlen(original_content)), 0,
                 "Should create original file");

    unsigned long original_size, encrypted_size, decrypted_size;

    // Encrypt the file
    encrypted_size = encrypt_file(input_file, encrypted_file, password, 0, &original_size);
    ASSERT_TRUE(encrypted_size > 0, "File encryption should succeed");
    ASSERT_TRUE(file_exists(encrypted_file), "Encrypted file should exist");
    ASSERT_TRUE(encrypted_size > original_size, "Encrypted file should be larger (includes salt + overhead)");

    // Decrypt the file
    decrypted_size = decrypt_file(encrypted_file, decrypted_file, password, 0, &original_size);
    ASSERT_TRUE(decrypted_size > 0, "File decryption should succeed");
    ASSERT_TRUE(file_exists(decrypted_file), "Decrypted file should exist");

    // Verify content matches
    ASSERT_EQUAL(compare_files(input_file, decrypted_file), 0,
                 "Decrypted file should exactly match original");

    // Verify it was added to file list
    int list_result = handle_file_list("find", "integration", 1);
    ASSERT_EQUAL(list_result, 0, "File should be findable in file list");

    return TEST_PASS;
}

static int test_full_compress_decompress_workflow(void)
{
    printf("  Testing full compress-decompress workflow...\n");

    // Create content with good compression potential
    size_t content_size = 5000;
    char *repetitive_content = malloc(content_size);
    ASSERT_NOT_NULL(repetitive_content, "Should allocate memory for test content");

    // Fill with repetitive pattern for good compression
    const char *pattern = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t pattern_len = strlen(pattern);
    for (size_t i = 0; i < content_size; i++)
        {
            repetitive_content[i] = pattern[i % pattern_len];
        }

    const char *input_file = "integration_compress_input.txt";
    const char *compressed_file = "integration_compressed.huf";
    const char *decompressed_file = "integration_decompressed.txt";

    // Create input file
    ASSERT_EQUAL(create_test_file(input_file, repetitive_content, content_size), 0,
                 "Should create input file for compression test");

    unsigned long original_size, compressed_size, decompressed_size;

    // Compress the file
    compressed_size = compress_file(input_file, compressed_file, 0, &original_size);
    ASSERT_TRUE(compressed_size > 0, "File compression should succeed");
    ASSERT_TRUE(file_exists(compressed_file), "Compressed file should exist");
    ASSERT_EQUAL(original_size, content_size, "Original size should match input");
    ASSERT_TRUE(compressed_size < original_size, "Compressed file should be smaller");

    // Decompress the file
    decompressed_size = decompress_file(compressed_file, decompressed_file, 0, &original_size);
    ASSERT_TRUE(decompressed_size > 0, "File decompression should succeed");
    ASSERT_TRUE(file_exists(decompressed_file), "Decompressed file should exist");

    // Verify content matches
    ASSERT_EQUAL(compare_files(input_file, decompressed_file), 0,
                 "Decompressed file should exactly match original");

    free(repetitive_content);
    return TEST_PASS;
}

static int test_full_process_extract_workflow(void)
{
    printf("  Testing full process-extract workflow...\n");

    const char *complex_content = "Integration test for process (compress+encrypt) and extract (decrypt+decompress). "
                                  "This tests the complete pipeline with realistic data. "
                                  "Binary data: \x00\x01\x02\x03\x04\xFF\xFE\xFD\xFC "
                                  "Special chars: åäö ñç ß μ π ∑ ∞ ";
    const char *password = "process_extract_password_456";
    const char *input_file = "integration_process_input.txt";
    const char *processed_file = "integration_processed.sec";
    const char *extracted_file = "integration_extracted.txt";

    // Create input file
    ASSERT_EQUAL(create_test_file(input_file, complex_content, strlen(complex_content)), 0,
                 "Should create input file for process test");

    unsigned long original_size, processed_size, extracted_size;

    // Process the file (compress + encrypt)
    processed_size = process_file(input_file, processed_file, password, 0, &original_size);
    ASSERT_TRUE(processed_size > 0, "File processing should succeed");
    ASSERT_TRUE(file_exists(processed_file), "Processed file should exist");
    ASSERT_EQUAL(original_size, strlen(complex_content), "Original size should match input");

    // Extract the file (decrypt + decompress)
    extracted_size = extract_file(processed_file, extracted_file, password, 0, &original_size);
    ASSERT_TRUE(extracted_size > 0, "File extraction should succeed");
    ASSERT_TRUE(file_exists(extracted_file), "Extracted file should exist");

    // Verify content matches exactly
    ASSERT_EQUAL(compare_files(input_file, extracted_file), 0,
                 "Extracted file should exactly match original");

    // Verify it was added to file list
    int list_result = handle_file_list("find", "process", 1);
    ASSERT_EQUAL(list_result, 0, "Processed file should be findable in file list");

    return TEST_PASS;
}

static int test_batch_processing_workflow(void)
{
    printf("  Testing batch processing workflow...\n");

    // Create multiple test files
    const char *files[] = {
        "batch_file1.txt",
        "batch_file2.txt", 
        "batch_file3.txt"
    };
    const char *contents[] = {
        "Content of batch file number one with some text for compression.",
        "Second batch file content with different data for testing purposes.",
        "Third and final batch file with unique content for comprehensive testing."
    };
    
    const char *output_dir = "batch_output_test";
    const char *password = "batch_test_password_789";

    // Create test files
    for (int i = 0; i < 3; i++)
        {
            ASSERT_EQUAL(create_test_file(files[i], contents[i], strlen(contents[i])), 0,
                         "Should create batch test file");
        }

    // Create output directory
    char mkdir_cmd[256];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    system(mkdir_cmd);

    // Prepare file array for batch processing
    char *file_array[3];
    for (int i = 0; i < 3; i++)
        {
            file_array[i] = (char *)files[i];
        }

    // Process files in batch
    int result = batch_process(file_array, 3, output_dir, password, 0);
    ASSERT_EQUAL(result, 0, "Batch processing should succeed");

    // Verify output files exist
    for (int i = 0; i < 3; i++)
        {
            char expected_output[512];
            snprintf(expected_output, sizeof(expected_output), "%s/%s.secure", output_dir, files[i]);
            ASSERT_TRUE(file_exists(expected_output), "Batch output file should exist");
        }

    // Test extraction of one batch file to verify correctness
    char batch_output[512];
    char extracted_file[512];
    snprintf(batch_output, sizeof(batch_output), "%s/%s.secure", output_dir, files[0]);
    snprintf(extracted_file, sizeof(extracted_file), "batch_extracted_%s", files[0]);

    unsigned long original_size;
    unsigned long extracted_size = extract_file(batch_output, extracted_file, password, 1, &original_size);
    ASSERT_TRUE(extracted_size > 0, "Batch file extraction should succeed");

    // Compare with original
    ASSERT_EQUAL(compare_files(files[0], extracted_file), 0,
                 "Extracted batch file should match original");

    return TEST_PASS;
}

static int test_mixed_file_types_workflow(void)
{
    printf("  Testing workflow with mixed file types...\n");

    // Test with different file types and sizes
    struct {
        const char *filename;
        const char *content;
        size_t content_size;
        const char *description;
    } test_files[] = {
        {"test_text.txt", "Plain text file content for testing.", 0, "text file"},
        {"test_binary.bin", "\x00\x01\x02\x03\xFF\xFE\xFD\xFC\x7F\x80", 10, "binary file"},
        {"test_empty.dat", "", 0, "empty file"},
        {"test_large.log", NULL, 10000, "large file"}
    };

    const char *password = "mixed_types_password";

    // Create large file content
    char *large_content = malloc(10000);
    if (large_content)
        {
            for (int i = 0; i < 10000; i++)
                {
                    large_content[i] = (char)('A' + (i % 26));
                }
            test_files[3].content = large_content;
        }

    for (size_t i = 0; i < sizeof(test_files) / sizeof(test_files[0]); i++)
        {
            if (!test_files[i].content && i == 3)
                continue; // Skip if malloc failed

            size_t size = test_files[i].content_size > 0 ? test_files[i].content_size : strlen(test_files[i].content);
            
            // Create file
            ASSERT_EQUAL(create_test_file(test_files[i].filename, test_files[i].content, size), 0,
                         "Should create mixed type test file");

            // Process file
            char processed_file[256];
            char extracted_file[256];
            snprintf(processed_file, sizeof(processed_file), "%s.processed", test_files[i].filename);
            snprintf(extracted_file, sizeof(extracted_file), "%s.extracted", test_files[i].filename);

            unsigned long original_size, processed_size, extracted_size;
            
            processed_size = process_file(test_files[i].filename, processed_file, password, 1, &original_size);
            ASSERT_TRUE(processed_size > 0, "Mixed type file processing should succeed");

            extracted_size = extract_file(processed_file, extracted_file, password, 1, &original_size);
            ASSERT_TRUE(extracted_size >= 0, "Mixed type file extraction should succeed");

            // Compare files
            ASSERT_EQUAL(compare_files(test_files[i].filename, extracted_file), 0,
                         "Mixed type extracted file should match original");
        }

    if (large_content)
        free(large_content);

    return TEST_PASS;
}

static int test_error_recovery_workflow(void)
{
    printf("  Testing error recovery in workflows...\n");

    const char *test_content = "Error recovery test content";
    const char *correct_password = "correct_password";
    const char *wrong_password = "wrong_password";
    const char *input_file = "error_recovery_input.txt";
    const char *processed_file = "error_recovery_processed.sec";
    const char *output_file = "error_recovery_output.txt";

    // Create test file
    ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                 "Should create error recovery test file");

    unsigned long original_size, processed_size;

    // Process with correct password
    processed_size = process_file(input_file, processed_file, correct_password, 1, &original_size);
    ASSERT_TRUE(processed_size > 0, "Processing with correct password should succeed");

    // Try to extract with wrong password (should fail gracefully)
    unsigned long extracted_size = extract_file(processed_file, output_file, wrong_password, 1, &original_size);
    ASSERT_EQUAL(extracted_size, 0, "Extraction with wrong password should fail");

    // Extract with correct password (should succeed)
    extracted_size = extract_file(processed_file, output_file, correct_password, 1, &original_size);
    ASSERT_TRUE(extracted_size > 0, "Extraction with correct password should succeed");

    // Verify content
    ASSERT_EQUAL(compare_files(input_file, output_file), 0,
                 "Error recovery extracted file should match original");

    return TEST_PASS;
}

int run_integration_tests(void)
{
    printf("Running integration tests...\n");

    if (test_full_encrypt_decrypt_workflow() != TEST_PASS)
        return TEST_FAIL;
    if (test_full_compress_decompress_workflow() != TEST_PASS)
        return TEST_FAIL;
    if (test_full_process_extract_workflow() != TEST_PASS)
        return TEST_FAIL;
    if (test_batch_processing_workflow() != TEST_PASS)
        return TEST_FAIL;
    if (test_mixed_file_types_workflow() != TEST_PASS)
        return TEST_FAIL;
    if (test_error_recovery_workflow() != TEST_PASS)
        return TEST_FAIL;

    printf("All integration tests passed!\n\n");
    return TEST_PASS;
}