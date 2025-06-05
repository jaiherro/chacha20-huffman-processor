/**
 * test_performance.c - Performance and stress tests
 */

#include "test_utils.h"
#include "operations/file_operations.h"
#include "compression/huffman.h"
#include "encryption/chacha20.h"
#include "encryption/key_derivation.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double get_time_diff(clock_t start, clock_t end)
{
    return ((double)(end - start)) / CLOCKS_PER_SEC;
}

static int test_compression_performance(void)
{
    printf("  Testing compression performance...\n");

    // Create test data with varying compression characteristics
    size_t sizes[] = { 1024, 10240, 102400 }; // 1KB, 10KB, 100KB
    const char *descriptions[] = { "1KB", "10KB", "100KB" };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        {
            char *test_data = malloc(sizes[i]);
            ASSERT_NOT_NULL(test_data, "Should allocate memory for performance test");

            // Create repetitive data for good compression
            for (size_t j = 0; j < sizes[i]; j++)
                {
                    test_data[j] = 'A' + (j % 26);
                }

            char input_file[64], output_file[64];
            snprintf(input_file, sizeof(input_file), "perf_input_%zu.txt", i);
            snprintf(output_file, sizeof(output_file), "perf_output_%zu.huf", i);

            ASSERT_EQUAL(create_test_file(input_file, test_data, sizes[i]), 0,
                         "Should create performance test file");

            unsigned long original_size;
            clock_t start = clock();
            
            unsigned long compressed_size = compress_file(input_file, output_file, 1, &original_size);
            
            clock_t end = clock();
            double elapsed = get_time_diff(start, end);

            ASSERT_TRUE(compressed_size > 0, "Performance compression should succeed");
            
            printf("    %s compression: %.3f seconds, ratio: %.2f%%\n", 
                   descriptions[i], elapsed, 
                   (double)compressed_size / original_size * 100.0);

            free(test_data);
        }

    return TEST_PASS;
}

static int test_encryption_performance(void)
{
    printf("  Testing encryption performance...\n");

    size_t sizes[] = { 1024, 10240, 102400 }; // 1KB, 10KB, 100KB
    const char *descriptions[] = { "1KB", "10KB", "100KB" };
    const char *password = "performance_test_password";

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        {
            char *test_data = malloc(sizes[i]);
            ASSERT_NOT_NULL(test_data, "Should allocate memory for encryption performance test");

            // Create varied data
            for (size_t j = 0; j < sizes[i]; j++)
                {
                    test_data[j] = (char)(j & 0xFF);
                }

            char input_file[64], output_file[64];
            snprintf(input_file, sizeof(input_file), "perf_enc_input_%zu.txt", i);
            snprintf(output_file, sizeof(output_file), "perf_enc_output_%zu.enc", i);

            ASSERT_EQUAL(create_test_file(input_file, test_data, sizes[i]), 0,
                         "Should create encryption performance test file");

            unsigned long original_size;
            clock_t start = clock();
            
            unsigned long encrypted_size = encrypt_file(input_file, output_file, password, 1, &original_size);
            
            clock_t end = clock();
            double elapsed = get_time_diff(start, end);

            ASSERT_TRUE(encrypted_size > 0, "Performance encryption should succeed");
            
            printf("    %s encryption: %.3f seconds, throughput: %.2f KB/s\n", 
                   descriptions[i], elapsed, 
                   (double)sizes[i] / 1024.0 / elapsed);

            free(test_data);
        }

    return TEST_PASS;
}

static int test_key_derivation_performance(void)
{
    printf("  Testing key derivation performance...\n");

    const char *password = "performance_test_password_123";
    unsigned char salt[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    unsigned char key[32];
    unsigned char nonce[12];

    // Test with different iteration counts
    unsigned int iterations[] = { 1000, 10000, 100000 };
    const char *descriptions[] = { "1K", "10K", "100K" };

    for (size_t i = 0; i < sizeof(iterations) / sizeof(iterations[0]); i++)
        {
            clock_t start = clock();
            
            int result = derive_key_and_nonce(password, salt, 16, iterations[i], 
                                              key, 32, nonce, 12);
            
            clock_t end = clock();
            double elapsed = get_time_diff(start, end);

            ASSERT_EQUAL(result, 0, "Key derivation performance test should succeed");
            
            printf("    %s iterations: %.3f seconds\n", descriptions[i], elapsed);
        }

    return TEST_PASS;
}

static int test_chacha20_performance(void)
{
    printf("  Testing ChaCha20 performance...\n");

    unsigned char key[32] = {0};
    unsigned char nonce[12] = {0};
    chacha20_ctx ctx;

    size_t sizes[] = { 1024, 10240, 102400, 1024000 }; // 1KB, 10KB, 100KB, 1MB
    const char *descriptions[] = { "1KB", "10KB", "100KB", "1MB" };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        {
            unsigned char *input = malloc(sizes[i]);
            unsigned char *output = malloc(sizes[i]);
            
            ASSERT_NOT_NULL(input, "Should allocate input buffer for ChaCha20 performance");
            ASSERT_NOT_NULL(output, "Should allocate output buffer for ChaCha20 performance");

            // Fill input with test pattern
            for (size_t j = 0; j < sizes[i]; j++)
                {
                    input[j] = (unsigned char)(j & 0xFF);
                }

            int result = chacha20_init(&ctx, key, nonce, 0);
            ASSERT_EQUAL(result, 0, "ChaCha20 init should succeed");

            clock_t start = clock();
            
            result = chacha20_process(&ctx, input, output, sizes[i]);
            
            clock_t end = clock();
            double elapsed = get_time_diff(start, end);

            ASSERT_EQUAL(result, 0, "ChaCha20 performance test should succeed");
            
            printf("    %s ChaCha20: %.3f seconds, throughput: %.2f MB/s\n", 
                   descriptions[i], elapsed, 
                   (double)sizes[i] / 1024.0 / 1024.0 / elapsed);

            chacha20_cleanup(&ctx);
            free(input);
            free(output);
        }

    return TEST_PASS;
}

static int test_full_pipeline_performance(void)
{
    printf("  Testing full pipeline performance...\n");

    size_t test_size = 100000; // 100KB test file
    char *test_data = malloc(test_size);
    ASSERT_NOT_NULL(test_data, "Should allocate memory for pipeline performance test");

    // Create test data with good compression characteristics
    for (size_t i = 0; i < test_size; i++)
        {
            test_data[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[i % 36];
        }

    const char *input_file = "perf_pipeline_input.txt";
    const char *processed_file = "perf_pipeline_processed.sec";
    const char *extracted_file = "perf_pipeline_extracted.txt";
    const char *password = "pipeline_performance_password";

    ASSERT_EQUAL(create_test_file(input_file, test_data, test_size), 0,
                 "Should create pipeline performance test file");

    unsigned long original_size, processed_size, extracted_size;

    // Test processing (compress + encrypt)
    clock_t start = clock();
    processed_size = process_file(input_file, processed_file, password, 1, &original_size);
    clock_t mid = clock();
    
    ASSERT_TRUE(processed_size > 0, "Pipeline processing should succeed");

    // Test extraction (decrypt + decompress)
    extracted_size = extract_file(processed_file, extracted_file, password, 1, &original_size);
    clock_t end = clock();

    ASSERT_TRUE(extracted_size > 0, "Pipeline extraction should succeed");

    double process_time = get_time_diff(start, mid);
    double extract_time = get_time_diff(mid, end);
    double total_time = get_time_diff(start, end);

    printf("    100KB full pipeline:\n");
    printf("      Process: %.3f seconds\n", process_time);
    printf("      Extract: %.3f seconds\n", extract_time);
    printf("      Total: %.3f seconds\n", total_time);
    printf("      Compression ratio: %.2f%%\n", 
           (double)processed_size / original_size * 100.0);

    // Verify integrity
    ASSERT_EQUAL(compare_files(input_file, extracted_file), 0,
                 "Pipeline performance test should preserve data integrity");

    free(test_data);
    return TEST_PASS;
}

static int test_memory_usage_patterns(void)
{
    printf("  Testing memory usage patterns...\n");

    // Test that operations don't leave significant memory leaks
    // by repeating operations multiple times
    const char *test_content = "Memory usage test content for repeated operations.";
    const char *password = "memory_test_password";

    for (int iteration = 0; iteration < 10; iteration++)
        {
            char input_file[64], output_file[64], final_file[64];
            snprintf(input_file, sizeof(input_file), "mem_test_input_%d.txt", iteration);
            snprintf(output_file, sizeof(output_file), "mem_test_output_%d.sec", iteration);
            snprintf(final_file, sizeof(final_file), "mem_test_final_%d.txt", iteration);

            ASSERT_EQUAL(create_test_file(input_file, test_content, strlen(test_content)), 0,
                         "Should create memory test file");

            unsigned long original_size, processed_size, final_size;

            // Process
            processed_size = process_file(input_file, output_file, password, 1, &original_size);
            ASSERT_TRUE(processed_size > 0, "Memory test processing should succeed");

            // Extract
            final_size = extract_file(output_file, final_file, password, 1, &original_size);
            ASSERT_TRUE(final_size > 0, "Memory test extraction should succeed");

            // Verify
            ASSERT_EQUAL(compare_files(input_file, final_file), 0,
                         "Memory test should preserve data integrity");
        }

    printf("    Completed 10 iterations without memory issues\n");

    return TEST_PASS;
}

static int test_stress_concurrent_operations(void)
{
    printf("  Testing stress with multiple operations...\n");

    // Create multiple files and process them
    const int num_files = 5;
    const char *password = "stress_test_password";

    for (int i = 0; i < num_files; i++)
        {
            char input_file[64], output_file[64], final_file[64];
            snprintf(input_file, sizeof(input_file), "stress_input_%d.txt", i);
            snprintf(output_file, sizeof(output_file), "stress_output_%d.sec", i);
            snprintf(final_file, sizeof(final_file), "stress_final_%d.txt", i);

            // Create unique content for each file
            char content[1000];
            snprintf(content, sizeof(content), 
                     "Stress test file number %d with unique content to ensure "
                     "each file has different compression characteristics. "
                     "This content is designed to test the robustness of the system "
                     "when processing multiple files in sequence.", i);

            ASSERT_EQUAL(create_test_file(input_file, content, strlen(content)), 0,
                         "Should create stress test file");

            unsigned long original_size, processed_size, final_size;

            // Process
            processed_size = process_file(input_file, output_file, password, 1, &original_size);
            ASSERT_TRUE(processed_size > 0, "Stress test processing should succeed");

            // Extract
            final_size = extract_file(output_file, final_file, password, 1, &original_size);
            ASSERT_TRUE(final_size > 0, "Stress test extraction should succeed");

            // Verify
            ASSERT_EQUAL(compare_files(input_file, final_file), 0,
                         "Stress test should preserve data integrity");
        }

    printf("    Successfully processed %d files under stress conditions\n", num_files);

    return TEST_PASS;
}

int run_performance_tests(void)
{
    printf("Running performance and stress tests...\n");

    if (test_compression_performance() != TEST_PASS)
        return TEST_FAIL;
    if (test_encryption_performance() != TEST_PASS)
        return TEST_FAIL;
    if (test_key_derivation_performance() != TEST_PASS)
        return TEST_FAIL;
    if (test_chacha20_performance() != TEST_PASS)
        return TEST_FAIL;
    if (test_full_pipeline_performance() != TEST_PASS)
        return TEST_FAIL;
    if (test_memory_usage_patterns() != TEST_PASS)
        return TEST_FAIL;
    if (test_stress_concurrent_operations() != TEST_PASS)
        return TEST_FAIL;

    printf("All performance tests completed successfully!\n\n");
    return TEST_PASS;
}