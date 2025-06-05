/**
 * test_batch.c - Batch processing tests
 */

#include "test_utils.h"
#include "operations/batch.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int test_batch_basic_processing(void)
{
    printf("  Testing basic batch processing...\n");

    // Create test files
    const char *test_files[] = {
        "batch_test1.txt",
        "batch_test2.txt"
    };
    const char *test_contents[] = {
        "Content of first batch file for testing batch processing functionality.",
        "Content of second batch file with different data to ensure proper handling."
    };
    const char *output_dir = "test_batch_output";
    const char *password = "batch_test_password";

    // Create test files
    for (int i = 0; i < 2; i++)
        {
            ASSERT_EQUAL(create_test_file(test_files[i], test_contents[i], strlen(test_contents[i])), 0,
                         "Should create batch test file");
        }

    // Create output directory
    char mkdir_cmd[256];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    system(mkdir_cmd);

    // Prepare file array
    char *file_array[2];
    file_array[0] = (char *)test_files[0];
    file_array[1] = (char *)test_files[1];

    // Test batch processing
    int result = batch_process(file_array, 2, output_dir, password, 1);
    ASSERT_EQUAL(result, 0, "Batch processing should succeed");

    // Verify output files exist
    for (int i = 0; i < 2; i++)
        {
            char expected_output[512];
            snprintf(expected_output, sizeof(expected_output), "%s/%s.secure", output_dir, test_files[i]);
            ASSERT_TRUE(file_exists(expected_output), "Batch output file should exist");
        }

    return TEST_PASS;
}

static int test_batch_empty_file_list(void)
{
    printf("  Testing batch processing with empty file list...\n");

    const char *output_dir = "test_empty_batch_output";
    const char *password = "empty_batch_password";

    // Test with zero files
    int result = batch_process(NULL, 0, output_dir, password, 1);
    ASSERT_NOT_EQUAL(result, 0, "Batch processing should fail with empty file list");

    return TEST_PASS;
}

static int test_batch_nonexistent_files(void)
{
    printf("  Testing batch processing with nonexistent files...\n");

    const char *nonexistent_files[] = {
        "does_not_exist1.txt",
        "does_not_exist2.txt"
    };
    const char *output_dir = "test_nonexistent_batch_output";
    const char *password = "nonexistent_batch_password";

    char *file_array[2];
    file_array[0] = (char *)nonexistent_files[0];
    file_array[1] = (char *)nonexistent_files[1];

    // Test batch processing with nonexistent files
    int result = batch_process(file_array, 2, output_dir, password, 1);
    ASSERT_NOT_EQUAL(result, 0, "Batch processing should fail with nonexistent files");

    return TEST_PASS;
}

static int test_batch_large_file_list(void)
{
    printf("  Testing batch processing with large file list...\n");

    const int num_files = 10;
    const char *output_dir = "test_large_batch_output";
    const char *password = "large_batch_password";
    char **file_array = malloc(num_files * sizeof(char *));
    char filenames[10][64];

    ASSERT_NOT_NULL(file_array, "Should allocate memory for file array");

    // Create multiple test files
    for (int i = 0; i < num_files; i++)
        {
            snprintf(filenames[i], sizeof(filenames[i]), "large_batch_file_%d.txt", i);
            char content[256];
            snprintf(content, sizeof(content), "Content of large batch test file number %d with unique data.", i);
            
            ASSERT_EQUAL(create_test_file(filenames[i], content, strlen(content)), 0,
                         "Should create large batch test file");
            
            file_array[i] = filenames[i];
        }

    // Create output directory
    char mkdir_cmd[256];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    system(mkdir_cmd);

    // Test batch processing
    int result = batch_process(file_array, num_files, output_dir, password, 1);
    ASSERT_EQUAL(result, 0, "Large batch processing should succeed");

    // Verify all output files exist
    for (int i = 0; i < num_files; i++)
        {
            char expected_output[512];
            snprintf(expected_output, sizeof(expected_output), "%s/%s.secure", output_dir, filenames[i]);
            ASSERT_TRUE(file_exists(expected_output), "Large batch output file should exist");
        }

    free(file_array);
    return TEST_PASS;
}

static int test_batch_mixed_file_sizes(void)
{
    printf("  Testing batch processing with mixed file sizes...\n");

    const char *output_dir = "test_mixed_batch_output";
    const char *password = "mixed_batch_password";

    // Create files of different sizes
    struct {
        const char *filename;
        size_t size;
    } test_files[] = {
        {"small_batch.txt", 50},
        {"medium_batch.txt", 1000},
        {"large_batch.txt", 10000}
    };

    char *file_array[3];

    for (int i = 0; i < 3; i++)
        {
            // Create content of specified size
            char *content = malloc(test_files[i].size + 1);
            ASSERT_NOT_NULL(content, "Should allocate memory for test content");

            for (size_t j = 0; j < test_files[i].size; j++)
                {
                    content[j] = 'A' + (j % 26);
                }
            content[test_files[i].size] = '\0';

            ASSERT_EQUAL(create_test_file(test_files[i].filename, content, test_files[i].size), 0,
                         "Should create mixed size test file");

            file_array[i] = (char *)test_files[i].filename;
            free(content);
        }

    // Create output directory
    char mkdir_cmd[256];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    system(mkdir_cmd);

    // Test batch processing
    int result = batch_process(file_array, 3, output_dir, password, 1);
    ASSERT_EQUAL(result, 0, "Mixed size batch processing should succeed");

    // Verify output files exist
    for (int i = 0; i < 3; i++)
        {
            char expected_output[512];
            snprintf(expected_output, sizeof(expected_output), "%s/%s.secure", output_dir, test_files[i].filename);
            ASSERT_TRUE(file_exists(expected_output), "Mixed size batch output file should exist");
        }

    return TEST_PASS;
}

static int test_batch_null_inputs(void)
{
    printf("  Testing batch processing with null inputs...\n");

    const char *output_dir = "test_null_batch_output";
    const char *password = "null_batch_password";
    char *file_array[1] = { "test.txt" };

    // Test null file array
    int result = batch_process(NULL, 1, output_dir, password, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null file array");

    // Test null output directory
    result = batch_process(file_array, 1, NULL, password, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null output directory");

    // Test null password
    result = batch_process(file_array, 1, output_dir, NULL, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null password");

    return TEST_PASS;
}

static int test_batch_invalid_output_directory(void)
{
    printf("  Testing batch processing with invalid output directory...\n");

    const char *test_file = "batch_invalid_dir_test.txt";
    const char *test_content = "Test content for invalid directory test";
    const char *invalid_output_dir = "/invalid/nonexistent/directory/path";
    const char *password = "invalid_dir_password";

    // Create test file
    ASSERT_EQUAL(create_test_file(test_file, test_content, strlen(test_content)), 0,
                 "Should create test file");

    char *file_array[1] = { (char *)test_file };

    // Test batch processing with invalid output directory
    int result = batch_process(file_array, 1, invalid_output_dir, password, 1);
    ASSERT_NOT_EQUAL(result, 0, "Batch processing should fail with invalid output directory");

    return TEST_PASS;
}

int run_batch_tests(void)
{
    printf("Running batch processing tests...\n");

    if (test_batch_basic_processing() != TEST_PASS)
        return TEST_FAIL;
    if (test_batch_empty_file_list() != TEST_PASS)
        return TEST_FAIL;
    if (test_batch_nonexistent_files() != TEST_PASS)
        return TEST_FAIL;
    if (test_batch_large_file_list() != TEST_PASS)
        return TEST_FAIL;
    if (test_batch_mixed_file_sizes() != TEST_PASS)
        return TEST_FAIL;
    if (test_batch_null_inputs() != TEST_PASS)
        return TEST_FAIL;
    if (test_batch_invalid_output_directory() != TEST_PASS)
        return TEST_FAIL;

    printf("All batch processing tests passed!\n\n");
    return TEST_PASS;
}