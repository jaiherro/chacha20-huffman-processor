/**
 * test_file_list.c - File list management tests
 */

#include "test_utils.h"
#include "utils/file_list.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int test_file_list_basic_operations(void)
{
    printf("  Testing basic file list operations...\n");

    const char *input_file = "test_input.txt";
    const char *output_file = "test_output.enc";
    unsigned long input_size = 1000;
    unsigned long output_size = 900;

    // Add entry to file list
    int result = add_entry_to_file_list(input_file, output_file, input_size, output_size, 1);
    ASSERT_EQUAL(result, 0, "Adding entry to file list should succeed");

    // Test list functionality
    result = handle_file_list("list", NULL, 1);
    ASSERT_EQUAL(result, 0, "Listing files should succeed");

    return TEST_PASS;
}

static int test_file_list_search(void)
{
    printf("  Testing file list search functionality...\n");

    const char *input_file1 = "document.txt";
    const char *output_file1 = "document.enc";
    const char *input_file2 = "report.pdf";
    const char *output_file2 = "report.enc";
    const char *input_file3 = "image.jpg";
    const char *output_file3 = "image.enc";

    // Add multiple entries
    add_entry_to_file_list(input_file1, output_file1, 500, 450, 1);
    add_entry_to_file_list(input_file2, output_file2, 2000, 1800, 1);
    add_entry_to_file_list(input_file3, output_file3, 1500, 1400, 1);

    // Test search for specific pattern
    int result = handle_file_list("find", "document", 1);
    ASSERT_EQUAL(result, 0, "Finding files by pattern should succeed");

    result = handle_file_list("find", "report", 1);
    ASSERT_EQUAL(result, 0, "Finding report files should succeed");

    result = handle_file_list("find", "nonexistent", 1);
    ASSERT_EQUAL(result, 0, "Searching for nonexistent pattern should not crash");

    return TEST_PASS;
}

static int test_file_list_multiple_entries(void)
{
    printf("  Testing file list with multiple entries...\n");

    // Add multiple entries with different characteristics
    for (int i = 0; i < 10; i++)
        {
            char input_name[64];
            char output_name[64];
            snprintf(input_name, sizeof(input_name), "test_file_%d.txt", i);
            snprintf(output_name, sizeof(output_name), "test_file_%d.enc", i);

            int result = add_entry_to_file_list(input_name, output_name, 
                                                1000 + i * 100, 900 + i * 90, 1);
            ASSERT_EQUAL(result, 0, "Adding multiple entries should succeed");
        }

    // List all entries
    int result = handle_file_list("list", NULL, 1);
    ASSERT_EQUAL(result, 0, "Listing multiple entries should succeed");

    return TEST_PASS;
}

static int test_file_list_edge_cases(void)
{
    printf("  Testing file list edge cases...\n");

    // Test with very long filenames
    const char *long_input = "very_very_very_very_very_very_very_very_long_filename_for_testing_purposes.txt";
    const char *long_output = "very_very_very_very_very_very_very_very_long_filename_for_testing_purposes.enc";

    int result = add_entry_to_file_list(long_input, long_output, 5000, 4500, 1);
    ASSERT_EQUAL(result, 0, "Adding entry with long filename should succeed");

    // Test with special characters in filenames
    const char *special_input = "file with spaces & symbols!@#.txt";
    const char *special_output = "file with spaces & symbols!@#.enc";

    result = add_entry_to_file_list(special_input, special_output, 1200, 1100, 1);
    ASSERT_EQUAL(result, 0, "Adding entry with special characters should succeed");

    // Test with zero sizes
    result = add_entry_to_file_list("empty.txt", "empty.enc", 0, 0, 1);
    ASSERT_EQUAL(result, 0, "Adding entry with zero sizes should succeed");

    return TEST_PASS;
}

static int test_file_list_null_inputs(void)
{
    printf("  Testing file list with null inputs...\n");

    // Test add_entry_to_file_list with null inputs
    int result = add_entry_to_file_list(NULL, "output.enc", 100, 90, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null input filename");

    result = add_entry_to_file_list("input.txt", NULL, 100, 90, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null output filename");

    // Test handle_file_list with null inputs
    result = handle_file_list(NULL, NULL, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should reject null operation");

    result = handle_file_list("find", NULL, 1);
    ASSERT_NOT_EQUAL(result, 0, "Find operation should reject null pattern");

    return TEST_PASS;
}

static int test_file_list_invalid_operations(void)
{
    printf("  Testing file list with invalid operations...\n");

    // Test with invalid operation
    int result = handle_file_list("invalid_operation", NULL, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should reject invalid operation");

    // Test with empty operation
    result = handle_file_list("", NULL, 1);
    ASSERT_NOT_EQUAL(result, 0, "Should reject empty operation");

    return TEST_PASS;
}

static int test_file_list_persistence(void)
{
    printf("  Testing file list persistence...\n");

    const char *test_input = "persistent_test.txt";
    const char *test_output = "persistent_test.enc";

    // Add an entry
    int result = add_entry_to_file_list(test_input, test_output, 2000, 1800, 1);
    ASSERT_EQUAL(result, 0, "Adding entry should succeed");

    // The file list should persist across calls
    result = handle_file_list("list", NULL, 1);
    ASSERT_EQUAL(result, 0, "Listing should succeed after adding entry");

    // Search for the added entry
    result = handle_file_list("find", "persistent", 1);
    ASSERT_EQUAL(result, 0, "Finding persistent entry should succeed");

    return TEST_PASS;
}

static int test_file_list_compression_ratios(void)
{
    printf("  Testing file list with various compression ratios...\n");

    // Test different compression scenarios
    struct {
        const char *name;
        unsigned long input_size;
        unsigned long output_size;
    } test_cases[] = {
        {"high_compression.txt", 10000, 2000},    // 80% compression
        {"low_compression.bin", 5000, 4800},      // 4% compression
        {"no_compression.jpg", 3000, 3100},       // Expansion (encrypted overhead)
        {"medium_compression.doc", 8000, 6000}    // 25% compression
    };

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
        {
            int result = add_entry_to_file_list(test_cases[i].name, "output.enc",
                                                test_cases[i].input_size,
                                                test_cases[i].output_size, 1);
            ASSERT_EQUAL(result, 0, "Adding compression ratio test case should succeed");
        }

    // List all entries to verify
    int result = handle_file_list("list", NULL, 1);
    ASSERT_EQUAL(result, 0, "Listing compression ratio entries should succeed");

    return TEST_PASS;
}

int run_file_list_tests(void)
{
    printf("Running file list tests...\n");

    if (test_file_list_basic_operations() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_search() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_multiple_entries() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_edge_cases() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_null_inputs() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_invalid_operations() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_persistence() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_compression_ratios() != TEST_PASS)
        return TEST_FAIL;

    printf("All file list tests passed!\n\n");
    return TEST_PASS;
}