/**
 * test_utils.c - Utility function tests
 */

#include "test_utils.h"
#include "utils/filesystem.h"
#include "utils/debug.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int test_filesystem_operations(void)
{
    printf("  Testing filesystem utility functions...\n");

    const char *test_file = "test_filesystem.txt";
    const char *test_content = "Filesystem test content";

    // Create test file
    ASSERT_EQUAL(create_test_file(test_file, test_content, strlen(test_content)), 0,
                 "Should create test file");

    // Test file_exists function
    ASSERT_TRUE(file_exists(test_file), "file_exists should return true for existing file");
    ASSERT_FALSE(file_exists("nonexistent_file.txt"), "file_exists should return false for nonexistent file");

    return TEST_PASS;
}

static int test_debug_system(void)
{
    printf("  Testing debug system...\n");

    // Test debug initialization
    debug_init(1, DEBUG_LEVEL_INFO);

    // Test debug messages (these should not crash)
    DEBUG_INFO("Test info message: %s", "info");
    DEBUG_ERROR("Test error message: %s", "error");
    DEBUG_TRACE("Test trace message: %s", "trace");

    // Test function entry/exit
    DEBUG_FUNCTION_ENTER("test_function");
    DEBUG_FUNCTION_EXIT("test_function", 0);

    // Test debug cleanup
    debug_init(0, DEBUG_LEVEL_NONE);

    return TEST_PASS;
}

static int test_debug_levels(void)
{
    printf("  Testing debug levels...\n");

    // Test different debug levels
    debug_init(1, DEBUG_LEVEL_ERROR);
    DEBUG_ERROR("This error should appear: %s", "error");
    DEBUG_INFO("This info should not appear: %s", "info");

    debug_init(1, DEBUG_LEVEL_INFO);
    DEBUG_ERROR("This error should appear: %s", "error");
    DEBUG_INFO("This info should appear: %s", "info");

    debug_init(1, DEBUG_LEVEL_TRACE);
    DEBUG_ERROR("This error should appear: %s", "error");
    DEBUG_INFO("This info should appear: %s", "info");
    DEBUG_TRACE("This trace should appear: %s", "trace");

    // Disable debug
    debug_init(0, DEBUG_LEVEL_NONE);

    return TEST_PASS;
}

static int test_debug_null_inputs(void)
{
    printf("  Testing debug system with null inputs...\n");

    debug_init(1, DEBUG_LEVEL_INFO);

    // These should not crash even with null inputs
    DEBUG_INFO("Test with null: %s", NULL);
    DEBUG_ERROR("Test error with null: %s", NULL);

    debug_init(0, DEBUG_LEVEL_NONE);

    return TEST_PASS;
}

int run_utils_tests(void)
{
    printf("Running utility function tests...\n");

    if (test_filesystem_operations() != TEST_PASS)
        return TEST_FAIL;
    if (test_debug_system() != TEST_PASS)
        return TEST_FAIL;
    if (test_debug_levels() != TEST_PASS)
        return TEST_FAIL;
    if (test_debug_null_inputs() != TEST_PASS)
        return TEST_FAIL;

    printf("All utility function tests passed!\n\n");
    return TEST_PASS;
}