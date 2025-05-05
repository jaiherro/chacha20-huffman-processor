#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <string.h> // For memcmp

// Simple assertion macro
#define ASSERT_TRUE(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "Assertion failed: (%s) - %s:%d\n", message, __FILE__, __LINE__); \
            return 0; /* Indicate failure */ \
        } \
    } while (0)

#define ASSERT_FALSE(condition, message) ASSERT_TRUE(!(condition), message)
#define ASSERT_EQUAL_INT(expected, actual, message) ASSERT_TRUE((expected) == (actual), message)
#define ASSERT_NOT_EQUAL_INT(expected, actual, message) ASSERT_TRUE((expected) != (actual), message)
#define ASSERT_EQUAL_MEM(expected, actual, size, message) ASSERT_TRUE(memcmp(expected, actual, size) == 0, message)
#define ASSERT_NULL(ptr, message) ASSERT_TRUE((ptr) == NULL, message)
#define ASSERT_NOT_NULL(ptr, message) ASSERT_TRUE((ptr) != NULL, message)

// Test suite reporting
static int total_tests = 0;
static int passed_tests = 0;

#define RUN_TEST(test_func) \
    do { \
        total_tests++; \
        printf("  Running test: %s... ", #test_func); \
        fflush(stdout); \
        if (test_func()) { \
            printf("PASSED\n"); \
            passed_tests++; \
        } else { \
            printf("FAILED\n"); \
            /* Optional: exit immediately on failure */ \
            /* return 1; */ \
        } \
    } while (0)

#define START_TEST_SUITE(name) \
    printf("\n--- Running Test Suite: %s ---\n", name); \
    total_tests = 0; \
    passed_tests = 0;

#define END_TEST_SUITE() \
    printf("--- Test Suite Summary: %d / %d tests passed ---\n", passed_tests, total_tests); \
    return (passed_tests == total_tests) ? 0 : 1; /* Return 0 on success, 1 on failure */

// Function prototypes for test runners in other files
// We declare them here so test_main.c can call them.
int run_compression_tests();
int run_encryption_tests();
int run_key_derivation_tests();
int run_file_list_tests();

#endif // TEST_UTILS_H
