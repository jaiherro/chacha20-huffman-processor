/**
 * test_utils.h - Common test utilities and function declarations
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

// Test result macros
#define TEST_PASS 0
#define TEST_FAIL 1

// Test assertion macros
#define ASSERT_TRUE(condition, msg)                                            \
    if (!(condition))                                                          \
        {                                                                      \
            printf("    FAIL: %s\n", msg);                                     \
            return TEST_FAIL;                                                  \
        }

#define ASSERT_FALSE(condition, msg)                                           \
    if (condition)                                                             \
        {                                                                      \
            printf("    FAIL: %s\n", msg);                                     \
            return TEST_FAIL;                                                  \
        }

#define ASSERT_EQUAL(a, b, msg)                                                \
    if ((a) != (b))                                                            \
        {                                                                      \
            printf("    FAIL: %s (expected %lu, got %lu)\n", msg,              \
                   (unsigned long)(b), (unsigned long)(a));                    \
            return TEST_FAIL;                                                  \
        }

#define ASSERT_NOT_EQUAL(a, b, msg)                                            \
    if ((a) == (b))                                                            \
        {                                                                      \
            printf("    FAIL: %s (values should not be equal: %lu)\n", msg,    \
                   (unsigned long)(a));                                        \
            return TEST_FAIL;                                                  \
        }

#define ASSERT_MEM_EQUAL(a, b, len, msg)                                       \
    if (memcmp(a, b, len) != 0)                                                \
        {                                                                      \
            printf("    FAIL: %s (memory mismatch)\n", msg);                   \
            return TEST_FAIL;                                                  \
        }

#define ASSERT_MEM_NOT_EQUAL(a, b, len, msg)                                   \
    if (memcmp(a, b, len) == 0)                                                \
        {                                                                      \
            printf("    FAIL: %s (memory should not match)\n", msg);           \
            return TEST_FAIL;                                                  \
        }

#define ASSERT_NULL(ptr, msg)                                                  \
    if ((ptr) != NULL)                                                         \
        {                                                                      \
            printf("    FAIL: %s (expected NULL)\n", msg);                     \
            return TEST_FAIL;                                                  \
        }

#define ASSERT_NOT_NULL(ptr, msg)                                              \
    if ((ptr) == NULL)                                                         \
        {                                                                      \
            printf("    FAIL: %s (unexpected NULL)\n", msg);                   \
            return TEST_FAIL;                                                  \
        }

// Test utility functions
int create_test_file(const char *filename, const char *content, size_t size);
int file_exists(const char *filename);
int delete_test_file(const char *filename);
int compare_files(const char *file1, const char *file2);
void cleanup_test_files(void);

// Test suite function declarations

// Huffman compression tests
int run_huffman_tests(void);

// ChaCha20 encryption tests
int run_chacha20_tests(void);

// Key derivation tests
int run_key_derivation_tests(void);

// File list management tests
int run_file_list_tests(void);

// File operations tests
int run_file_operations_tests(void);

// Utility functions tests
int run_utils_tests(void);

// Password utility tests
int run_password_tests(void);

// Batch operations tests
int run_batch_tests(void);

// Integration tests
int run_integration_tests(void);

// Edge case tests
int run_edge_case_tests(void);

// Performance tests
int run_performance_tests(void);

#endif // TEST_UTILS_H