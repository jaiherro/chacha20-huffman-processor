/**
 * test_utils.h - Common test utilities and function declarations
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>

/* Test result macros */
#define TEST_PASS 0
#define TEST_FAIL 1

/* Test assertion macros */
#define ASSERT_TRUE(condition, msg)                                            \
    if (!(condition))                                                          \
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

#define ASSERT_MEM_EQUAL(a, b, len, msg)                                       \
    if (memcmp(a, b, len) != 0)                                                \
        {                                                                      \
            printf("    FAIL: %s (memory mismatch)\n", msg);                   \
            return TEST_FAIL;                                                  \
        }

/* Test suite function declarations */
int run_chacha20_tests(void);
int run_huffman_tests(void);
int run_key_derivation_tests(void);
int run_file_list_tests(void);

#endif /* TEST_UTILS_H */