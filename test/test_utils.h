#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <string.h> // For memcmp
#include <stdint.h> // For uint8_t
#include <stddef.h> // For size_t

// Test counters
extern int tests_run;
extern int tests_failed;

// --- Test Macros ---
#define TEST_START(name) \
    do { \
        printf("-- Test Suite: %s --\n", name); \
        tests_run = 0; \
        tests_failed = 0; \
    } while (0)

#define TEST_END(name) \
    do { \
        printf("-- End Suite: %s (%d tests run, %d failed) --\n\n", \
               name, tests_run, tests_failed); \
    } while (0)

#define RUN_TEST(test_func) \
    do { \
        printf("   Running test: %s... ", #test_func); \
        tests_run++; \
        if (test_func()) { \
            printf("PASSED\n"); \
        } else { \
            printf("FAILED\n"); \
            tests_failed++; \
        } \
    } while (0)

// --- Assertion Helpers ---

// Checks if a condition is true
static inline int check(int condition, const char *message) {
    if (!condition) {
        printf("\n      ASSERT FAILED: %s\n     ", message);
        return 0; // Failure
    }
    return 1; // Success
}

// Checks for equality between two integers
static inline int check_equal_int(long long expected, long long actual, const char *message) {
    if (expected != actual) {
        printf("\n      ASSERT FAILED: %s\n", message);
        printf("         Expected: %lld\n", expected);
        printf("         Actual:   %lld\n     ", actual);
        return 0; // Failure
    }
    return 1; // Success
}

// Checks for equality between two size_t values
static inline int check_equal_size(size_t expected, size_t actual, const char *message) {
    if (expected != actual) {
        printf("\n      ASSERT FAILED: %s\n", message);
        printf("         Expected: %zu\n", expected);
        printf("         Actual:   %zu\n     ", actual);
        return 0; // Failure
    }
    return 1; // Success
}

// Checks for non-NULL pointer
static inline int check_not_null(const void *ptr, const char *message) {
    if (ptr == NULL) {
        printf("\n      ASSERT FAILED: %s (Pointer was NULL)\n     ", message);
        return 0; // Failure
    }
    return 1; // Success
}

// Checks for NULL pointer
static inline int check_null(const void *ptr, const char *message) {
    if (ptr != NULL) {
        printf("\n      ASSERT FAILED: %s (Pointer was not NULL)\n     ", message);
        return 0; // Failure
    }
    return 1; // Success
}

// Checks if two memory buffers are equal
static inline int check_equal_mem(const void *expected, const void *actual, size_t size, const char *message) {
    if (memcmp(expected, actual, size) != 0) {
        printf("\n      ASSERT FAILED: %s (Memory differs)\n     ", message);
        // Optionally print hex diff here if needed
        return 0; // Failure
    }
    return 1; // Success
}

// Checks if two memory buffers are different
static inline int check_different_mem(const void *buf1, const void *buf2, size_t size, const char *message) {
    if (memcmp(buf1, buf2, size) == 0) {
        printf("\n      ASSERT FAILED: %s (Memory is identical)\n     ", message);
        return 0; // Failure
    }
    return 1; // Success
}


#endif // TEST_UTILS_H