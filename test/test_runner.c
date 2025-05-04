#include "test_utils.h"
#include <time.h>   // For time()
#include <stdlib.h> // For srand()

// Declare test suite functions from other files
extern void run_huffman_tests();
extern void run_chacha20_tests();
extern void run_key_derivation_tests();
extern void run_file_list_tests();

// Global test counters
int tests_run = 0;
int tests_failed = 0;

int main() {
    // Seed random number generator (useful for tests involving randomness)
    srand((unsigned int)time(NULL));

    printf("=== Running Unit Tests ===\n\n");

    int total_run = 0;
    int total_failed = 0;

    // Run test suites
    run_huffman_tests();
    total_run += tests_run;
    total_failed += tests_failed;

    run_chacha20_tests();
    total_run += tests_run;
    total_failed += tests_failed;

    run_key_derivation_tests();
    total_run += tests_run;
    total_failed += tests_failed;

    run_file_list_tests();
    total_run += tests_run;
    total_failed += tests_failed;


    printf("=== Test Summary ===\n");
    printf("Total Tests Run:    %d\n", total_run);
    printf("Total Tests Passed: %d\n", total_run - total_failed);
    printf("Total Tests Failed: %d\n", total_failed);
    printf("====================\n");

    return (total_failed == 0) ? 0 : 1; // Return 0 on success, 1 on failure
}