/**
 * test_main.c - Main test runner for the comprehensive test suite
 */

#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Test suite statistics
typedef struct {
    int total_suites;
    int passed_suites;
    int failed_suites;
    clock_t start_time;
    clock_t end_time;
} test_stats;

static void print_test_header(void)
{
    printf("================================================================================\n");
    printf("                    SECURE FILE PROCESSOR - COMPREHENSIVE TEST SUITE\n");
    printf("================================================================================\n");
    printf("Testing ChaCha20 encryption, Huffman compression, and file operations\n");
    printf("Test suite includes: Unit tests, Integration tests, Edge cases, Performance\n");
    printf("================================================================================\n\n");
}

static void print_test_summary(test_stats *stats)
{
    double elapsed = ((double)(stats->end_time - stats->start_time)) / CLOCKS_PER_SEC;
    
    printf("================================================================================\n");
    printf("                                TEST SUMMARY\n");
    printf("================================================================================\n");
    printf("Total test suites: %d\n", stats->total_suites);
    printf("Passed: %d\n", stats->passed_suites);
    printf("Failed: %d\n", stats->failed_suites);
    printf("Success rate: %.1f%%\n", 
           stats->total_suites > 0 ? (double)stats->passed_suites / stats->total_suites * 100.0 : 0.0);
    printf("Total execution time: %.2f seconds\n", elapsed);
    printf("================================================================================\n");
    
    if (stats->failed_suites == 0)
        {
            printf("🎉 ALL TESTS PASSED! The secure file processor is working correctly.\n");
        }
    else
        {
            printf("❌ Some tests failed. Please review the output above for details.\n");
        }
    printf("================================================================================\n");
}

static int run_test_suite(const char *suite_name, int (*test_function)(void), test_stats *stats)
{
    printf("Starting %s...\n", suite_name);
    clock_t suite_start = clock();
    
    int result = test_function();
    
    clock_t suite_end = clock();
    double elapsed = ((double)(suite_end - suite_start)) / CLOCKS_PER_SEC;
    
    stats->total_suites++;
    if (result == TEST_PASS)
        {
            stats->passed_suites++;
            printf("✓ %s completed successfully (%.2f seconds)\n\n", suite_name, elapsed);
        }
    else
        {
            stats->failed_suites++;
            printf("✗ %s FAILED (%.2f seconds)\n\n", suite_name, elapsed);
        }
    
    return result;
}

int main(int argc, char *argv[])
{
    test_stats stats = {0};
    int overall_result = TEST_PASS;
    bool run_performance_tests = true;
    bool run_specific_suite = false;
    const char *specific_suite = NULL;

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "--no-performance") == 0)
                {
                    run_performance_tests = false;
                }
            else if (strcmp(argv[i], "--suite") == 0 && i + 1 < argc)
                {
                    run_specific_suite = true;
                    specific_suite = argv[i + 1];
                    i++; // Skip next argument
                }
            else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
                {
                    printf("Usage: %s [options]\n", argv[0]);
                    printf("Options:\n");
                    printf("  --no-performance    Skip performance tests\n");
                    printf("  --suite <name>      Run specific test suite only\n");
                    printf("                      Available suites: chacha20, huffman, key_derivation,\n");
                    printf("                      file_operations, file_list, utils, password, batch,\n");
                    printf("                      integration, edge_cases, performance\n");
                    printf("  --help, -h          Show this help message\n");
                    return 0;
                }
        }

    stats.start_time = clock();
    
    print_test_header();

    // Define test suites
    struct {
        const char *name;
        int (*function)(void);
        bool is_performance;
    } test_suites[] = {
        {"ChaCha20 Encryption Tests", run_chacha20_tests, false},
        {"Huffman Compression Tests", run_huffman_tests, false},
        {"Key Derivation Tests", run_key_derivation_tests, false},
        {"File Operations Tests", run_file_operations_tests, false},
        {"File List Management Tests", run_file_list_tests, false},
        {"Utility Function Tests", run_utils_tests, false},
        {"Password Utility Tests", run_password_tests, false},
        {"Batch Processing Tests", run_batch_tests, false},
        {"Integration Tests", run_integration_tests, false},
        {"Edge Case Tests", run_edge_case_tests, false},
        {"Performance Tests", run_performance_tests, true}
    };

    size_t num_suites = sizeof(test_suites) / sizeof(test_suites[0]);

    // Run test suites
    for (size_t i = 0; i < num_suites; i++)
        {
            // Skip performance tests if requested
            if (test_suites[i].is_performance && !run_performance_tests)
                {
                    printf("Skipping %s (performance tests disabled)\n\n", test_suites[i].name);
                    continue;
                }

            // If specific suite requested, only run that one
            if (run_specific_suite)
                {
                    bool is_requested = false;
                    if (strstr(test_suites[i].name, "ChaCha20") && strcmp(specific_suite, "chacha20") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "Huffman") && strcmp(specific_suite, "huffman") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "Key Derivation") && strcmp(specific_suite, "key_derivation") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "File Operations") && strcmp(specific_suite, "file_operations") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "File List") && strcmp(specific_suite, "file_list") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "Utility") && strcmp(specific_suite, "utils") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "Password") && strcmp(specific_suite, "password") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "Batch") && strcmp(specific_suite, "batch") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "Integration") && strcmp(specific_suite, "integration") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "Edge Case") && strcmp(specific_suite, "edge_cases") == 0)
                        is_requested = true;
                    else if (strstr(test_suites[i].name, "Performance") && strcmp(specific_suite, "performance") == 0)
                        is_requested = true;

                    if (!is_requested)
                        {
                            continue;
                        }
                }

            int result = run_test_suite(test_suites[i].name, test_suites[i].function, &stats);
            if (result != TEST_PASS)
                {
                    overall_result = TEST_FAIL;
                }
        }

    // Clean up test files
    printf("Cleaning up test files...\n");
    cleanup_test_files();
    printf("Test file cleanup completed.\n\n");

    stats.end_time = clock();
    print_test_summary(&stats);

    // Exit with appropriate code
    return (overall_result == TEST_PASS) ? EXIT_SUCCESS : EXIT_FAILURE;
}