#include "test_utils.h" // Includes declarations for run_*_tests functions

int main() {
    int overall_result = 0;
    int suite_result;

    printf("=====================================\n");
    printf("      Running All Test Suites        \n");
    printf("=====================================\n");

    // Run compression tests
    suite_result = run_compression_tests();
    if (suite_result != 0) {
        overall_result = 1; // Mark overall failure if any suite fails
    }

    // Run encryption tests
    suite_result = run_encryption_tests();
    if (suite_result != 0) {
        overall_result = 1;
    }

    // Run key derivation tests
    suite_result = run_key_derivation_tests();
    if (suite_result != 0) {
        overall_result = 1;
    }

    // Run file list tests
    suite_result = run_file_list_tests();
    if (suite_result != 0) {
        overall_result = 1;
    }

    // Add calls to other test suites here if needed

    printf("\n=====================================\n");
    if (overall_result == 0) {
        printf("      All Test Suites Passed!      \n");
    } else {
        printf("      Some Test Suites FAILED!     \n");
    }
    printf("=====================================\n");

    return overall_result; // Exit with 0 on success, 1 on failure
}
