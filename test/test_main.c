/**
 * test_main.c - Main test runner
 */

#include "test_utils.h"

int main(void)
{
    int overall_result = 0;
    int suite_result;

    printf("=====================================\n");
    printf("      Running All Test Suites        \n");
    printf("=====================================\n");

    /* Run ChaCha20 encryption tests */
    suite_result = run_chacha20_tests();
    if (suite_result != 0)
        {
            overall_result = 1;
        }

    /* Run Huffman compression tests */
    suite_result = run_huffman_tests();
    if (suite_result != 0)
        {
            overall_result = 1;
        }

    /* Run key derivation tests */
    suite_result = run_key_derivation_tests();
    if (suite_result != 0)
        {
            overall_result = 1;
        }

    /* Run file list tests */
    suite_result = run_file_list_tests();
    if (suite_result != 0)
        {
            overall_result = 1;
        }

    printf("\n=====================================\n");
    if (overall_result == 0)
        {
            printf("      All Test Suites Passed!        \n");
        }
    else
        {
            printf("      Some Test Suites FAILED!       \n");
        }
    printf("=====================================\n");

    return overall_result;
}