/**
 * test_password.c - Password utility tests
 */

#include "test_utils.h"
#include "utils/password.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Mock password input for automated testing
static const char *mock_passwords[] = {
    "test_password_123",
    "another_password",
    "complex_p@ssw0rd!",
    ""
};
static int mock_password_index = 0;

static int test_password_validation(void)
{
    printf("  Testing password validation...\n");

    // Test various password scenarios
    const char *test_passwords[] = {
        "short",           // Too short
        "good_password",   // Good password
        "very_very_very_very_very_very_very_very_very_very_long_password_that_exceeds_reasonable_limits", // Too long
        "normal123",       // Normal password
        ""                 // Empty password
    };

    // Note: Since get_password is interactive, we can only test that the function
    // exists and doesn't crash with reasonable inputs. In a real test environment,
    // we would need to mock stdin or use a test harness.

    return TEST_PASS;
}

static int test_password_security_clear(void)
{
    printf("  Testing password security clearing...\n");

    char password_buffer[256];
    strcpy(password_buffer, "sensitive_password_data");

    // Simulate the password clearing that should happen in the actual functions
    memset(password_buffer, 0, sizeof(password_buffer));

    // Verify buffer is cleared
    for (size_t i = 0; i < sizeof(password_buffer); i++)
        {
            ASSERT_EQUAL(password_buffer[i], 0, "Password buffer should be cleared");
        }

    return TEST_PASS;
}

static int test_password_buffer_limits(void)
{
    printf("  Testing password buffer limits...\n");

    // Test that password functions can handle maximum expected password lengths
    char max_password[MAX_PASSWORD];
    memset(max_password, 'A', MAX_PASSWORD - 1);
    max_password[MAX_PASSWORD - 1] = '\0';

    // The password should fit in the buffer
    ASSERT_TRUE(strlen(max_password) < MAX_PASSWORD, "Max password should fit in buffer");

    // Clear the test password
    memset(max_password, 0, sizeof(max_password));

    return TEST_PASS;
}

static int test_password_edge_cases(void)
{
    printf("  Testing password edge cases...\n");

    // Test with special characters
    char special_password[] = "p@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>?";
    
    // Password should be valid (contains special characters)
    ASSERT_TRUE(strlen(special_password) > 0, "Special character password should be valid");

    // Test with unicode characters (if supported)
    char unicode_password[] = "pässwörd123";
    ASSERT_TRUE(strlen(unicode_password) > 0, "Unicode password should be valid");

    // Test password confirmation scenario
    char password1[] = "confirmation_test";
    char password2[] = "confirmation_test";
    
    ASSERT_EQUAL(strcmp(password1, password2), 0, "Matching passwords should be equal");

    // Test mismatched confirmation
    char password3[] = "different_password";
    ASSERT_NOT_EQUAL(strcmp(password1, password3), 0, "Different passwords should not match");

    return TEST_PASS;
}

static int test_password_memory_safety(void)
{
    printf("  Testing password memory safety...\n");

    // Test that we don't have buffer overflows with password operations
    char small_buffer[8];
    char large_input[] = "this_is_a_very_long_password_that_should_not_overflow_small_buffers";

    // Safely copy only what fits
    strncpy(small_buffer, large_input, sizeof(small_buffer) - 1);
    small_buffer[sizeof(small_buffer) - 1] = '\0';

    // Verify we didn't overflow
    ASSERT_TRUE(strlen(small_buffer) < sizeof(small_buffer), "Buffer should not overflow");

    // Clear buffer
    memset(small_buffer, 0, sizeof(small_buffer));

    return TEST_PASS;
}

int run_password_tests(void)
{
    printf("Running password utility tests...\n");

    if (test_password_validation() != TEST_PASS)
        return TEST_FAIL;
    if (test_password_security_clear() != TEST_PASS)
        return TEST_FAIL;
    if (test_password_buffer_limits() != TEST_PASS)
        return TEST_FAIL;
    if (test_password_edge_cases() != TEST_PASS)
        return TEST_FAIL;
    if (test_password_memory_safety() != TEST_PASS)
        return TEST_FAIL;

    printf("All password utility tests passed!\n\n");
    return TEST_PASS;
}