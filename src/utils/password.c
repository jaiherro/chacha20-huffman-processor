/**
 * password.c - Implementation of password handling utilities
 */

#include "utils/password.h"
#include <stdio.h>
#include <string.h>

int get_password(char *password, unsigned long max_len, int confirm)
{
    char confirm_password[MAX_PASSWORD];

    if (max_len == 0)
        return -1; // Cannot read into zero-length buffer

    printf("Enter password: ");
    fflush(stdout);
    if (fgets(password, (int)max_len, stdin) == NULL)
    { // fgets expects int for size
        if (feof(stdin))
        {
            fprintf(stderr, "\nERROR: End-of-file reached while reading password.\n");
        }
        else
        {
            fprintf(stderr, "\nERROR: Failed to read password input.\n");
        }
        clearerr(stdin);
        return -1;
    }
    password[strcspn(password, "\n")] = '\0';

    if (password[0] == '\0')
    {
        fprintf(stderr, "ERROR: Password cannot be empty.\n");
        return -1;
    }

    if (confirm)
    {
        printf("Confirm password: ");
        fflush(stdout);
        if (fgets(confirm_password, sizeof(confirm_password), stdin) == NULL)
        {
            if (feof(stdin))
            {
                fprintf(stderr, "\nERROR: End-of-file reached while reading password confirmation.\n");
            }
            else
            {
                fprintf(stderr, "\nERROR: Failed to read password confirmation.\n");
            }
            clearerr(stdin);
            memset(password, 0, max_len);
            return -1;
        }
        confirm_password[strcspn(confirm_password, "\n")] = '\0';

        if (strcmp(password, confirm_password) != 0)
        {
            fprintf(stderr, "ERROR: Password confirmation does not match.\n");
            memset(password, 0, max_len);
            memset(confirm_password, 0, sizeof(confirm_password));
            return -1;
        }
        memset(confirm_password, 0, sizeof(confirm_password));
    }
    return 0;
}
