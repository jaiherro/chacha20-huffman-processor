/**
 * test_utils_functions.c - Implementation of test utility functions
 */

#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

// List of test files to clean up
static char test_files[100][256];
static int test_file_count = 0;

int create_test_file(const char *filename, const char *content, size_t size)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp)
        return -1;

    if (content && size > 0)
        {
            size_t written = fwrite(content, 1, size, fp);
            if (written != size)
                {
                    fclose(fp);
                    return -1;
                }
        }

    fclose(fp);

    // Add to cleanup list
    if (test_file_count < 100)
        {
            strncpy(test_files[test_file_count], filename, 255);
            test_files[test_file_count][255] = '\0';
            test_file_count++;
        }

    return 0;
}

int file_exists(const char *filename)
{
    struct stat st;
    return (stat(filename, &st) == 0);
}

int delete_test_file(const char *filename)
{
    return unlink(filename);
}

int compare_files(const char *file1, const char *file2)
{
    FILE *fp1 = fopen(file1, "rb");
    FILE *fp2 = fopen(file2, "rb");

    if (!fp1 || !fp2)
        {
            if (fp1)
                fclose(fp1);
            if (fp2)
                fclose(fp2);
            return -1;
        }

    int c1, c2;
    do
        {
            c1 = fgetc(fp1);
            c2 = fgetc(fp2);
        }
    while (c1 == c2 && c1 != EOF && c2 != EOF);

    fclose(fp1);
    fclose(fp2);

    return (c1 == c2) ? 0 : 1;
}

void cleanup_test_files(void)
{
    for (int i = 0; i < test_file_count; i++)
        {
            unlink(test_files[i]);
        }
    test_file_count = 0;
}