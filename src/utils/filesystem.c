/**
 * filesystem.c - Implementation of file system utility functions
 */

#include "utils/filesystem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILENAME 256

int file_exists(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (file)
    {
        fclose(file);
        return 1; // File exists and is readable
    }
    return 0; // File does not exist or cannot be opened
}

int ensure_directory_exists(const char *directory)
{
    char command[MAX_FILENAME * 2];

    if (directory == NULL || directory[0] == '\0')
    {
        fprintf(stderr, "Error: Invalid directory path provided.\n");
        return -1;
    }

    // Create directory using system command
    // Note: This is a simple approach given standard library constraints
#ifdef _WIN32
    snprintf(command, sizeof(command), "mkdir \"%s\" 2>nul", directory);
#else
    snprintf(command, sizeof(command), "mkdir -p \"%s\" 2>/dev/null", directory);
#endif
    command[sizeof(command) - 1] = '\0';

    // Execute command - ignore return value as directory may already exist
    // Let subsequent file operations handle any real failures
    system(command);

    return 0;
}
