/**
 * filesystem.c - Implementation of file system utility functions
 */

#include "utils/filesystem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Debug printing support */
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[FileSystem] " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

#define MAX_FILENAME 256

int file_exists(const char *filename)
{
    FILE *file = fopen(filename, "rb"); // Open for binary read
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

    // Simple check: try to open the directory. This is not a perfect check.
    // A more robust way involves stat() which is POSIX, or platform specific APIs.
    // For this project, relying on mkdir's behavior is simpler.
    FILE *dir_check = fopen(directory, "r");
    if (dir_check)
    {
        fclose(dir_check);
        // Directory likely exists (or it's a file, mkdir will fail then)
        return 0;
    }

#ifdef _WIN32
    snprintf(command, sizeof(command), "mkdir \"%s\"", directory);
#else // POSIX-like systems
    snprintf(command, sizeof(command), "mkdir -p \"%s\"", directory);
#endif
    command[sizeof(command) - 1] = '\0'; // Ensure null termination

    int status = system(command);

    if (status != 0)
    {
        // system() return value is complex. mkdir -p returns 0 if dir exists or created.
        // On Windows, mkdir returns 0 on success.
        // A non-zero status might indicate a real error (e.g., permission denied).
        // We can't be certain without more checks, so we'll proceed and let fopen fail later if needed.
        DEBUG_PRINT("system(\"%s\") returned status %d. Directory might not have been created if it didn't exist or error occurred.\n", command, status);
    }
    return 0; // Assume success or directory already exists/will be handled by fopen
}
