/**
 * filesystem.h - File system utility functions
 *
 * This header provides functions for file system operations
 * like checking file existence and creating directories.
 */

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

/**
 * Check if a file exists and is readable
 *
 * @param filename Path to the file to check
 * @return 1 if file exists and is readable, 0 otherwise
 */
int file_exists(const char *filename);

/**
 * Create a directory if it doesn't exist
 *
 * @param directory Path to the directory to create
 * @return 0 on success, -1 on failure
 */
int ensure_directory_exists(const char *directory);

#endif /* FILESYSTEM_H */
