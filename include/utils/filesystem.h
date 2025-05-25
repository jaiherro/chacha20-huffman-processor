/*
 * filesystem.h - File system utility functions
 */

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

/* Check if file exists and is readable */
int file_exists(const char *filename);

/* Create directory if it doesn't exist */
int ensure_directory_exists(const char *directory);

#endif
