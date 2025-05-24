/*
 * file_operations.h - High-level file operations
 */

#ifndef FILE_OPERATIONS_H
#define FILE_OPERATIONS_H

/* Constants */
#define DEFAULT_SALT_SIZE 16
#define DEFAULT_FILE_LIST "file_list.dat"
#define MAX_FILENAME 256
#define BUFFER_SIZE 4096

/* Add entry to file list */
int add_entry_to_file_list(const char *input_file, const char *output_file,
                           unsigned long long original_size,
                           unsigned long long processed_size,
                           int quiet);

/* Encrypt file using ChaCha20 */
unsigned long long encrypt_file(const char *input_file, const char *output_file,
                                const char *password, int quiet,
                                unsigned long long *original_size_out);

/* Decrypt file using ChaCha20 */
unsigned long long decrypt_file(const char *input_file, const char *output_file,
                                const char *password, int quiet,
                                unsigned long long *original_size_out);

/* Compress file using Huffman coding */
unsigned long long compress_file(const char *input_file, const char *output_file,
                                 int quiet, unsigned long long *original_size_out);

/* Decompress file using Huffman coding */
unsigned long long decompress_file(const char *input_file, const char *output_file,
                                   int quiet, unsigned long long *original_size_out);

/* Process file (compress then encrypt) */
unsigned long long process_file(const char *input_file, const char *output_file,
                                const char *password, int quiet,
                                unsigned long long *original_size_out);

/* Extract file (decrypt then decompress) */
unsigned long long extract_file(const char *input_file, const char *output_file,
                                const char *password, int quiet,
                                unsigned long long *original_size_out);

/* Handle file list operations */
int handle_file_list(const char *command, const char *filename_pattern,
                     int quiet);

#endif /* FILE_OPERATIONS_H */
