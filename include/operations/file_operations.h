/**
 * file_operations.h - High-level file operations
 *
 * This header provides functions for compressing, decompressing,
 * encrypting, decrypting, and processing files.
 */

#ifndef FILE_OPERATIONS_H
#define FILE_OPERATIONS_H

/* Constants */
#define DEFAULT_SALT_SIZE 16              /* Default salt size in bytes */
#define DEFAULT_FILE_LIST "file_list.dat" /* Default file list filename */
#define MAX_FILENAME 256                  /* Maximum filename length */
#define BUFFER_SIZE 4096                  /* Buffer size for file processing */

/**
 * Add an entry to the file list
 *
 * @param output_file Path to the output file
 * @param original_size Original file size
 * @param processed_size Processed file size
 * @param quiet If non-zero, suppress warnings
 * @return 0 on success, -1 on failure
 */
int add_entry_to_file_list(const char *output_file, unsigned long original_size,
                           unsigned long processed_size, int quiet);

/**
 * Encrypt a file using ChaCha20
 *
 * @param input_file Path to the input file
 * @param output_file Path to the output file
 * @param password Password for encryption
 * @param quiet If non-zero, suppress output
 * @param original_size_out Pointer to store the original file size (can be NULL)
 * @return Final size of encrypted file on success, 0 on failure
 */
unsigned long encrypt_file(const char *input_file, const char *output_file,
                           const char *password, int quiet,
                           unsigned long *original_size_out);

/**
 * Decrypt a file using ChaCha20
 *
 * @param input_file Path to the input file
 * @param output_file Path to the output file
 * @param password Password for decryption
 * @param quiet If non-zero, suppress output
 * @param original_size_out Pointer to store the original file size (can be NULL)
 * @return Final size of decrypted file on success, 0 on failure
 */
unsigned long decrypt_file(const char *input_file, const char *output_file,
                           const char *password, int quiet,
                           unsigned long *original_size_out);

/**
 * Compress a file using Huffman coding
 *
 * @param input_file Path to the input file
 * @param output_file Path to the output file
 * @param quiet If non-zero, suppress output
 * @param original_size_out Pointer to store the original file size (can be NULL)
 * @return Final size of compressed file on success, 0 on failure
 */
unsigned long compress_file(const char *input_file, const char *output_file,
                            int quiet, unsigned long *original_size_out);

/**
 * Decompress a file that was compressed using Huffman coding
 *
 * @param input_file Path to the input file
 * @param output_file Path to the output file
 * @param quiet If non-zero, suppress output
 * @param original_size_out Pointer to store the original file size (can be NULL)
 * @return Final size of decompressed file on success, 0 on failure
 */
unsigned long decompress_file(const char *input_file, const char *output_file,
                              int quiet, unsigned long *original_size_out);

/**
 * Process a file (compress and encrypt)
 *
 * @param input_file Path to the input file
 * @param output_file Path to the output file
 * @param password Password for encryption
 * @param quiet If non-zero, suppress output
 * @param original_size_out Pointer to store the original file size (can be NULL)
 * @return Final size of processed file on success, 0 on failure
 */
unsigned long process_file(const char *input_file, const char *output_file,
                           const char *password, int quiet,
                           unsigned long *original_size_out);

/**
 * Extract a file (decrypt and decompress)
 *
 * @param input_file Path to the input file
 * @param output_file Path to the output file
 * @param password Password for decryption
 * @param quiet If non-zero, suppress output
 * @param original_size_out Pointer to store the original file size (can be NULL)
 * @return Final size of extracted file on success, 0 on failure
 */
unsigned long extract_file(const char *input_file, const char *output_file,
                           const char *password, int quiet,
                           unsigned long *original_size_out);

/**
 * Handle file list operations (list, find)
 *
 * @param command Command to execute ("list" or "find")
 * @param filename_pattern Pattern to search for (only for "find" command)
 * @param quiet If non-zero, suppress output
 * @return 0 on success, -1 on failure
 */
int handle_file_list(const char *command, const char *filename_pattern, int quiet);

#endif /* FILE_OPERATIONS_H */
