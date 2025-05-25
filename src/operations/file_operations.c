/**
 * file_operations.c - Implementation of high-level file operations
 *
 * Built by: Ethan Hall and Jai Herro
 *
 */

#include "operations/file_operations.h"
#include "compression/huffman.h"
#include "encryption/chacha20.h"
#include "encryption/key_derivation.h"
#include "utils/debug.h"
#include "utils/file_list.h"
#include "utils/ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Constants */
#define KEY_DERIVATION_ITERATIONS 100000
#define MIN_ENCRYPTED_FILE_SIZE (DEFAULT_SALT_SIZE + 1)
#define MIN_COMPRESSED_FILE_SIZE (sizeof (unsigned long) + 1)
#define ENCRYPTION_MAGIC "SFPv1"
#define ENCRYPTION_MAGIC_LEN 5
#define TEMP_FILE_SUFFIX_COMPRESS ".tmp_compress"
#define TEMP_FILE_SUFFIX_DECRYPT ".tmp_decrypt"
#define WRITE_CHUNK_SIZE BUFFER_SIZE

/* Error codes for internal functions */
typedef enum
{
    FILE_OP_SUCCESS = 0,
    FILE_OP_ERROR_OPEN_INPUT = -1,
    FILE_OP_ERROR_OPEN_OUTPUT = -2,
    FILE_OP_ERROR_FILE_SIZE = -3,
    FILE_OP_ERROR_MEMORY = -4,
    FILE_OP_ERROR_READ = -5,
    FILE_OP_ERROR_WRITE = -6,
    FILE_OP_ERROR_CRYPTO = -7,
    FILE_OP_ERROR_COMPRESSION = -8,
    FILE_OP_ERROR_VALIDATION = -9
} file_op_result_t;

/* Structure for managing crypto operations */
typedef struct
{
    unsigned char *input_buffer;
    unsigned char *output_buffer;
    chacha20_ctx *crypto_ctx;
    FILE *input_file;
    FILE *output_file;
    unsigned char key[CHACHA20_KEY_SIZE];
    unsigned char nonce[CHACHA20_NONCE_SIZE];
    unsigned char salt[DEFAULT_SALT_SIZE];
} crypto_operation_t;

/* Helper function prototypes */
static int validate_input_params (const char *input_file,
                                  const char *output_file);
static int get_file_size (FILE *file, unsigned long *size);
static FILE *open_input_file (const char *filename);
static FILE *open_output_file (const char *filename);
static int allocate_crypto_buffers (crypto_operation_t *op);
static void cleanup_crypto_operation (crypto_operation_t *op,
                                      const char *output_file, int failed);
static void secure_cleanup_crypto_keys (crypto_operation_t *op);
static int init_crypto_context (crypto_operation_t *op, const char *password);
static int verify_magic_header (crypto_operation_t *op);
static int write_magic_header (crypto_operation_t *op);
static unsigned long process_crypto_chunks (crypto_operation_t *op,
                                            unsigned long data_size, int quiet,
                                            int encrypt);
static int create_temp_filename (char *temp_file, size_t size,
                                 const char *output_file, const char *suffix);

/* Input validation helper */
static int
validate_input_params (const char *input_file, const char *output_file)
{
    if (!input_file || strlen (input_file) == 0)
        {
            fprintf (stderr, "ERROR: Input filename is null or empty.\n");
            DEBUG_ERROR_MSG ("Input filename validation failed");
            return FILE_OP_ERROR_VALIDATION;
        }

    if (!output_file || strlen (output_file) == 0)
        {
            fprintf (stderr, "ERROR: Output filename is null or empty.\n");
            DEBUG_ERROR_MSG ("Output filename validation failed");
            return FILE_OP_ERROR_VALIDATION;
        }

    if (strcmp (input_file, output_file) == 0)
        {
            fprintf (stderr,
                     "ERROR: Input and output files cannot be the same.\n");
            DEBUG_ERROR_MSG ("Input and output files are identical");
            return FILE_OP_ERROR_VALIDATION;
        }

    return FILE_OP_SUCCESS;
}

/* File operation helpers */
static int
get_file_size (FILE *file, unsigned long *size)
{
    DEBUG_TRACE_MSG ("Getting file size");

    if (fseek (file, 0, SEEK_END) != 0)
        {
            DEBUG_ERROR_MSG ("Failed to seek to end of file");
            return FILE_OP_ERROR_FILE_SIZE;
        }

    *size = ftell (file);

    if (fseek (file, 0, SEEK_SET) != 0)
        {
            DEBUG_ERROR_MSG ("Failed to seek back to start of file");
            return FILE_OP_ERROR_FILE_SIZE;
        }

    DEBUG_TRACE ("File size determined: %lu bytes", *size);
    return FILE_OP_SUCCESS;
}

static FILE *
open_input_file (const char *filename)
{
    FILE *file = fopen (filename, "rb");
    if (!file)
        {
            fprintf (stderr,
                     "ERROR: Cannot open input file '%s' for reading.\n",
                     filename);
            DEBUG_ERROR ("Failed to open input file: '%s'", filename);
            return NULL;
        }
    DEBUG_TRACE ("Input file opened successfully: '%s'", filename);
    return file;
}

static FILE *
open_output_file (const char *filename)
{
    FILE *file = fopen (filename, "wb");
    if (!file)
        {
            fprintf (stderr,
                     "ERROR: Cannot open output file '%s' for writing.\n",
                     filename);
            DEBUG_ERROR ("Failed to open output file: '%s'", filename);
            return NULL;
        }
    DEBUG_TRACE ("Output file opened successfully: '%s'", filename);
    return file;
}

/* Buffer management helpers */
static int
allocate_crypto_buffers (crypto_operation_t *op)
{
    op->input_buffer = malloc (BUFFER_SIZE);
    op->output_buffer = malloc (BUFFER_SIZE);

    if (!op->input_buffer || !op->output_buffer)
        {
            fprintf (stderr,
                     "ERROR: Memory allocation failed for crypto buffers.\n");
            DEBUG_ERROR_MSG ("Crypto buffer allocation failed");

            if (op->input_buffer)
                {
                    memset (op->input_buffer, 0, BUFFER_SIZE);
                    free (op->input_buffer);
                    op->input_buffer = NULL;
                }
            if (op->output_buffer)
                {
                    memset (op->output_buffer, 0, BUFFER_SIZE);
                    free (op->output_buffer);
                    op->output_buffer = NULL;
                }
            return FILE_OP_ERROR_MEMORY;
        }
    DEBUG_TRACE_MSG ("Crypto buffers allocated successfully");
    return FILE_OP_SUCCESS;
}

/* Cleanup helpers */
static void
cleanup_crypto_operation (crypto_operation_t *op, const char *output_file,
                          int failed)
{
    DEBUG_TRACE ("Cleaning up crypto operation - failed: %s",
                 failed ? "yes" : "no");

    if (op->input_file)
        {
            fclose (op->input_file);
            op->input_file = NULL;
        }

    if (op->output_file)
        {
            fclose (op->output_file);
            op->output_file = NULL;
        }

    if (op->input_buffer)
        {
            memset (op->input_buffer, 0, BUFFER_SIZE);
            free (op->input_buffer);
            op->input_buffer = NULL;
        }

    if (op->output_buffer)
        {
            memset (op->output_buffer, 0, BUFFER_SIZE);
            free (op->output_buffer);
            op->output_buffer = NULL;
        }

    if (op->crypto_ctx)
        {
            chacha20_cleanup (op->crypto_ctx);
            op->crypto_ctx = NULL;
        }

    if (failed && output_file)
        {
            DEBUG_TRACE ("Removing failed output file: '%s'", output_file);
            if (remove (output_file) != 0)
                {
                    DEBUG_ERROR ("Failed to remove output file: '%s'",
                                 output_file);
                }
            else
                {
                    DEBUG_TRACE_MSG ("Failed output file removed successfully");
                }
        }
}

static void
secure_cleanup_crypto_keys (crypto_operation_t *op)
{
    memset (op->key, 0, CHACHA20_KEY_SIZE);
    memset (op->nonce, 0, CHACHA20_NONCE_SIZE);
    memset (op->salt, 0, DEFAULT_SALT_SIZE);
    DEBUG_TRACE_MSG ("Crypto keys securely cleared");
}

/* Crypto operation helpers */
static int
init_crypto_context (crypto_operation_t *op, const char *password)
{
    // Generate salt for encryption, read for decryption
    if (generate_salt (op->salt, DEFAULT_SALT_SIZE) != 0)
        {
            fprintf (stderr, "ERROR: Failed to generate salt.\n");
            DEBUG_ERROR_MSG ("Salt generation failed");
            return FILE_OP_ERROR_CRYPTO;
        }
    DEBUG_TRACE_MSG ("Salt generated successfully");

    // Derive key and nonce
    if (derive_key_and_nonce (password, op->salt, DEFAULT_SALT_SIZE,
                              KEY_DERIVATION_ITERATIONS, op->key,
                              CHACHA20_KEY_SIZE, op->nonce, CHACHA20_NONCE_SIZE)
        != 0)
        {
            fprintf (stderr,
                     "ERROR: Failed to derive key and nonce from password.\n");
            DEBUG_ERROR_MSG ("Key derivation failed");
            return FILE_OP_ERROR_CRYPTO;
        }
    DEBUG_TRACE_MSG ("Key and nonce derived successfully");

    // Initialise ChaCha20
    if (chacha20_init (op->crypto_ctx, op->key, op->nonce, 1) != 0)
        {
            fprintf (stderr, "ERROR: Failed to initialise ChaCha20 context.\n");
            DEBUG_ERROR_MSG ("ChaCha20 initialisation failed");
            return FILE_OP_ERROR_CRYPTO;
        }
    DEBUG_TRACE_MSG ("ChaCha20 context initialised successfully");

    return FILE_OP_SUCCESS;
}

static int
write_magic_header (crypto_operation_t *op)
{
    unsigned char magic_plain[ENCRYPTION_MAGIC_LEN] = ENCRYPTION_MAGIC;
    unsigned char magic_cipher[ENCRYPTION_MAGIC_LEN];

    if (chacha20_process (op->crypto_ctx, magic_plain, magic_cipher,
                          ENCRYPTION_MAGIC_LEN)
        != 0)
        {
            fprintf (stderr, "ERROR: Failed to encrypt magic header.\n");
            DEBUG_ERROR_MSG ("Failed to encrypt magic header");
            return FILE_OP_ERROR_CRYPTO;
        }

    if (fwrite (magic_cipher, 1, ENCRYPTION_MAGIC_LEN, op->output_file)
        != ENCRYPTION_MAGIC_LEN)
        {
            fprintf (stderr,
                     "ERROR: Failed to write magic header to output file.\n");
            DEBUG_ERROR_MSG ("Failed to write magic header");
            return FILE_OP_ERROR_WRITE;
        }

    DEBUG_TRACE_MSG ("Magic header encrypted and written");
    return FILE_OP_SUCCESS;
}

static int
verify_magic_header (crypto_operation_t *op)
{
    unsigned char magic_cipher[ENCRYPTION_MAGIC_LEN];
    unsigned char magic_plain[ENCRYPTION_MAGIC_LEN];

    if (fread (magic_cipher, 1, ENCRYPTION_MAGIC_LEN, op->input_file)
        != ENCRYPTION_MAGIC_LEN)
        {
            fprintf (stderr,
                     "ERROR: Failed to read magic header from input file.\n");
            DEBUG_ERROR_MSG ("Failed to read magic header");
            return FILE_OP_ERROR_READ;
        }

    if (chacha20_process (op->crypto_ctx, magic_cipher, magic_plain,
                          ENCRYPTION_MAGIC_LEN)
        != 0)
        {
            fprintf (stderr, "ERROR: Failed to decrypt magic header.\n");
            DEBUG_ERROR_MSG ("Magic header decryption failed");
            return FILE_OP_ERROR_CRYPTO;
        }

    if (memcmp (magic_plain, ENCRYPTION_MAGIC, ENCRYPTION_MAGIC_LEN) != 0)
        {
            fprintf (stderr, "ERROR: Incorrect password or corrupted file.\n");
            DEBUG_ERROR_MSG ("Magic header verification failed - incorrect "
                             "password or corrupted file");
            return FILE_OP_ERROR_VALIDATION;
        }

    DEBUG_TRACE_MSG ("Magic header verified successfully");
    return FILE_OP_SUCCESS;
}

/* Process crypto data in chunks */
static unsigned long
process_crypto_chunks (crypto_operation_t *op, unsigned long data_size,
                       int quiet, int encrypt)
{
    unsigned long processed_size = 0;
    unsigned long read_size;
    const char *operation = encrypt ? "Encrypting" : "Decrypting";

    if (!quiet)
        {
            printf ("\n%s file...\n", operation);
            print_progress_bar (0, data_size, PROGRESS_WIDTH);
        }
    DEBUG_INFO ("Starting %s loop for %lu bytes", operation, data_size);

    while (processed_size < data_size)
        {
            unsigned long chunk_size
                = (data_size - processed_size < BUFFER_SIZE)
                      ? data_size - processed_size
                      : BUFFER_SIZE;

            DEBUG_TRACE ("Processing chunk: %lu bytes (progress: %lu/%lu)",
                         chunk_size, processed_size, data_size);

            read_size = fread (op->input_buffer, 1, chunk_size, op->input_file);
            if (read_size == 0)
                {
                    if (feof (op->input_file) && processed_size < data_size)
                        {
                            fprintf (stderr, "\nERROR: Unexpected end of file "
                                             "while reading data.\n");
                            DEBUG_ERROR ("Unexpected EOF at position %lu/%lu",
                                         processed_size, data_size);
                        }
                    else if (ferror (op->input_file))
                        {
                            fprintf (stderr,
                                     "\nERROR: File read error during %s.\n",
                                     operation);
                            DEBUG_ERROR_MSG (
                                "File read error during processing");
                        }
                    return 0;
                }

            if (chacha20_process (op->crypto_ctx, op->input_buffer,
                                  op->output_buffer, read_size)
                != 0)
                {
                    fprintf (stderr,
                             "\nERROR: ChaCha20 %s failed during processing.\n",
                             operation);
                    DEBUG_ERROR_MSG ("ChaCha20 processing failed for chunk");
                    return 0;
                }

            if (fwrite (op->output_buffer, 1, read_size, op->output_file)
                != read_size)
                {
                    fprintf (
                        stderr,
                        "\nERROR: Failed to write %s data to output file.\n",
                        encrypt ? "encrypted" : "decrypted");
                    DEBUG_ERROR_MSG ("Failed to write processed data");
                    return 0;
                }

            processed_size += read_size;
            if (!quiet)
                {
                    print_progress_bar (processed_size, data_size,
                                        PROGRESS_WIDTH);
                }
        }
    DEBUG_INFO ("%s loop completed, processed %lu bytes", operation,
                processed_size);
    return processed_size;
}

/* Create temporary filename helper */
static int
create_temp_filename (char *temp_file, size_t size, const char *output_file,
                      const char *suffix)
{
    int result = snprintf (temp_file, size, "%s%s", output_file, suffix);
    if (result >= (int)size || result < 0)
        {
            fprintf (stderr, "ERROR: Temporary filename too long.\n");
            DEBUG_ERROR_MSG ("Temporary filename creation failed");
            return FILE_OP_ERROR_VALIDATION;
        }
    temp_file[size - 1] = '\0';
    DEBUG_TRACE ("Temporary filename created: '%s'", temp_file);
    return FILE_OP_SUCCESS;
}

/* Main operation functions */
int
add_entry_to_file_list (const char *input_file, const char *output_file,
                        unsigned long original_size,
                        unsigned long processed_size, int quiet)
{
    file_list_t file_list;

    DEBUG_FUNCTION_ENTER ("add_entry_to_file_list");
    DEBUG_INFO ("Adding entry to file list - input: '%s', output: '%s', "
                "original: %lu, processed: %lu, quiet: %s",
                input_file, output_file, original_size, processed_size,
                quiet ? "yes" : "no");

    if (validate_input_params (input_file, output_file) != FILE_OP_SUCCESS)
        {
            DEBUG_FUNCTION_EXIT ("add_entry_to_file_list", -1);
            return -1;
        }

    file_list_init (&file_list);
    DEBUG_TRACE_MSG ("File list structure initialised");

    if (file_list_load (&file_list, DEFAULT_FILE_LIST) != 0)
        {
            DEBUG_INFO_MSG (
                "Failed to load existing file list, creating new one");
            file_list_free (&file_list);
            file_list_init (&file_list);
        }
    else
        {
            DEBUG_TRACE ("Existing file list loaded from: '%s'",
                         DEFAULT_FILE_LIST);
        }

    if (file_list_add (&file_list, input_file, output_file, original_size,
                       processed_size)
        != 0)
        {
            if (!quiet)
                {
                    fprintf (stderr,
                             "Warning: Failed to add entry '%s -> %s' to file "
                             "list structure in memory.\n",
                             input_file, output_file);
                }
            DEBUG_ERROR (
                "Failed to add entry to file list in memory: '%s' -> '%s'",
                input_file, output_file);
            file_list_free (&file_list);
            DEBUG_FUNCTION_EXIT ("add_entry_to_file_list", -1);
            return -1;
        }
    DEBUG_TRACE_MSG ("Entry added to file list structure in memory");

    if (file_list_save (&file_list, DEFAULT_FILE_LIST) != 0)
        {
            if (!quiet)
                {
                    fprintf (
                        stderr,
                        "Warning: Failed to save updated file list to %s\n",
                        DEFAULT_FILE_LIST);
                }
            DEBUG_ERROR ("Failed to save file list to: '%s'",
                         DEFAULT_FILE_LIST);
            file_list_free (&file_list);
            DEBUG_FUNCTION_EXIT ("add_entry_to_file_list", -1);
            return -1;
        }
    DEBUG_TRACE ("File list saved successfully to: '%s'", DEFAULT_FILE_LIST);

    file_list_free (&file_list);
    DEBUG_TRACE_MSG ("File list structure cleaned up");
    DEBUG_FUNCTION_EXIT ("add_entry_to_file_list", 0);
    return 0;
}

unsigned long
encrypt_file (const char *input_file, const char *output_file,
              const char *password, int quiet, unsigned long *original_size_out)
{
    crypto_operation_t op = { 0 };
    chacha20_ctx ctx;
    unsigned long original_size = 0, final_output_size = 0;

    DEBUG_FUNCTION_ENTER ("encrypt_file");
    DEBUG_INFO ("Encrypting file - input: '%s', output: '%s', quiet: %s",
                input_file, output_file, quiet ? "yes" : "no");

    if (validate_input_params (input_file, output_file) != FILE_OP_SUCCESS
        || !password || strlen (password) == 0)
        {
            if (!password || strlen (password) == 0)
                {
                    fprintf (stderr, "ERROR: Password cannot be empty.\n");
                    DEBUG_ERROR_MSG ("Empty password provided");
                }
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }

    if (!quiet)
        {
            print_section_header ("File Encryption");
            printf ("Input file:  %s\n", input_file);
            printf ("Output file: %s\n", output_file);
            printf ("Encryption:  ChaCha20 (256-bit)\n");
        }

    // Open files
    op.input_file = open_input_file (input_file);
    if (!op.input_file)
        {
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }

    if (get_file_size (op.input_file, &original_size) != FILE_OP_SUCCESS)
        {
            fprintf (stderr,
                     "ERROR: Could not determine size of input file '%s'.\n",
                     input_file);
            DEBUG_ERROR ("Failed to get file size for: '%s'", input_file);
            fclose (op.input_file);
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }
    DEBUG_INFO ("Input file size: %lu bytes", original_size);

    if (original_size_out)
        *original_size_out = original_size;

    op.output_file = open_output_file (output_file);
    if (!op.output_file)
        {
            fclose (op.input_file);
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }

    // Set up crypto context
    op.crypto_ctx = &ctx;
    if (init_crypto_context (&op, password) != FILE_OP_SUCCESS)
        {
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }

    // Write salt to output file
    if (fwrite (op.salt, 1, DEFAULT_SALT_SIZE, op.output_file)
        != DEFAULT_SALT_SIZE)
        {
            fprintf (stderr,
                     "ERROR: Failed to write salt to output file '%s'.\n",
                     output_file);
            DEBUG_ERROR ("Failed to write salt to output file: '%s'",
                         output_file);
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }
    final_output_size += DEFAULT_SALT_SIZE;
    DEBUG_TRACE_MSG ("Salt written to output file");

    // Write encrypted magic header
    if (write_magic_header (&op) != FILE_OP_SUCCESS)
        {
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }
    final_output_size += ENCRYPTION_MAGIC_LEN;

    // Allocate buffers
    if (allocate_crypto_buffers (&op) != FILE_OP_SUCCESS)
        {
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }

    // Process file data
    unsigned long processed_size
        = process_crypto_chunks (&op, original_size, quiet, 1);
    if (processed_size == 0 && original_size > 0)
        {
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("encrypt_file", 0);
            return 0;
        }

    final_output_size += processed_size;
    DEBUG_INFO ("Encryption completed - final output size: %lu bytes",
                final_output_size);

    if (!quiet && original_size > 0)
        {
            print_progress_bar (original_size, original_size, PROGRESS_WIDTH);
            printf ("\n");
        }

    // Clean up successfully
    cleanup_crypto_operation (&op, NULL, 0);
    secure_cleanup_crypto_keys (&op);

    DEBUG_FUNCTION_EXIT_SIZE ("encrypt_file", final_output_size);
    return final_output_size;
}

unsigned long
decrypt_file (const char *input_file, const char *output_file,
              const char *password, int quiet, unsigned long *original_size_out)
{
    crypto_operation_t op = { 0 };
    chacha20_ctx ctx;
    unsigned long total_input_size = 0, data_to_decrypt_size,
                  final_output_size = 0;

    DEBUG_FUNCTION_ENTER ("decrypt_file");
    DEBUG_INFO ("Decrypting file - input: '%s', output: '%s', quiet: %s",
                input_file, output_file, quiet ? "yes" : "no");

    if (validate_input_params (input_file, output_file) != FILE_OP_SUCCESS
        || !password || strlen (password) == 0)
        {
            if (!password || strlen (password) == 0)
                {
                    fprintf (stderr, "ERROR: Password cannot be empty.\n");
                    DEBUG_ERROR_MSG ("Empty password provided");
                }
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }

    if (!quiet)
        {
            print_section_header ("File Decryption");
            printf ("Input file:  %s\n", input_file);
            printf ("Output file: %s\n", output_file);
            printf ("Decryption:  ChaCha20 (256-bit)\n");
        }

    // Open and validate input file
    op.input_file = open_input_file (input_file);
    if (!op.input_file)
        {
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }

    if (get_file_size (op.input_file, &total_input_size) != FILE_OP_SUCCESS)
        {
            fprintf (stderr,
                     "ERROR: Could not determine size of input file '%s'.\n",
                     input_file);
            DEBUG_ERROR ("Failed to get file size for: '%s'", input_file);
            fclose (op.input_file);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }
    DEBUG_INFO ("Input file size: %lu bytes", total_input_size);

    if (original_size_out)
        *original_size_out = total_input_size;

    if (total_input_size < MIN_ENCRYPTED_FILE_SIZE)
        {
            fprintf (stderr,
                     "ERROR: Input file '%s' is too small (%lu bytes) to be "
                     "valid encrypted data.\n",
                     input_file, total_input_size);
            DEBUG_ERROR ("Input file too small: %lu bytes", total_input_size);
            fclose (op.input_file);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }

    op.output_file = open_output_file (output_file);
    if (!op.output_file)
        {
            fclose (op.input_file);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }

    // Read salt
    if (fread (op.salt, 1, DEFAULT_SALT_SIZE, op.input_file)
        != DEFAULT_SALT_SIZE)
        {
            fprintf (stderr,
                     "ERROR: Failed to read salt from input file '%s'.\n",
                     input_file);
            DEBUG_ERROR_MSG ("Failed to read salt from input file");
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }
    DEBUG_TRACE ("Salt read successfully (%d bytes)", DEFAULT_SALT_SIZE);

    // Set up crypto context with existing salt
    op.crypto_ctx = &ctx;
    if (derive_key_and_nonce (password, op.salt, DEFAULT_SALT_SIZE,
                              KEY_DERIVATION_ITERATIONS, op.key,
                              CHACHA20_KEY_SIZE, op.nonce, CHACHA20_NONCE_SIZE)
        != 0)
        {
            fprintf (stderr,
                     "ERROR: Failed to derive key and nonce from password.\n");
            DEBUG_ERROR_MSG ("Key derivation failed");
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }
    DEBUG_TRACE_MSG ("Key and nonce derived successfully");

    if (chacha20_init (op.crypto_ctx, op.key, op.nonce, 1) != 0)
        {
            fprintf (stderr, "ERROR: Failed to initialise ChaCha20 context.\n");
            DEBUG_ERROR_MSG ("ChaCha20 initialisation failed");
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }
    DEBUG_TRACE_MSG ("ChaCha20 context initialised successfully");

    // Allocate buffers
    if (allocate_crypto_buffers (&op) != FILE_OP_SUCCESS)
        {
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }

    // Verify magic header
    data_to_decrypt_size = total_input_size - DEFAULT_SALT_SIZE;
    DEBUG_INFO ("Data to decrypt size: %lu bytes", data_to_decrypt_size);

    if (data_to_decrypt_size < ENCRYPTION_MAGIC_LEN)
        {
            fprintf (
                stderr,
                "ERROR: Encrypted file too small to contain magic header.\n");
            DEBUG_ERROR ("File too small for magic header: %lu bytes",
                         data_to_decrypt_size);
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }

    if (verify_magic_header (&op) != FILE_OP_SUCCESS)
        {
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }

    data_to_decrypt_size -= ENCRYPTION_MAGIC_LEN;
    DEBUG_INFO ("Adjusted data to decrypt size: %lu bytes",
                data_to_decrypt_size);

    // Process encrypted data
    final_output_size
        = process_crypto_chunks (&op, data_to_decrypt_size, quiet, 0);
    if (final_output_size == 0 && data_to_decrypt_size > 0)
        {
            cleanup_crypto_operation (&op, output_file, 1);
            DEBUG_FUNCTION_EXIT ("decrypt_file", 0);
            return 0;
        }

    DEBUG_INFO ("Final output size: %lu bytes", final_output_size);

    if (!quiet && data_to_decrypt_size > 0)
        {
            print_progress_bar (data_to_decrypt_size, data_to_decrypt_size,
                                PROGRESS_WIDTH);
            printf ("\n");
        }

    // Clean up successfully
    cleanup_crypto_operation (&op, NULL, 0);
    secure_cleanup_crypto_keys (&op);

    DEBUG_FUNCTION_EXIT_SIZE ("decrypt_file", final_output_size);
    return final_output_size;
}

unsigned long
compress_file (const char *input_file, const char *output_file, int quiet,
               unsigned long *original_size_out)
{
    FILE *input_file_handle;
    unsigned long original_size = 0;
    unsigned long compressed_file_size = 0;

    DEBUG_FUNCTION_ENTER ("compress_file");
    DEBUG_INFO (
        "Compressing file (streaming) - input: '%s', output: '%s', quiet: %s",
        input_file, output_file, quiet ? "yes" : "no");

    if (validate_input_params (input_file, output_file) != FILE_OP_SUCCESS)
        {
            DEBUG_FUNCTION_EXIT ("compress_file", 0);
            return 0;
        }

    if (!quiet)
        {
            print_section_header ("File Compression");
            printf ("Input file:  %s\n", input_file);
            printf ("Output file: %s\n", output_file);
            printf ("Algorithm:   Huffman Coding (Streaming)\n");
        }

    // Get original file size for reporting
    input_file_handle = open_input_file (input_file);
    if (!input_file_handle)
        {
            DEBUG_FUNCTION_EXIT ("compress_file", 0);
            return 0;
        }

    if (get_file_size (input_file_handle, &original_size) != FILE_OP_SUCCESS)
        {
            fprintf (stderr,
                     "ERROR: Could not determine size of input file '%s'.\n",
                     input_file);
            DEBUG_ERROR ("Failed to get file size for: '%s'", input_file);
            fclose (input_file_handle);
            DEBUG_FUNCTION_EXIT ("compress_file", 0);
            return 0;
        }
    fclose (input_file_handle);

    DEBUG_INFO ("Input file size: %lu bytes", original_size);

    if (original_size_out)
        *original_size_out = original_size;

    // Perform streaming compression
    if (!quiet)
        {
            printf ("\nCompressing file (streaming approach)...\n");
            print_progress_bar (0, original_size, PROGRESS_WIDTH);
        }
    DEBUG_INFO (
        "Starting streaming Huffman compression - input size: %lu bytes",
        original_size);
    if (huffman_compress_file (input_file, output_file, quiet) != 0)
        {
            fprintf (stderr,
                     "\nERROR: Streaming Huffman compression failed.\n");
            DEBUG_ERROR_MSG ("Streaming Huffman compression failed");
            DEBUG_FUNCTION_EXIT ("compress_file", 0);
            return 0;
        }

    // Get compressed file size
    FILE *output_handle = fopen (output_file, "rb");
    if (output_handle)
        {
            if (get_file_size (output_handle, &compressed_file_size)
                == FILE_OP_SUCCESS)
                {
                    DEBUG_INFO ("Streaming Huffman compression completed - "
                                "output size: %lu bytes",
                                compressed_file_size);
                }
            fclose (output_handle);
        }

    if (!quiet)
        {
            print_progress_bar (original_size, original_size, PROGRESS_WIDTH);
            printf ("\n");
        }

    DEBUG_INFO ("Compression completed - compressed file size: %lu bytes",
                compressed_file_size);
    DEBUG_FUNCTION_EXIT_SIZE ("compress_file", compressed_file_size);
    return compressed_file_size;
}

unsigned long
decompress_file (const char *input_file, const char *output_file, int quiet,
                 unsigned long *original_size_out)
{
    FILE *input_file_handle;
    unsigned long compressed_file_size = 0;
    unsigned long decompressed_file_size = 0;

    DEBUG_FUNCTION_ENTER ("decompress_file");
    DEBUG_INFO (
        "Decompressing file (streaming) - input: '%s', output: '%s', quiet: %s",
        input_file, output_file, quiet ? "yes" : "no");

    if (validate_input_params (input_file, output_file) != FILE_OP_SUCCESS)
        {
            DEBUG_FUNCTION_EXIT ("decompress_file", 0);
            return 0;
        }

    if (!quiet)
        {
            print_section_header ("File Decompression");
            printf ("Input file:  %s\n", input_file);
            printf ("Output file: %s\n", output_file);
            printf ("Algorithm:   Huffman Coding (Streaming)\n");
        }

    // Get compressed file size for reporting
    input_file_handle = open_input_file (input_file);
    if (!input_file_handle)
        {
            DEBUG_FUNCTION_EXIT ("decompress_file", 0);
            return 0;
        }

    if (get_file_size (input_file_handle, &compressed_file_size)
        != FILE_OP_SUCCESS)
        {
            fprintf (stderr,
                     "ERROR: Could not determine size of input file '%s'.\n",
                     input_file);
            DEBUG_ERROR ("Failed to get file size for: '%s'", input_file);
            fclose (input_file_handle);
            DEBUG_FUNCTION_EXIT ("decompress_file", 0);
            return 0;
        }
    fclose (input_file_handle);

    DEBUG_INFO ("Compressed file size: %lu bytes", compressed_file_size);

    if (original_size_out)
        *original_size_out = compressed_file_size;

    // Handle empty compressed file (only size header, no data)
    if (compressed_file_size == sizeof (unsigned long))
        {
            if (!quiet)
                {
                    print_section_header ("Empty File Decompression");
                    printf ("Input file:  %s\n", input_file);
                    printf ("Output file: %s\n", output_file);
                    printf ("No data to decompress; creating empty file.\n");
                }
            // Create an empty output file
            FILE *out = fopen (output_file, "wb");
            if (out)
                fclose (out);
            DEBUG_FUNCTION_EXIT ("decompress_file", 0);
            return 0;
        }

    if (compressed_file_size < MIN_COMPRESSED_FILE_SIZE)
        {
            fprintf (stderr,
                     "ERROR: Input file '%s' is too small (%lu bytes) to "
                     "contain header.\n",
                     input_file, compressed_file_size);
            DEBUG_ERROR ("Input file too small: %lu bytes",
                         compressed_file_size);
            DEBUG_FUNCTION_EXIT ("decompress_file", 0);
            return 0;
        }

    // Perform streaming decompression
    if (!quiet)
        {
            printf ("\nDecompressing file (streaming approach)...\n");
            print_progress_bar (0, compressed_file_size, PROGRESS_WIDTH);
        }
    DEBUG_INFO (
        "Starting streaming Huffman decompression - compressed size: %lu bytes",
        compressed_file_size);
    if (huffman_stream_decompress_file (input_file, output_file, quiet) != 0)
        {
            fprintf (
                stderr,
                "\nERROR: Streaming Huffman decompression failed. Input file "
                "might be corrupted or not compressed with this tool.\n");
            DEBUG_ERROR_MSG ("Streaming Huffman decompression failed");
            DEBUG_FUNCTION_EXIT ("decompress_file", 0);
            return 0;
        }

    // Get decompressed file size
    FILE *output_handle = fopen (output_file, "rb");
    if (output_handle)
        {
            if (get_file_size (output_handle, &decompressed_file_size)
                == FILE_OP_SUCCESS)
                {
                    DEBUG_INFO ("Streaming Huffman decompression completed - "
                                "output size: %lu bytes",
                                decompressed_file_size);
                }
            fclose (output_handle);
        }

    if (!quiet)
        {
            print_progress_bar (compressed_file_size, compressed_file_size,
                                PROGRESS_WIDTH);
            printf ("\n");
        }

    DEBUG_INFO ("Decompression completed - decompressed file size: %lu bytes",
                decompressed_file_size);
    DEBUG_FUNCTION_EXIT_SIZE ("decompress_file", decompressed_file_size);
    return decompressed_file_size;
}

unsigned long
process_file (const char *input_file, const char *output_file,
              const char *password, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long compressed_size = 0, final_size = 0, original_input_size = 0;

    DEBUG_FUNCTION_ENTER ("process_file");
    DEBUG_INFO (
        "Processing file (compress + encrypt) - input: '%s', output: '%s'",
        input_file, output_file);

    if (validate_input_params (input_file, output_file) != FILE_OP_SUCCESS
        || !password || strlen (password) == 0)
        {
            if (!password || strlen (password) == 0)
                {
                    fprintf (stderr, "ERROR: Password cannot be empty.\n");
                    DEBUG_ERROR_MSG ("Empty password provided");
                }
            DEBUG_FUNCTION_EXIT ("process_file", 0);
            return 0;
        }

    if (create_temp_filename (temp_file, sizeof (temp_file), output_file,
                              TEMP_FILE_SUFFIX_COMPRESS)
        != FILE_OP_SUCCESS)
        {
            DEBUG_FUNCTION_EXIT ("process_file", 0);
            return 0;
        }

    if (!quiet)
        {
            print_section_header ("File Processing");
            printf ("Operation: Compress and Encrypt\n");
            printf ("Input file: %s\n", input_file);
            printf ("Output file: %s\n", output_file);
        }

    // Compression step
    if (!quiet)
        printf ("\n--- Compression Step ---\n");
    DEBUG_INFO_MSG ("Starting compression step");

    compressed_size
        = compress_file (input_file, temp_file, quiet, &original_input_size);
    if (original_size_out)
        *original_size_out = original_input_size;

    DEBUG_INFO (
        "Compression step completed - input: %lu bytes, compressed: %lu bytes",
        original_input_size, compressed_size);

    if (compressed_size == 0 && original_input_size > 0)
        {
            fprintf (stderr, "ERROR: Compression step failed for input '%s'.\n",
                     input_file);
            DEBUG_ERROR_MSG ("Compression step failed");
            remove (temp_file);
            DEBUG_FUNCTION_EXIT ("process_file", 0);
            return 0;
        }

    // Encryption step
    if (!quiet)
        printf ("\n--- Encryption Step ---\n");
    DEBUG_INFO_MSG ("Starting encryption step");

    final_size = encrypt_file (temp_file, output_file, password, quiet, NULL);
    DEBUG_INFO (
        "Encryption step completed - compressed: %lu bytes, final: %lu bytes",
        compressed_size, final_size);

    if (final_size == 0 && compressed_size > 0)
        {
            fprintf (stderr,
                     "ERROR: Encryption step failed for temporary file '%s'.\n",
                     temp_file);
            DEBUG_ERROR_MSG ("Encryption step failed");
            remove (temp_file);
            remove (output_file);
            DEBUG_FUNCTION_EXIT ("process_file", 0);
            return 0;
        }

    // Clean up
    DEBUG_TRACE ("Removing temporary file: '%s'", temp_file);
    remove (temp_file);

    if (!quiet)
        {
            printf ("\n");
            print_processing_summary ("Process (Compress + Encrypt)",
                                      input_file, output_file,
                                      original_input_size, final_size);
            print_operation_result (0, "File processing (compress + encrypt)");
        }

    DEBUG_INFO ("File processing completed successfully - original: %lu bytes, "
                "final: %lu bytes",
                original_input_size, final_size);
    DEBUG_FUNCTION_EXIT_SIZE ("process_file", final_size);
    return final_size;
}

unsigned long
extract_file (const char *input_file, const char *output_file,
              const char *password, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long decrypted_size = 0, final_size = 0, original_input_size = 0;

    DEBUG_FUNCTION_ENTER ("extract_file");
    DEBUG_INFO (
        "Extracting file (decrypt + decompress) - input: '%s', output: '%s'",
        input_file, output_file);

    if (validate_input_params (input_file, output_file) != FILE_OP_SUCCESS
        || !password || strlen (password) == 0)
        {
            if (!password || strlen (password) == 0)
                {
                    fprintf (stderr, "ERROR: Password cannot be empty.\n");
                    DEBUG_ERROR_MSG ("Empty password provided");
                }
            DEBUG_FUNCTION_EXIT ("extract_file", 0);
            return 0;
        }

    if (create_temp_filename (temp_file, sizeof (temp_file), output_file,
                              TEMP_FILE_SUFFIX_DECRYPT)
        != FILE_OP_SUCCESS)
        {
            DEBUG_FUNCTION_EXIT ("extract_file", 0);
            return 0;
        }

    if (!quiet)
        {
            print_section_header ("File Extraction");
            printf ("Operation: Decrypt and Decompress\n");
            printf ("Input file: %s\n", input_file);
            printf ("Output file: %s\n", output_file);
        }

    // Decryption step
    if (!quiet)
        printf ("\n--- Decryption Step ---\n");
    DEBUG_INFO_MSG ("Starting decryption step");

    decrypted_size = decrypt_file (input_file, temp_file, password, quiet,
                                   &original_input_size);
    if (original_size_out)
        *original_size_out = decrypted_size;

    DEBUG_INFO (
        "Decryption step completed - input: %lu bytes, decrypted: %lu bytes",
        original_input_size, decrypted_size);

    if (decrypted_size == 0 && original_input_size > DEFAULT_SALT_SIZE)
        {
            fprintf (stderr,
                     "ERROR: Decryption step failed for input '%s' (I/O or "
                     "memory error).\n",
                     input_file);
            DEBUG_ERROR_MSG ("Decryption step failed");
            remove (temp_file);
            DEBUG_FUNCTION_EXIT ("extract_file", 0);
            return 0;
        }

    // Decompression step
    if (!quiet)
        printf ("\n--- Decompression Step ---\n");
    DEBUG_INFO_MSG ("Starting decompression step");

    final_size = decompress_file (temp_file, output_file, quiet, NULL);
    DEBUG_INFO ("Decompression step completed - compressed: %lu bytes, final: "
                "%lu bytes",
                decrypted_size, final_size);

    if (final_size == 0 && decrypted_size > sizeof (unsigned long))
        {
            fprintf (stderr,
                     "ERROR: Decompression step failed for temporary file "
                     "'%s'. Decrypted data might be corrupted.\n",
                     temp_file);
            DEBUG_ERROR_MSG ("Decompression step failed");
            remove (temp_file);
            remove (output_file);
            DEBUG_FUNCTION_EXIT ("extract_file", 0);
            return 0;
        }

    // Clean up
    DEBUG_TRACE ("Removing temporary file: '%s'", temp_file);
    remove (temp_file);

    if (!quiet)
        {
            printf ("\n");
            print_processing_summary ("Extract (Decrypt+Decompress)",
                                      input_file, output_file,
                                      original_input_size, final_size);
            print_operation_result (0,
                                    "File extraction (decrypt + decompress)");
        }

    DEBUG_INFO ("File extraction completed successfully - original: %lu bytes, "
                "final: %lu bytes",
                original_input_size, final_size);
    DEBUG_FUNCTION_EXIT_SIZE ("extract_file", final_size);
    return final_size;
}

int
handle_file_list (const char *command, const char *filename_pattern, int quiet)
{
    file_list_t file_list;
    file_entry_t *found_entry;

    DEBUG_FUNCTION_ENTER ("handle_file_list");
    DEBUG_INFO (
        "Handling file list command - command: '%s', pattern: '%s', quiet: %s",
        command, filename_pattern ? filename_pattern : "(null)",
        quiet ? "yes" : "no");

    if (!command || strlen (command) == 0)
        {
            fprintf (stderr, "ERROR: File list command cannot be empty.\n");
            DEBUG_ERROR_MSG ("Empty file list command");
            DEBUG_FUNCTION_EXIT ("handle_file_list", -1);
            return -1;
        }

    file_list_init (&file_list);
    DEBUG_TRACE_MSG ("File list structure initialised");

    if (file_list_load (&file_list, DEFAULT_FILE_LIST) != 0)
        {
            DEBUG_INFO_MSG (
                "Failed to load file list, initialising empty list");
            if (!quiet)
                {
                    file_list_free (&file_list);
                    file_list_init (&file_list);
                }
        }
    else
        {
            DEBUG_TRACE ("File list loaded from: '%s'", DEFAULT_FILE_LIST);
        }

    if (strcmp (command, "list") == 0)
        {
            DEBUG_INFO_MSG ("Processing 'list' command");
            if (!quiet)
                print_section_header ("File Processing History");
            printf ("Data source: %s\n\n", DEFAULT_FILE_LIST);
            file_list_print (&file_list);
            DEBUG_TRACE_MSG ("File list printed successfully");
        }
    else if (strcmp (command, "find") == 0)
        {
            DEBUG_INFO ("Processing 'find' command with pattern: '%s'",
                        filename_pattern ? filename_pattern : "(null)");
            if (!filename_pattern || filename_pattern[0] == '\0')
                {
                    fprintf (stderr, "ERROR: No search pattern specified.\n");
                    DEBUG_ERROR_MSG (
                        "No search pattern specified for find command");
                    file_list_free (&file_list);
                    DEBUG_FUNCTION_EXIT ("handle_file_list", -1);
                    return -1;
                }

            if (!quiet)
                {
                    print_section_header ("File Search Results");
                    printf ("Search pattern: '%s'\n\n", filename_pattern);
                }

            found_entry = file_list_find (&file_list, filename_pattern);
            if (found_entry)
                {
                    DEBUG_INFO ("Found matching entry for pattern: '%s'",
                                filename_pattern);
                    printf ("MATCH FOUND:\n");
                    printf ("Input file:     %s\n",
                            found_entry->input_filename);
                    printf ("Output file:    %s\n",
                            found_entry->output_filename);
                    printf ("Sequence ID:    %lu\n", found_entry->sequence_num);
                    printf ("Original size:  %lu bytes\n",
                            found_entry->original_size);
                    printf ("Processed size: %lu bytes\n",
                            found_entry->processed_size);
                    if (found_entry->original_size > 0)
                        {
                            printf ("Size ratio:     %.2f%%\n",
                                    (float)found_entry->processed_size * 100.0f
                                        / found_entry->original_size);
                        }
                    else
                        {
                            printf ("Size ratio:     N/A\n");
                        }
                }
            else
                {
                    DEBUG_INFO ("No matching entry found for pattern: '%s'",
                                filename_pattern);
                    printf ("NO MATCH: No files found matching pattern '%s'\n",
                            filename_pattern);
                }
        }
    else
        {
            fprintf (stderr, "ERROR: Unknown internal file list command: %s\n",
                     command);
            DEBUG_ERROR ("Unknown file list command: '%s'", command);
            file_list_free (&file_list);
            DEBUG_FUNCTION_EXIT ("handle_file_list", -1);
            return -1;
        }

    file_list_free (&file_list);
    DEBUG_TRACE_MSG ("File list structure cleaned up");
    DEBUG_FUNCTION_EXIT ("handle_file_list", 0);
    return 0;
}