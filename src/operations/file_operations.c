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
#include "utils/file_list.h"
#include "utils/ui.h"
#include "utils/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fixed number of iterations for key derivation */
#define KEY_DERIVATION_ITERATIONS 100000
#define MIN_ENCRYPTED_FILE_SIZE (DEFAULT_SALT_SIZE + 1)
#define MIN_COMPRESSED_FILE_SIZE (sizeof(unsigned long) + 1)
#define ENCRYPTION_MAGIC "SFPv1"
#define ENCRYPTION_MAGIC_LEN 5

/* Helper function prototypes */
static int get_file_size(FILE *file, unsigned long *size);
static void cleanup_crypto_buffers(unsigned char *buf1, unsigned char *buf2, chacha20_ctx *ctx);
static void cleanup_crypto_operation(FILE *in, FILE *out, unsigned char *buf1,
                                     unsigned char *buf2, chacha20_ctx *ctx,
                                     const char *output_file, int failed);

/* Helper function implementations */
static int get_file_size(FILE *file, unsigned long *size)
{
    DEBUG_TRACE_MSG("Getting file size");

    if (fseek(file, 0, SEEK_END) != 0)
    {
        DEBUG_ERROR_MSG("Failed to seek to end of file");
        return -1;
    }
    *size = ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0)
    {
        DEBUG_ERROR_MSG("Failed to seek back to start of file");
        return -1;
    }

    DEBUG_TRACE("File size determined: %lu bytes", *size);
    return 0;
}

static void cleanup_crypto_buffers(unsigned char *buf1, unsigned char *buf2, chacha20_ctx *ctx)
{
    if (buf1)
    {
        memset(buf1, 0, BUFFER_SIZE);
        free(buf1);
    }
    if (buf2)
    {
        memset(buf2, 0, BUFFER_SIZE);
        free(buf2);
    }
    if (ctx)
    {
        chacha20_cleanup(ctx);
    }
}

static void cleanup_crypto_operation(FILE *in, FILE *out, unsigned char *buf1,
                                     unsigned char *buf2, chacha20_ctx *ctx,
                                     const char *output_file, int failed)
{
    DEBUG_TRACE("Cleaning up crypto operation - failed: %s", failed ? "yes" : "no");

    if (in)
        fclose(in);
    if (out)
        fclose(out);
    cleanup_crypto_buffers(buf1, buf2, ctx);
    if (failed && output_file)
    {
        DEBUG_TRACE("Removing failed output file: '%s'", output_file);
        if (remove(output_file) != 0)
        {
            DEBUG_ERROR("Failed to remove output file: '%s'", output_file);
        }
        else
        {
            DEBUG_TRACE_MSG("Failed output file removed successfully");
        }
    }
}

int add_entry_to_file_list(const char *input_file, const char *output_file, unsigned long original_size, unsigned long processed_size, int quiet)
{
    file_list_t file_list;

    DEBUG_FUNCTION_ENTER("add_entry_to_file_list");
    DEBUG_INFO("Adding entry to file list - input: '%s', output: '%s', original: %lu, processed: %lu, quiet: %s",
               input_file, output_file, original_size, processed_size, quiet ? "yes" : "no");

    file_list_init(&file_list);
    DEBUG_TRACE_MSG("File list structure initialised");

    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        DEBUG_INFO_MSG("Failed to load existing file list, creating new one");
        file_list_free(&file_list);
        file_list_init(&file_list);
    }
    else
    {
        DEBUG_TRACE("Existing file list loaded from: '%s'", DEFAULT_FILE_LIST);
    }

    if (file_list_add(&file_list, input_file, output_file, original_size, processed_size) != 0)
    {
        if (!quiet)
        {
            fprintf(stderr, "Warning: Failed to add entry '%s -> %s' to file list structure in memory.\n", input_file, output_file);
        }
        DEBUG_ERROR("Failed to add entry to file list in memory: '%s' -> '%s'", input_file, output_file);
        file_list_free(&file_list);
        DEBUG_FUNCTION_EXIT("add_entry_to_file_list", -1);
        return -1;
    }
    DEBUG_TRACE_MSG("Entry added to file list structure in memory");

    if (file_list_save(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        if (!quiet)
        {
            fprintf(stderr, "Warning: Failed to save updated file list to %s\n", DEFAULT_FILE_LIST);
        }
        DEBUG_ERROR("Failed to save file list to: '%s'", DEFAULT_FILE_LIST);
        file_list_free(&file_list);
        DEBUG_FUNCTION_EXIT("add_entry_to_file_list", -1);
        return -1;
    }
    DEBUG_TRACE("File list saved successfully to: '%s'", DEFAULT_FILE_LIST);

    file_list_free(&file_list);
    DEBUG_TRACE_MSG("File list structure cleaned up");
    DEBUG_FUNCTION_EXIT("add_entry_to_file_list", 0);
    return 0;
}

unsigned long encrypt_file(const char *input_file, const char *output_file,
                           const char *password, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    unsigned char *buffer = NULL, *output_buffer = NULL;
    unsigned char key[CHACHA20_KEY_SIZE];
    unsigned char nonce[CHACHA20_NONCE_SIZE];
    unsigned char salt[DEFAULT_SALT_SIZE];
    unsigned long read_size, file_size = 0, original_size = 0;
    unsigned long final_output_size = 0;

    DEBUG_FUNCTION_ENTER("encrypt_file");
    DEBUG_INFO("Encrypting file - input: '%s', output: '%s', quiet: %s",
               input_file, output_file, quiet ? "yes" : "no");

    if (!quiet)
    {
        print_section_header("File Encryption");
        printf("Input file:  %s\n", input_file);
        printf("Output file: %s\n", output_file);
        printf("Encryption:  ChaCha20 (256-bit)\n");
    }
    in = fopen(input_file, "rb");
    if (!in)
    {
        fprintf(stderr, "ERROR: Cannot open input file '%s' for reading.\n", input_file);
        DEBUG_ERROR("Failed to open input file: '%s'", input_file);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Input file opened successfully");

    if (get_file_size(in, &original_size) != 0)
    {
        fprintf(stderr, "ERROR: Could not determine size of input file '%s'.\n", input_file);
        DEBUG_ERROR("Failed to get file size for: '%s'", input_file);
        fclose(in);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }
    DEBUG_INFO("Input file size: %lu bytes", original_size);
    if (original_size_out)
        *original_size_out = original_size;

    out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "ERROR: Cannot open output file '%s' for writing.\n", output_file);
        DEBUG_ERROR("Failed to open output file: '%s'", output_file);
        fclose(in);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Output file opened successfully");

    // Generate and write salt
    if (generate_salt(salt, DEFAULT_SALT_SIZE) != 0)
    {
        fprintf(stderr, "ERROR: Failed to generate salt.\n");
        DEBUG_ERROR_MSG("Salt generation failed");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Salt generated successfully");

    if (fwrite(salt, 1, DEFAULT_SALT_SIZE, out) != DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "ERROR: Failed to write salt to output file '%s'.\n", output_file);
        DEBUG_ERROR("Failed to write salt to output file: '%s'", output_file);
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }
    final_output_size += DEFAULT_SALT_SIZE;
    DEBUG_TRACE_MSG("Salt written to output file");

    // Derive key and nonce
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, KEY_DERIVATION_ITERATIONS,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0)
    {
        fprintf(stderr, "ERROR: Failed to derive key and nonce from password.\n");
        DEBUG_ERROR_MSG("Key derivation failed");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Key and nonce derived successfully");

    // Initialise ChaCha20
    if (chacha20_init(&ctx, key, nonce, 1) != 0)
    {
        fprintf(stderr, "ERROR: Failed to initialise ChaCha20 context.\n");
        DEBUG_ERROR_MSG("ChaCha20 initialisation failed");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("ChaCha20 context initialised");

    // Write encrypted magic header to detect wrong password on decryption
    {
        unsigned char magic_plain[ENCRYPTION_MAGIC_LEN] = ENCRYPTION_MAGIC;
        unsigned char magic_cipher[ENCRYPTION_MAGIC_LEN];
        if (chacha20_process(&ctx, magic_plain, magic_cipher, ENCRYPTION_MAGIC_LEN) != 0)
        {
            fprintf(stderr, "ERROR: Failed to encrypt magic header.\n");
            DEBUG_ERROR_MSG("Failed to encrypt magic header");
            cleanup_crypto_operation(in, out, NULL, NULL, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("encrypt_file", 0);
            return 0;
        }
        if (fwrite(magic_cipher, 1, ENCRYPTION_MAGIC_LEN, out) != ENCRYPTION_MAGIC_LEN)
        {
            fprintf(stderr, "ERROR: Failed to write magic header to output file '%s'.\n", output_file);
            DEBUG_ERROR("Failed to write magic header to: '%s'", output_file);
            cleanup_crypto_operation(in, out, NULL, NULL, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("encrypt_file", 0);
            return 0;
        }
        file_size += ENCRYPTION_MAGIC_LEN;
        DEBUG_TRACE_MSG("Magic header encrypted and written");
    }

    // Allocate buffers
    buffer = malloc(BUFFER_SIZE);
    output_buffer = malloc(BUFFER_SIZE);
    if (!buffer || !output_buffer)
    {
        fprintf(stderr, "ERROR: Memory allocation failed for buffers.\n");
        DEBUG_ERROR_MSG("Buffer allocation failed");
        cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Encryption buffers allocated");

    if (!quiet)
    {
        printf("\nEncrypting file...\n");
        print_progress_bar(0, original_size, PROGRESS_WIDTH);
    }
    DEBUG_INFO("Starting encryption loop for %lu bytes", original_size);

    // Process file in chunks
    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0)
    {
        DEBUG_TRACE("Processing chunk of %lu bytes", read_size);
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0)
        {
            fprintf(stderr, "\nERROR: ChaCha20 encryption failed during processing.\n");
            DEBUG_ERROR_MSG("ChaCha20 encryption failed during chunk processing");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("encrypt_file", 0);
            return 0;
        }

        if (fwrite(output_buffer, 1, read_size, out) != read_size)
        {
            fprintf(stderr, "\nERROR: Failed to write encrypted data to output file '%s'.\n", output_file);
            DEBUG_ERROR("Failed to write encrypted chunk to: '%s'", output_file);
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("encrypt_file", 0);
            return 0;
        }

        file_size += read_size;
        if (!quiet)
        {
            print_progress_bar(file_size, original_size, PROGRESS_WIDTH);
        }
    }
    DEBUG_INFO("Encryption loop completed, processed %lu bytes", file_size);
    if (ferror(in))
    {
        fprintf(stderr, "\nERROR: Failed reading from input file '%s'.\n", input_file);
        DEBUG_ERROR("File read error for input: '%s'", input_file);
        cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
        DEBUG_FUNCTION_EXIT("encrypt_file", 0);
        return 0;
    }

    final_output_size += file_size;
    DEBUG_INFO("Encryption completed - final output size: %lu bytes", final_output_size);
    if (!quiet)
    {
        if (original_size > 0)
        {
            print_progress_bar(original_size, original_size, PROGRESS_WIDTH);
        }
        printf("\n");
    }

    // Clean up successfully
    cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, NULL, 0);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    memset(salt, 0, DEFAULT_SALT_SIZE);
    DEBUG_TRACE_MSG("Encryption cleanup completed");

    DEBUG_FUNCTION_EXIT_SIZE("encrypt_file", final_output_size);
    return final_output_size;
}

unsigned long decrypt_file(const char *input_file, const char *output_file,
                           const char *password, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    unsigned char *buffer = NULL, *output_buffer = NULL;
    unsigned char key[CHACHA20_KEY_SIZE];
    unsigned char nonce[CHACHA20_NONCE_SIZE];
    unsigned char salt[DEFAULT_SALT_SIZE];
    unsigned long read_size, file_size = 0, total_input_size = 0;
    unsigned long data_to_decrypt_size, final_output_size = 0;

    DEBUG_FUNCTION_ENTER("decrypt_file");
    DEBUG_INFO("Decrypting file - input: '%s', output: '%s', quiet: %s",
               input_file, output_file, quiet ? "yes" : "no");
    if (!quiet)
    {
        print_section_header("File Decryption");
        printf("Input file:  %s\n", input_file);
        printf("Output file: %s\n", output_file);
        printf("Decryption:  ChaCha20 (256-bit)\n");
    }

    in = fopen(input_file, "rb");
    if (!in)
    {
        fprintf(stderr, "ERROR: Cannot open input file '%s' for reading.\n", input_file);
        DEBUG_ERROR("Failed to open input file: '%s'", input_file);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Input file opened successfully");

    if (get_file_size(in, &total_input_size) != 0)
    {
        fprintf(stderr, "ERROR: Could not determine size of input file '%s'.\n", input_file);
        DEBUG_ERROR("Failed to get file size for: '%s'", input_file);
        fclose(in);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }
    DEBUG_INFO("Input file size: %lu bytes", total_input_size);

    if (original_size_out)
        *original_size_out = total_input_size;

    if (total_input_size < MIN_ENCRYPTED_FILE_SIZE)
    {
        fprintf(stderr, "ERROR: Input file '%s' is too small (%lu bytes) to be valid encrypted data.\n",
                input_file, total_input_size);
        DEBUG_ERROR("Input file too small: %lu bytes", total_input_size);
        fclose(in);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }

    out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "ERROR: Cannot open output file '%s' for writing.\n", output_file);
        DEBUG_ERROR("Failed to open output file: '%s'", output_file);
        fclose(in);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Output file opened successfully");

    // Read salt
    if (fread(salt, 1, DEFAULT_SALT_SIZE, in) != DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "ERROR: Failed to read salt from input file '%s'.\n", input_file);
        DEBUG_ERROR_MSG("Failed to read salt from input file");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE("Salt read successfully (%d bytes)", DEFAULT_SALT_SIZE); // Derive key and nonce
    DEBUG_TRACE_MSG("Deriving key and nonce from password");
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, KEY_DERIVATION_ITERATIONS,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0)
    {
        fprintf(stderr, "ERROR: Failed to derive key and nonce from password.\n");
        DEBUG_ERROR_MSG("Key derivation failed");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Key and nonce derived successfully");

    // Initialise ChaCha20
    DEBUG_TRACE_MSG("Initialising ChaCha20 context");
    if (chacha20_init(&ctx, key, nonce, 1) != 0)
    {
        fprintf(stderr, "ERROR: Failed to initialise ChaCha20 context.\n");
        DEBUG_ERROR_MSG("ChaCha20 initialisation failed");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("ChaCha20 context initialised successfully");

    // Allocate buffers
    DEBUG_TRACE("Allocating buffers (%d bytes each)", BUFFER_SIZE);
    buffer = malloc(BUFFER_SIZE);
    output_buffer = malloc(BUFFER_SIZE);
    if (!buffer || !output_buffer)
    {
        fprintf(stderr, "ERROR: Memory allocation failed for buffers.\n");
        DEBUG_ERROR_MSG("Buffer allocation failed");
        cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Buffers allocated successfully"); // Verify encrypted magic header to detect wrong password
    data_to_decrypt_size = total_input_size - DEFAULT_SALT_SIZE;
    DEBUG_INFO("Data to decrypt size: %lu bytes", data_to_decrypt_size);
    if (data_to_decrypt_size < ENCRYPTION_MAGIC_LEN)
    {
        fprintf(stderr, "ERROR: Encrypted file too small to contain magic header.\n");
        DEBUG_ERROR("File too small for magic header: %lu bytes", data_to_decrypt_size);
        cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
        DEBUG_FUNCTION_EXIT("decrypt_file", 0);
        return 0;
    }
    {
        unsigned char magic_cipher[ENCRYPTION_MAGIC_LEN];
        unsigned char magic_plain[ENCRYPTION_MAGIC_LEN];
        DEBUG_TRACE_MSG("Reading and verifying magic header");
        if (fread(magic_cipher, 1, ENCRYPTION_MAGIC_LEN, in) != ENCRYPTION_MAGIC_LEN)
        {
            fprintf(stderr, "ERROR: Failed to read magic header from input file '%s'.\n", input_file);
            DEBUG_ERROR_MSG("Failed to read magic header");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("decrypt_file", 0);
            return 0;
        }
        if (chacha20_process(&ctx, magic_cipher, magic_plain, ENCRYPTION_MAGIC_LEN) != 0)
        {
            fprintf(stderr, "ERROR: Failed to decrypt magic header.\n");
            DEBUG_ERROR_MSG("Magic header decryption failed");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("decrypt_file", 0);
            return 0;
        }
        if (memcmp(magic_plain, ENCRYPTION_MAGIC, ENCRYPTION_MAGIC_LEN) != 0)
        {
            if (!quiet)
                fprintf(stderr, "ERROR: Incorrect password or corrupted file.\n");
            DEBUG_ERROR_MSG("Magic header verification failed - incorrect password or corrupted file");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("decrypt_file", 0);
            return 0;
        }
        DEBUG_TRACE_MSG("Magic header verified successfully");
        // Reduce data to decrypt by magic header length
        data_to_decrypt_size -= ENCRYPTION_MAGIC_LEN;
        DEBUG_INFO("Adjusted data to decrypt size: %lu bytes", data_to_decrypt_size);
    }
    if (!quiet)
    {
        printf("\nDecrypting file...\n");
        print_progress_bar(0, data_to_decrypt_size, PROGRESS_WIDTH);
    }
    DEBUG_INFO("Starting decryption loop for %lu bytes", data_to_decrypt_size);

    // Decrypt file in chunks
    while (file_size < data_to_decrypt_size)
    {
        unsigned long chunk_size = (data_to_decrypt_size - file_size < BUFFER_SIZE) ? data_to_decrypt_size - file_size : BUFFER_SIZE;

        DEBUG_TRACE("Processing chunk: %lu bytes (progress: %lu/%lu)", chunk_size, file_size, data_to_decrypt_size);
        read_size = fread(buffer, 1, chunk_size, in);
        if (read_size == 0)
        {
            if (feof(in) && file_size < data_to_decrypt_size)
            {
                fprintf(stderr, "\nERROR: Unexpected end of file while reading encrypted data.\n");
                DEBUG_ERROR("Unexpected EOF at position %lu/%lu", file_size, data_to_decrypt_size);
            }
            else if (ferror(in))
            {
                fprintf(stderr, "\nERROR: File read error during decryption.\n");
                DEBUG_ERROR_MSG("File read error during decryption");
            }
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("decrypt_file", 0);
            return 0;
        }

        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0)
        {
            fprintf(stderr, "\nERROR: ChaCha20 decryption failed during processing.\n");
            DEBUG_ERROR_MSG("ChaCha20 processing failed for chunk");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("decrypt_file", 0);
            return 0;
        }

        if (fwrite(output_buffer, 1, read_size, out) != read_size)
        {
            fprintf(stderr, "\nERROR: Failed to write decrypted data to output file '%s'.\n", output_file);
            DEBUG_ERROR_MSG("Failed to write decrypted data");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            DEBUG_FUNCTION_EXIT("decrypt_file", 0);
            return 0;
        }

        file_size += read_size;
        if (!quiet)
        {
            print_progress_bar(file_size, data_to_decrypt_size, PROGRESS_WIDTH);
        }
    }
    DEBUG_INFO_MSG("Decryption loop completed successfully");
    final_output_size = file_size;
    DEBUG_INFO("Final output size: %lu bytes", final_output_size);

    if (!quiet)
    {
        if (data_to_decrypt_size > 0)
        {
            print_progress_bar(data_to_decrypt_size, data_to_decrypt_size, PROGRESS_WIDTH);
        }
        printf("\n");
    }

    // Clean up successfully
    DEBUG_TRACE_MSG("Cleaning up and securing memory");
    cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, NULL, 0);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    memset(salt, 0, DEFAULT_SALT_SIZE);

    DEBUG_FUNCTION_EXIT_SIZE("decrypt_file", final_output_size);
    return final_output_size;
}

unsigned long compress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buffer = NULL, *output_buffer = NULL;
    unsigned long read_size, output_size, total_input_size = 0;
    unsigned long total_output_size = 0;

    DEBUG_FUNCTION_ENTER("compress_file");
    DEBUG_INFO("Compressing file - input: '%s', output: '%s', quiet: %s",
               input_file, output_file, quiet ? "yes" : "no");

    if (!quiet)
    {
        print_section_header("File Compression");
        printf("Input file:  %s\n", input_file);
        printf("Output file: %s\n", output_file);
        printf("Algorithm:   Huffman Coding\n");
    }

    in = fopen(input_file, "rb");
    if (!in)
    {
        fprintf(stderr, "ERROR: Cannot open input file '%s' for reading.\n", input_file);
        DEBUG_ERROR("Failed to open input file: '%s'", input_file);
        DEBUG_FUNCTION_EXIT("compress_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Input file opened successfully");
    if (get_file_size(in, &total_input_size) != 0)
    {
        fprintf(stderr, "ERROR: Could not determine size of input file '%s'.\n", input_file);
        DEBUG_ERROR("Failed to get file size for: '%s'", input_file);
        fclose(in);
        DEBUG_FUNCTION_EXIT("compress_file", 0);
        return 0;
    }
    DEBUG_INFO("Input file size: %lu bytes", total_input_size);

    if (original_size_out)
        *original_size_out = total_input_size;

    out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "ERROR: Cannot open output file '%s' for writing.\n", output_file);
        DEBUG_ERROR("Failed to open output file: '%s'", output_file);
        fclose(in);
        DEBUG_FUNCTION_EXIT("compress_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Output file opened successfully"); // Write the original file size to the output file header
    DEBUG_TRACE("Writing file size header (%lu bytes)", total_input_size);
    if (fwrite(&total_input_size, sizeof(unsigned long), 1, out) != 1)
    {
        fprintf(stderr, "ERROR: Failed to write file size header to output file '%s'.\n", output_file);
        DEBUG_ERROR_MSG("Failed to write file size header");
        fclose(in);
        fclose(out);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("compress_file", 0);
        return 0;
    }
    total_output_size += sizeof(unsigned long);
    DEBUG_TRACE_MSG("File size header written successfully");

    if (total_input_size > 0)
    {
        DEBUG_TRACE("Allocating input buffer (%lu bytes)", total_input_size);
        buffer = malloc(total_input_size);
        if (!buffer)
        {
            fprintf(stderr, "ERROR: Memory allocation failed for input buffer (%lu bytes).\n", total_input_size);
            DEBUG_ERROR_MSG("Input buffer allocation failed");
            fclose(in);
            fclose(out);
            remove(output_file);
            DEBUG_FUNCTION_EXIT("compress_file", 0);
            return 0;
        }

        DEBUG_TRACE("Reading entire input file (%lu bytes)", total_input_size);
        read_size = fread(buffer, 1, total_input_size, in);
        if (read_size != total_input_size || ferror(in))
        {
            fprintf(stderr, "ERROR: Failed to read entire input file '%s'.\n", input_file);
            DEBUG_ERROR("Failed to read input file - expected %lu, got %lu", total_input_size, read_size);
            free(buffer);
            fclose(in);
            fclose(out);
            remove(output_file);
            DEBUG_FUNCTION_EXIT("compress_file", 0);
            return 0;
        }
        DEBUG_TRACE_MSG("Input file read successfully");
    }
    else
    {
        buffer = NULL;
        read_size = 0;
        DEBUG_TRACE_MSG("Empty input file - no data to compress");
    }

    unsigned long output_max_len = huffman_worst_case_size(read_size);
    DEBUG_TRACE("Allocating output buffer (%lu bytes)", output_max_len);
    output_buffer = malloc(output_max_len > 0 ? output_max_len : 1);
    if (!output_buffer)
    {
        fprintf(stderr, "ERROR: Memory allocation failed for output buffer.\n");
        DEBUG_ERROR_MSG("Output buffer allocation failed");
        if (buffer)
            free(buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("compress_file", 0);
        return 0;
    }

    if (!quiet)
    {
        printf("\nCompressing file...\n");
        print_progress_bar(0, total_input_size, PROGRESS_WIDTH);
    }
    DEBUG_INFO("Starting Huffman compression - input size: %lu bytes", read_size);

    if (huffman_compress(buffer, read_size, output_buffer, output_max_len, &output_size) != 0)
    {
        fprintf(stderr, "\nERROR: Huffman compression failed.\n");
        DEBUG_ERROR_MSG("Huffman compression failed");
        if (buffer)
            free(buffer);
        free(output_buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("compress_file", 0);
        return 0;
    }
    DEBUG_INFO("Huffman compression completed - output size: %lu bytes", output_size);
    if (output_size > 0)
    {
        DEBUG_TRACE("Writing compressed data (%lu bytes)", output_size);
        if (!quiet)
        {
            print_progress_bar(0, output_size, PROGRESS_WIDTH);
        }
        size_t written = 0;
        while (written < output_size)
        {
            size_t chunk = (output_size - written < BUFFER_SIZE) ? output_size - written : BUFFER_SIZE;
            if (fwrite(output_buffer + written, 1, chunk, out) != chunk)
            {
                fprintf(stderr, "\nERROR: Failed to write compressed data to output file '%s'.\n", output_file);
                DEBUG_ERROR_MSG("Failed to write compressed data");
                if (buffer)
                    free(buffer);
                free(output_buffer);
                fclose(in);
                fclose(out);
                remove(output_file);
                DEBUG_FUNCTION_EXIT("compress_file", 0);
                return 0;
            }
            written += chunk;
            if (!quiet)
            {
                print_progress_bar(written, output_size, PROGRESS_WIDTH);
            }
        }
        if (!quiet)
            printf("\n");
        DEBUG_TRACE_MSG("Compressed data written successfully");
    }
    total_output_size += output_size;
    if (!quiet)
    {
        print_progress_bar(total_input_size, total_input_size, PROGRESS_WIDTH);
        printf("\n");
    }

    DEBUG_TRACE_MSG("Cleaning up buffers and files");
    if (buffer)
        free(buffer);
    free(output_buffer);
    fclose(in);
    fclose(out);

    DEBUG_INFO("Compression completed - total output size: %lu bytes", total_output_size);
    DEBUG_FUNCTION_EXIT_SIZE("compress_file", total_output_size);
    return total_output_size;
}

unsigned long decompress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buffer = NULL, *output_buffer = NULL;
    unsigned long compressed_data_size, output_size, expected_original_size = 0;
    unsigned long input_actual_file_size = 0;

    DEBUG_FUNCTION_ENTER("decompress_file");
    DEBUG_INFO("Decompressing file - input: '%s', output: '%s', quiet: %s",
               input_file, output_file, quiet ? "yes" : "no");

    if (!quiet)
    {
        print_section_header("File Decompression");
        printf("Input file:  %s\n", input_file);
        printf("Output file: %s\n", output_file);
        printf("Algorithm:   Huffman Coding\n");
    }
    in = fopen(input_file, "rb");
    if (!in)
    {
        fprintf(stderr, "ERROR: Cannot open input file '%s' for reading.\n", input_file);
        DEBUG_ERROR("Failed to open input file: '%s'", input_file);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Input file opened successfully");

    if (get_file_size(in, &input_actual_file_size) != 0)
    {
        fprintf(stderr, "ERROR: Could not determine size of input file '%s'.\n", input_file);
        DEBUG_ERROR("Failed to get file size for: '%s'", input_file);
        fclose(in);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }
    DEBUG_INFO("Input file size: %lu bytes", input_actual_file_size);

    if (original_size_out)
        *original_size_out = input_actual_file_size;

    if (input_actual_file_size < MIN_COMPRESSED_FILE_SIZE)
    {
        fprintf(stderr, "ERROR: Input file '%s' is too small (%lu bytes) to contain header.\n",
                input_file, input_actual_file_size);
        DEBUG_ERROR("Input file too small: %lu bytes", input_actual_file_size);
        fclose(in);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }

    DEBUG_TRACE_MSG("Reading original file size header");
    if (fread(&expected_original_size, sizeof(unsigned long), 1, in) != 1)
    {
        fprintf(stderr, "ERROR: Failed to read original file size header from input file '%s'.\n", input_file);
        DEBUG_ERROR_MSG("Failed to read original file size header");
        fclose(in);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }
    DEBUG_INFO("Expected original size: %lu bytes", expected_original_size);

    out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "ERROR: Cannot open output file '%s' for writing.\n", output_file);
        DEBUG_ERROR("Failed to open output file: '%s'", output_file);
        fclose(in);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }
    DEBUG_TRACE_MSG("Output file opened successfully");

    compressed_data_size = input_actual_file_size - sizeof(unsigned long);
    DEBUG_INFO("Compressed data size: %lu bytes", compressed_data_size);
    if (compressed_data_size > 0)
    {
        DEBUG_TRACE("Allocating compressed data buffer (%lu bytes)", compressed_data_size);
        buffer = malloc(compressed_data_size);
        if (!buffer)
        {
            fprintf(stderr, "ERROR: Memory allocation failed for compressed data buffer (%lu bytes).\n", compressed_data_size);
            DEBUG_ERROR_MSG("Compressed data buffer allocation failed");
            fclose(in);
            fclose(out);
            remove(output_file);
            DEBUG_FUNCTION_EXIT("decompress_file", 0);
            return 0;
        }

        DEBUG_TRACE("Reading compressed data (%lu bytes)", compressed_data_size);
        if (fread(buffer, 1, compressed_data_size, in) != compressed_data_size || ferror(in))
        {
            fprintf(stderr, "ERROR: Failed to read compressed data from input file '%s'.\n", input_file);
            DEBUG_ERROR_MSG("Failed to read compressed data");
            free(buffer);
            fclose(in);
            fclose(out);
            remove(output_file);
            DEBUG_FUNCTION_EXIT("decompress_file", 0);
            return 0;
        }
        DEBUG_TRACE_MSG("Compressed data read successfully");
    }
    else if (expected_original_size > 0)
    {
        fprintf(stderr, "ERROR: Compressed file format error - header indicates %lu original bytes, but no compressed data found.\n",
                expected_original_size);
        DEBUG_ERROR_MSG("File format error - no compressed data but original size > 0");
        fclose(in);
        fclose(out);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }
    else
    {
        buffer = NULL;
        DEBUG_TRACE_MSG("Empty file - no compressed data");
    }
    DEBUG_TRACE("Allocating output buffer (%lu bytes)", expected_original_size);
    output_buffer = malloc(expected_original_size > 0 ? expected_original_size : 1);
    if (!output_buffer)
    {
        fprintf(stderr, "ERROR: Memory allocation failed for output buffer (%lu bytes).\n", expected_original_size);
        DEBUG_ERROR_MSG("Output buffer allocation failed");
        if (buffer)
            free(buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }

    if (!quiet)
    {
        printf("\nDecompressing file...\n");
        print_progress_bar(0, expected_original_size, PROGRESS_WIDTH);
    }
    DEBUG_INFO("Starting Huffman decompression - compressed size: %lu, expected output: %lu bytes",
               compressed_data_size, expected_original_size);

    if (huffman_decompress(buffer, compressed_data_size, output_buffer, expected_original_size, &output_size) != 0)
    {
        fprintf(stderr, "\nERROR: Huffman decompression failed. Input file might be corrupted or not compressed with this tool.\n");
        DEBUG_ERROR_MSG("Huffman decompression failed");
        if (buffer)
            free(buffer);
        free(output_buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }
    DEBUG_INFO("Huffman decompression completed - actual output size: %lu bytes", output_size);
    if (output_size != expected_original_size)
    {
        fprintf(stderr, "\nERROR: Decompressed size (%lu) does not match expected size from header (%lu). File might be corrupted.\n",
                output_size, expected_original_size);
        DEBUG_ERROR("Size mismatch - expected: %lu, actual: %lu", expected_original_size, output_size);
        if (buffer)
            free(buffer);
        free(output_buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("decompress_file", 0);
        return 0;
    }
    if (output_size > 0)
    {
        DEBUG_TRACE("Writing decompressed data (%lu bytes)", output_size);
        if (fwrite(output_buffer, 1, output_size, out) != output_size)
        {
            fprintf(stderr, "\nERROR: Failed to write decompressed data to output file '%s'.\n", output_file);
            DEBUG_ERROR_MSG("Failed to write decompressed data");
            if (buffer)
                free(buffer);
            free(output_buffer);
            fclose(in);
            fclose(out);
            remove(output_file);
            DEBUG_FUNCTION_EXIT("decompress_file", 0);
            return 0;
        }
        DEBUG_TRACE_MSG("Decompressed data written successfully");
    }

    if (!quiet)
    {
        print_progress_bar(expected_original_size, expected_original_size, PROGRESS_WIDTH);
        printf("\n");
    }

    DEBUG_TRACE_MSG("Cleaning up buffers and files");
    if (buffer)
        free(buffer);
    free(output_buffer);
    fclose(in);
    fclose(out);

    DEBUG_INFO("Decompression completed successfully - output size: %lu bytes", expected_original_size);
    DEBUG_FUNCTION_EXIT_SIZE("decompress_file", expected_original_size);
    return expected_original_size;
}

unsigned long process_file(const char *input_file, const char *output_file,
                           const char *password, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long compressed_size = 0;
    unsigned long final_size = 0;
    unsigned long original_input_size = 0;

    DEBUG_FUNCTION_ENTER("process_file");
    DEBUG_INFO("Processing file (compress + encrypt) - input: '%s', output: '%s'",
               input_file, output_file);

    snprintf(temp_file, sizeof(temp_file), "%s.tmp_compress", output_file);
    temp_file[sizeof(temp_file) - 1] = '\0';
    DEBUG_TRACE("Temporary file for compression: '%s'", temp_file);

    if (!quiet)
    {
        print_section_header("File Processing");
        printf("Operation: Compress and Encrypt\n");
        printf("Input file: %s\n", input_file);
        printf("Output file: %s\n", output_file);
    }

    if (!quiet)
        printf("\n--- Compression Step ---\n");
    DEBUG_INFO_MSG("Starting compression step");
    compressed_size = compress_file(input_file, temp_file, quiet, &original_input_size);
    if (original_size_out)
        *original_size_out = original_input_size;
    DEBUG_INFO("Compression step completed - input: %lu bytes, compressed: %lu bytes",
               original_input_size, compressed_size);

    if (compressed_size == 0 && original_input_size > 0)
    {
        fprintf(stderr, "ERROR: Compression step failed for input '%s'.\n", input_file);
        DEBUG_ERROR_MSG("Compression step failed");
        remove(temp_file);
        DEBUG_FUNCTION_EXIT("process_file", 0);
        return 0;
    }
    if (!quiet)
        printf("\n--- Encryption Step ---\n");
    DEBUG_INFO_MSG("Starting encryption step");
    final_size = encrypt_file(temp_file, output_file, password, quiet, NULL);
    DEBUG_INFO("Encryption step completed - compressed: %lu bytes, final: %lu bytes",
               compressed_size, final_size);

    if (final_size == 0 && compressed_size > 0)
    {
        fprintf(stderr, "ERROR: Encryption step failed for temporary file '%s'.\n", temp_file);
        DEBUG_ERROR_MSG("Encryption step failed");
        remove(temp_file);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("process_file", 0);
        return 0;
    }

    DEBUG_TRACE("Removing temporary file: '%s'", temp_file);
    remove(temp_file);

    if (!quiet)
    {
        printf("\n");
        print_processing_summary("Process (Compress + Encrypt)", input_file, output_file,
                                 original_input_size, final_size);
        print_operation_result(0, "File processing (compress + encrypt)");
    }

    DEBUG_INFO("File processing completed successfully - original: %lu bytes, final: %lu bytes",
               original_input_size, final_size);
    DEBUG_FUNCTION_EXIT_SIZE("process_file", final_size);
    return final_size;
}

unsigned long extract_file(const char *input_file, const char *output_file,
                           const char *password, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long decrypted_size = 0;
    unsigned long final_size = 0;
    unsigned long original_input_size = 0;

    DEBUG_FUNCTION_ENTER("extract_file");
    DEBUG_INFO("Extracting file (decrypt + decompress) - input: '%s', output: '%s'",
               input_file, output_file);

    snprintf(temp_file, sizeof(temp_file), "%s.tmp_decrypt", output_file);
    temp_file[sizeof(temp_file) - 1] = '\0';
    DEBUG_TRACE("Temporary file for decryption: '%s'", temp_file);

    if (!quiet)
    {
        print_section_header("File Extraction");
        printf("Operation: Decrypt and Decompress\n");
        printf("Input file: %s\n", input_file);
        printf("Output file: %s\n", output_file);
    }

    if (!quiet)
        printf("\n--- Decryption Step ---\n");
    DEBUG_INFO_MSG("Starting decryption step");
    decrypted_size = decrypt_file(input_file, temp_file, password, quiet, &original_input_size);
    if (original_size_out)
        *original_size_out = original_input_size;
    DEBUG_INFO("Decryption step completed - input: %lu bytes, decrypted: %lu bytes",
               original_input_size, decrypted_size);

    if (decrypted_size == 0 && original_input_size > DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "ERROR: Decryption step failed for input '%s' (I/O or memory error).\n", input_file);
        DEBUG_ERROR_MSG("Decryption step failed");
        remove(temp_file);
        DEBUG_FUNCTION_EXIT("extract_file", 0);
        return 0;
    }

    if (!quiet)
        printf("\n--- Decompression Step ---\n");
    DEBUG_INFO_MSG("Starting decompression step");
    final_size = decompress_file(temp_file, output_file, quiet, NULL);
    DEBUG_INFO("Decompression step completed - compressed: %lu bytes, final: %lu bytes",
               decrypted_size, final_size);

    if (final_size == 0 && decrypted_size > sizeof(unsigned long))
    {
        fprintf(stderr, "ERROR: Decompression step failed for temporary file '%s'. Decrypted data might be corrupted.\n", temp_file);
        DEBUG_ERROR_MSG("Decompression step failed");
        remove(temp_file);
        remove(output_file);
        DEBUG_FUNCTION_EXIT("extract_file", 0);
        return 0;
    }

    DEBUG_TRACE("Removing temporary file: '%s'", temp_file);
    remove(temp_file);

    if (!quiet)
    {
        printf("\n");
        print_processing_summary("Extract (Decrypt+Decompress)", input_file, output_file,
                                 original_input_size, final_size);
        print_operation_result(0, "File extraction (decrypt + decompress)");
    }
    DEBUG_INFO("File extraction completed successfully - original: %lu bytes, final: %lu bytes",
               original_input_size, final_size);
    DEBUG_FUNCTION_EXIT_SIZE("extract_file", final_size);
    return final_size;
}

int handle_file_list(const char *command, const char *filename_pattern, int quiet)
{
    file_list_t file_list;
    file_entry_t *found_entry;

    DEBUG_FUNCTION_ENTER("handle_file_list");
    DEBUG_INFO("Handling file list command - command: '%s', pattern: '%s', quiet: %s",
               command, filename_pattern ? filename_pattern : "(null)", quiet ? "yes" : "no");

    file_list_init(&file_list);
    DEBUG_TRACE_MSG("File list structure initialised");

    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        DEBUG_INFO_MSG("Failed to load file list, initialising empty list");
        if (!quiet)
        {
            file_list_free(&file_list);
            file_list_init(&file_list);
        }
    }
    else
    {
        DEBUG_TRACE("File list loaded from: '%s'", DEFAULT_FILE_LIST);
    }

    if (strcmp(command, "list") == 0)
    {
        DEBUG_INFO_MSG("Processing 'list' command");
        if (!quiet)
            print_section_header("File Processing History");
        printf("Data source: %s\n\n", DEFAULT_FILE_LIST);
        file_list_print(&file_list);
        DEBUG_TRACE_MSG("File list printed successfully");
    }
    else if (strcmp(command, "find") == 0)
    {
        DEBUG_INFO("Processing 'find' command with pattern: '%s'", filename_pattern ? filename_pattern : "(null)");
        if (!filename_pattern || filename_pattern[0] == '\0')
        {
            fprintf(stderr, "ERROR: No search pattern specified.\n");
            DEBUG_ERROR_MSG("No search pattern specified for find command");
            file_list_free(&file_list);
            DEBUG_FUNCTION_EXIT("handle_file_list", -1);
            return -1;
        }

        if (!quiet)
        {
            print_section_header("File Search Results");
            printf("Search pattern: '%s'\n\n", filename_pattern);
        }

        found_entry = file_list_find(&file_list, filename_pattern);
        if (found_entry)
        {
            DEBUG_INFO("Found matching entry for pattern: '%s'", filename_pattern);
            printf("MATCH FOUND:\n");
            printf("Input file:     %s\n", found_entry->input_filename);
            printf("Output file:    %s\n", found_entry->output_filename);
            printf("Sequence ID:    %lu\n", found_entry->sequence_num);
            printf("Original size:  %lu bytes\n", found_entry->original_size);
            printf("Processed size: %lu bytes\n", found_entry->processed_size);
            if (found_entry->original_size > 0)
            {
                printf("Size ratio:     %.2f%%\n",
                       (float)found_entry->processed_size * 100.0f / found_entry->original_size);
            }
            else
            {
                printf("Size ratio:     N/A\n");
            }
        }
        else
        {
            DEBUG_INFO("No matching entry found for pattern: '%s'", filename_pattern);
            printf("NO MATCH: No files found matching pattern '%s'\n", filename_pattern);
        }
    }
    else
    {
        fprintf(stderr, "ERROR: Unknown internal file list command: %s\n", command);
        DEBUG_ERROR("Unknown file list command: '%s'", command);
        file_list_free(&file_list);
        DEBUG_FUNCTION_EXIT("handle_file_list", -1);
        return -1;
    }

    file_list_free(&file_list);
    DEBUG_TRACE_MSG("File list structure cleaned up");
    DEBUG_FUNCTION_EXIT("handle_file_list", 0);
    return 0;
}