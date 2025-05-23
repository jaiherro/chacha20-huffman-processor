/**
 * file_operations.c - Implementation of high-level file operations
 */

#include "operations/file_operations.h"
#include "compression/huffman.h"
#include "encryption/chacha20.h"
#include "encryption/key_derivation.h"
#include "utils/file_list.h"
#include "utils/ui.h"
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
    if (fseek(file, 0, SEEK_END) != 0)
        return -1;
    *size = ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0)
        return -1;
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
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    cleanup_crypto_buffers(buf1, buf2, ctx);
    if (failed && output_file)
    {
        remove(output_file);
    }
}

int add_entry_to_file_list(const char *input_file, const char *output_file, unsigned long original_size, unsigned long processed_size, int quiet)
{
    file_list_t file_list;
    file_list_init(&file_list);

    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        file_list_free(&file_list);
        file_list_init(&file_list);
    }

    if (file_list_add(&file_list, input_file, output_file, original_size, processed_size) != 0)
    {
        if (!quiet)
        {
            fprintf(stderr, "Warning: Failed to add entry '%s -> %s' to file list structure in memory.\n", input_file, output_file);
        }
        file_list_free(&file_list);
        return -1;
    }

    if (file_list_save(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        if (!quiet)
        {
            fprintf(stderr, "Warning: Failed to save updated file list to %s\n", DEFAULT_FILE_LIST);
        }
        file_list_free(&file_list);
        return -1;
    }

    file_list_free(&file_list);
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
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0;
    }

    if (get_file_size(in, &original_size) != 0)
    {
        fprintf(stderr, "Error: Could not determine size of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }

    if (original_size_out)
        *original_size_out = original_size;

    out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0;
    }

    // Generate and write salt
    if (generate_salt(salt, DEFAULT_SALT_SIZE) != 0)
    {
        fprintf(stderr, "Error: Failed to generate salt.\n");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        return 0;
    }

    if (fwrite(salt, 1, DEFAULT_SALT_SIZE, out) != DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "Error: Failed to write salt to output file '%s'.\n", output_file);
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        return 0;
    }
    final_output_size += DEFAULT_SALT_SIZE;

    // Derive key and nonce
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, KEY_DERIVATION_ITERATIONS,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0)
    {
        fprintf(stderr, "Error: Failed to derive key and nonce from password.\n");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        return 0;
    }

    // Initialise ChaCha20
    if (chacha20_init(&ctx, key, nonce, 1) != 0)
    {
        fprintf(stderr, "Error: Failed to initialise ChaCha20 context.\n");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        return 0;
    }

    // Write encrypted magic header to detect wrong password on decryption
    {
        unsigned char magic_plain[ENCRYPTION_MAGIC_LEN] = ENCRYPTION_MAGIC;
        unsigned char magic_cipher[ENCRYPTION_MAGIC_LEN];
        if (chacha20_process(&ctx, magic_plain, magic_cipher, ENCRYPTION_MAGIC_LEN) != 0)
        {
            fprintf(stderr, "Error: Failed to encrypt magic header.\n");
            cleanup_crypto_operation(in, out, NULL, NULL, &ctx, output_file, 1);
            return 0;
        }
        if (fwrite(magic_cipher, 1, ENCRYPTION_MAGIC_LEN, out) != ENCRYPTION_MAGIC_LEN)
        {
            fprintf(stderr, "Error: Failed to write magic header to output file '%s'.\n", output_file);
            cleanup_crypto_operation(in, out, NULL, NULL, &ctx, output_file, 1);
            return 0;
        }
        file_size += ENCRYPTION_MAGIC_LEN;
    }

    // Allocate buffers
    buffer = malloc(BUFFER_SIZE);
    output_buffer = malloc(BUFFER_SIZE);
    if (!buffer || !output_buffer)
    {
        fprintf(stderr, "Error: Memory allocation failed for buffers.\n");
        cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
        return 0;
    }

    if (!quiet)
    {
        printf("\nEncrypting file...\n");
        print_progress_bar(0, original_size, PROGRESS_WIDTH);
    }

    // Process file in chunks
    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0)
    {
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0)
        {
            fprintf(stderr, "\nError: ChaCha20 encryption failed during processing.\n");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            return 0;
        }

        if (fwrite(output_buffer, 1, read_size, out) != read_size)
        {
            fprintf(stderr, "\nError: Failed to write encrypted data to output file '%s'.\n", output_file);
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            return 0;
        }

        file_size += read_size;
        if (!quiet)
        {
            print_progress_bar(file_size, original_size, PROGRESS_WIDTH);
        }
    }

    if (ferror(in))
    {
        fprintf(stderr, "\nError: Failed reading from input file '%s'.\n", input_file);
        cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
        return 0;
    }

    final_output_size += file_size;

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
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0;
    }

    if (get_file_size(in, &total_input_size) != 0)
    {
        fprintf(stderr, "Error: Could not determine size of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }

    if (original_size_out)
        *original_size_out = total_input_size;

    if (total_input_size < MIN_ENCRYPTED_FILE_SIZE)
    {
        fprintf(stderr, "Error: Input file '%s' is too small (%lu bytes) to be valid encrypted data.\n",
                input_file, total_input_size);
        fclose(in);
        return 0;
    }

    out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0;
    }

    // Read salt
    if (fread(salt, 1, DEFAULT_SALT_SIZE, in) != DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "Error: Failed to read salt from input file '%s'.\n", input_file);
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        return 0;
    }

    // Derive key and nonce
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, KEY_DERIVATION_ITERATIONS,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0)
    {
        fprintf(stderr, "Error: Failed to derive key and nonce from password.\n");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        return 0;
    }

    // Initialise ChaCha20
    if (chacha20_init(&ctx, key, nonce, 1) != 0)
    {
        fprintf(stderr, "Error: Failed to initialise ChaCha20 context.\n");
        cleanup_crypto_operation(in, out, NULL, NULL, NULL, output_file, 1);
        return 0;
    }

    // Allocate buffers
    buffer = malloc(BUFFER_SIZE);
    output_buffer = malloc(BUFFER_SIZE);
    if (!buffer || !output_buffer)
    {
        fprintf(stderr, "Error: Memory allocation failed for buffers.\n");
        cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
        return 0;
    }

    // Verify encrypted magic header to detect wrong password
    data_to_decrypt_size = total_input_size - DEFAULT_SALT_SIZE;
    if (data_to_decrypt_size < ENCRYPTION_MAGIC_LEN)
    {
        fprintf(stderr, "Error: Encrypted file too small to contain magic header.\n");
        cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
        return 0;
    }
    {
        unsigned char magic_cipher[ENCRYPTION_MAGIC_LEN];
        unsigned char magic_plain[ENCRYPTION_MAGIC_LEN];
        if (fread(magic_cipher, 1, ENCRYPTION_MAGIC_LEN, in) != ENCRYPTION_MAGIC_LEN)
        {
            fprintf(stderr, "Error: Failed to read magic header from input file '%s'.\n", input_file);
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            return 0;
        }
        if (chacha20_process(&ctx, magic_cipher, magic_plain, ENCRYPTION_MAGIC_LEN) != 0)
        {
            fprintf(stderr, "Error: Failed to decrypt magic header.\n");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            return 0;
        }
        if (memcmp(magic_plain, ENCRYPTION_MAGIC, ENCRYPTION_MAGIC_LEN) != 0)
        {
            if (!quiet)
                fprintf(stderr, "Error: Incorrect password or corrupted file.\n");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            return 0;
        }
        // Reduce data to decrypt by magic header length
        data_to_decrypt_size -= ENCRYPTION_MAGIC_LEN;
    }

    if (!quiet)
    {
        printf("\nDecrypting file...\n");
        print_progress_bar(0, data_to_decrypt_size, PROGRESS_WIDTH);
    }

    // Decrypt file in chunks
    while (file_size < data_to_decrypt_size)
    {
        unsigned long chunk_size = (data_to_decrypt_size - file_size < BUFFER_SIZE) ? data_to_decrypt_size - file_size : BUFFER_SIZE;

        read_size = fread(buffer, 1, chunk_size, in);
        if (read_size == 0)
        {
            if (feof(in) && file_size < data_to_decrypt_size)
            {
                fprintf(stderr, "\nError: Unexpected end of file while reading encrypted data.\n");
            }
            else if (ferror(in))
            {
                fprintf(stderr, "\nError: File read error during decryption.\n");
            }
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            return 0;
        }

        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0)
        {
            fprintf(stderr, "\nError: ChaCha20 decryption failed during processing.\n");
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            return 0;
        }

        if (fwrite(output_buffer, 1, read_size, out) != read_size)
        {
            fprintf(stderr, "\nError: Failed to write decrypted data to output file '%s'.\n", output_file);
            cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, output_file, 1);
            return 0;
        }

        file_size += read_size;
        if (!quiet)
        {
            print_progress_bar(file_size, data_to_decrypt_size, PROGRESS_WIDTH);
        }
    }

    final_output_size = file_size;

    if (!quiet)
    {
        if (data_to_decrypt_size > 0)
        {
            print_progress_bar(data_to_decrypt_size, data_to_decrypt_size, PROGRESS_WIDTH);
        }
        printf("\n");
    }

    // Clean up successfully
    cleanup_crypto_operation(in, out, buffer, output_buffer, &ctx, NULL, 0);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    memset(salt, 0, DEFAULT_SALT_SIZE);

    return final_output_size;
}

unsigned long compress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buffer = NULL, *output_buffer = NULL;
    unsigned long read_size, output_size, total_input_size = 0;
    unsigned long total_output_size = 0;

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
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0;
    }

    if (get_file_size(in, &total_input_size) != 0)
    {
        fprintf(stderr, "Error: Could not determine size of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }

    if (original_size_out)
        *original_size_out = total_input_size;

    out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0;
    }

    // Write the original file size to the output file header
    if (fwrite(&total_input_size, sizeof(unsigned long), 1, out) != 1)
    {
        fprintf(stderr, "Error: Failed to write file size header to output file '%s'.\n", output_file);
        fclose(in);
        fclose(out);
        remove(output_file);
        return 0;
    }
    total_output_size += sizeof(unsigned long);

    if (total_input_size > 0)
    {
        buffer = malloc(total_input_size);
        if (!buffer)
        {
            fprintf(stderr, "Error: Memory allocation failed for input buffer (%lu bytes).\n", total_input_size);
            fclose(in);
            fclose(out);
            remove(output_file);
            return 0;
        }

        read_size = fread(buffer, 1, total_input_size, in);
        if (read_size != total_input_size || ferror(in))
        {
            fprintf(stderr, "Error: Failed to read entire input file '%s'.\n", input_file);
            free(buffer);
            fclose(in);
            fclose(out);
            remove(output_file);
            return 0;
        }
    }
    else
    {
        buffer = NULL;
        read_size = 0;
    }

    unsigned long output_max_len = huffman_worst_case_size(read_size);
    output_buffer = malloc(output_max_len > 0 ? output_max_len : 1);
    if (!output_buffer)
    {
        fprintf(stderr, "Error: Memory allocation failed for output buffer.\n");
        if (buffer)
            free(buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        return 0;
    }

    if (!quiet)
    {
        printf("\nCompressing file...\n");
        print_progress_bar(0, total_input_size, PROGRESS_WIDTH);
    }

    if (huffman_compress(buffer, read_size, output_buffer, output_max_len, &output_size) != 0)
    {
        fprintf(stderr, "\nError: Huffman compression failed.\n");
        if (buffer)
            free(buffer);
        free(output_buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        return 0;
    }

    if (output_size > 0)
    {
        if (fwrite(output_buffer, 1, output_size, out) != output_size)
        {
            fprintf(stderr, "\nError: Failed to write compressed data to output file '%s'.\n", output_file);
            if (buffer)
                free(buffer);
            free(output_buffer);
            fclose(in);
            fclose(out);
            remove(output_file);
            return 0;
        }
    }
    total_output_size += output_size;

    if (!quiet)
    {
        print_progress_bar(total_input_size, total_input_size, PROGRESS_WIDTH);
        printf("\n");
    }

    if (buffer)
        free(buffer);
    free(output_buffer);
    fclose(in);
    fclose(out);

    return total_output_size;
}

unsigned long decompress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buffer = NULL, *output_buffer = NULL;
    unsigned long compressed_data_size, output_size, expected_original_size = 0;
    unsigned long input_actual_file_size = 0;

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
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0;
    }

    if (get_file_size(in, &input_actual_file_size) != 0)
    {
        fprintf(stderr, "Error: Could not determine size of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }

    if (original_size_out)
        *original_size_out = input_actual_file_size;

    if (input_actual_file_size < MIN_COMPRESSED_FILE_SIZE)
    {
        fprintf(stderr, "Error: Input file '%s' is too small (%lu bytes) to contain header.\n",
                input_file, input_actual_file_size);
        fclose(in);
        return 0;
    }

    if (fread(&expected_original_size, sizeof(unsigned long), 1, in) != 1)
    {
        fprintf(stderr, "Error: Failed to read original file size header from input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }

    out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0;
    }

    compressed_data_size = input_actual_file_size - sizeof(unsigned long);

    if (compressed_data_size > 0)
    {
        buffer = malloc(compressed_data_size);
        if (!buffer)
        {
            fprintf(stderr, "Error: Memory allocation failed for compressed data buffer (%lu bytes).\n", compressed_data_size);
            fclose(in);
            fclose(out);
            remove(output_file);
            return 0;
        }

        if (fread(buffer, 1, compressed_data_size, in) != compressed_data_size || ferror(in))
        {
            fprintf(stderr, "Error: Failed to read compressed data from input file '%s'.\n", input_file);
            free(buffer);
            fclose(in);
            fclose(out);
            remove(output_file);
            return 0;
        }
    }
    else if (expected_original_size > 0)
    {
        fprintf(stderr, "Error: Compressed file format error - header indicates %lu original bytes, but no compressed data found.\n",
                expected_original_size);
        fclose(in);
        fclose(out);
        remove(output_file);
        return 0;
    }
    else
    {
        buffer = NULL;
    }

    output_buffer = malloc(expected_original_size > 0 ? expected_original_size : 1);
    if (!output_buffer)
    {
        fprintf(stderr, "Error: Memory allocation failed for output buffer (%lu bytes).\n", expected_original_size);
        if (buffer)
            free(buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        return 0;
    }

    if (!quiet)
    {
        printf("\nDecompressing file...\n");
        print_progress_bar(0, expected_original_size, PROGRESS_WIDTH);
    }

    if (huffman_decompress(buffer, compressed_data_size, output_buffer, expected_original_size, &output_size) != 0)
    {
        fprintf(stderr, "\nError: Huffman decompression failed. Input file might be corrupted or not compressed with this tool.\n");
        if (buffer)
            free(buffer);
        free(output_buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        return 0;
    }

    if (output_size != expected_original_size)
    {
        fprintf(stderr, "\nError: Decompressed size (%lu) does not match expected size from header (%lu). File might be corrupted.\n",
                output_size, expected_original_size);
        if (buffer)
            free(buffer);
        free(output_buffer);
        fclose(in);
        fclose(out);
        remove(output_file);
        return 0;
    }

    if (output_size > 0)
    {
        if (fwrite(output_buffer, 1, output_size, out) != output_size)
        {
            fprintf(stderr, "\nError: Failed to write decompressed data to output file '%s'.\n", output_file);
            if (buffer)
                free(buffer);
            free(output_buffer);
            fclose(in);
            fclose(out);
            remove(output_file);
            return 0;
        }
    }

    if (!quiet)
    {
        print_progress_bar(expected_original_size, expected_original_size, PROGRESS_WIDTH);
        printf("\n");
    }

    if (buffer)
        free(buffer);
    free(output_buffer);
    fclose(in);
    fclose(out);

    return expected_original_size;
}

unsigned long process_file(const char *input_file, const char *output_file,
                           const char *password, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long compressed_size = 0;
    unsigned long final_size = 0;
    unsigned long original_input_size = 0;

    snprintf(temp_file, sizeof(temp_file), "%s.tmp_compress", output_file);
    temp_file[sizeof(temp_file) - 1] = '\0';

    if (!quiet)
    {
        print_section_header("File Processing");
        printf("Operation: Compress and Encrypt\n");
        printf("Input file: %s\n", input_file);
        printf("Output file: %s\n", output_file);
    }

    if (!quiet)
        printf("\n--- Compression Step ---\n");
    compressed_size = compress_file(input_file, temp_file, quiet, &original_input_size);
    if (original_size_out)
        *original_size_out = original_input_size;

    if (compressed_size == 0 && original_input_size > 0)
    {
        fprintf(stderr, "Error: Compression step failed for input '%s'.\n", input_file);
        remove(temp_file);
        return 0;
    }

    if (!quiet)
        printf("\n--- Encryption Step ---\n");
    final_size = encrypt_file(temp_file, output_file, password, quiet, NULL);
    if (final_size == 0 && compressed_size > 0)
    {
        fprintf(stderr, "Error: Encryption step failed for temporary file '%s'.\n", temp_file);
        remove(temp_file);
        remove(output_file);
        return 0;
    }

    remove(temp_file);

    if (!quiet)
    {
        printf("\n");
        print_processing_summary("Process (Compress+Encrypt)", input_file, output_file,
                                 original_input_size, final_size);
        print_operation_result(0, "File processing (compress + encrypt)");
    }

    return final_size;
}

unsigned long extract_file(const char *input_file, const char *output_file,
                           const char *password, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long decrypted_size = 0;
    unsigned long final_size = 0;
    unsigned long original_input_size = 0;

    snprintf(temp_file, sizeof(temp_file), "%s.tmp_decrypt", output_file);
    temp_file[sizeof(temp_file) - 1] = '\0';

    if (!quiet)
    {
        print_section_header("File Extraction");
        printf("Operation: Decrypt and Decompress\n");
        printf("Input file: %s\n", input_file);
        printf("Output file: %s\n", output_file);
    }

    if (!quiet)
        printf("\n--- Decryption Step ---\n");
    decrypted_size = decrypt_file(input_file, temp_file, password, quiet, &original_input_size);
    if (original_size_out)
        *original_size_out = original_input_size;

    if (decrypted_size == 0 && original_input_size > DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "Error: Decryption step failed for input '%s' (I/O or memory error).\n", input_file);
        remove(temp_file);
        return 0;
    }

    if (!quiet)
        printf("\n--- Decompression Step ---\n");
    final_size = decompress_file(temp_file, output_file, quiet, NULL);
    if (final_size == 0 && decrypted_size > sizeof(unsigned long))
    {
        fprintf(stderr, "Error: Decompression step failed for temporary file '%s'. Decrypted data might be corrupted.\n", temp_file);
        remove(temp_file);
        remove(output_file);
        return 0;
    }

    remove(temp_file);

    if (!quiet)
    {
        printf("\n");
        print_processing_summary("Extract (Decrypt+Decompress)", input_file, output_file,
                                 original_input_size, final_size);
        print_operation_result(0, "File extraction (decrypt + decompress)");
    }

    return final_size;
}

int handle_file_list(const char *command, const char *filename_pattern, int quiet)
{
    file_list_t file_list;
    file_entry_t *found_entry;

    file_list_init(&file_list);

    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        if (!quiet)
        {
            file_list_free(&file_list);
            file_list_init(&file_list);
        }
    }

    if (strcmp(command, "list") == 0)
    {
        if (!quiet)
            print_section_header("File Processing History");
        printf("Data source: %s\n\n", DEFAULT_FILE_LIST);
        file_list_print(&file_list);
    }
    else if (strcmp(command, "find") == 0)
    {
        if (!filename_pattern || filename_pattern[0] == '\0')
        {
            fprintf(stderr, "ERROR: No search pattern specified.\n");
            file_list_free(&file_list);
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
            printf("NO MATCH: No files found matching pattern '%s'\n", filename_pattern);
        }
    }
    else
    {
        fprintf(stderr, "ERROR: Unknown internal file list command: %s\n", command);
        file_list_free(&file_list);
        return -1;
    }

    file_list_free(&file_list);
    return 0;
}
