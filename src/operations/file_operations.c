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

int add_entry_to_file_list(const char *output_file, unsigned long original_size, unsigned long processed_size, int quiet)
{
    file_list_t file_list;
    file_list_init(&file_list);

    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        file_list_free(&file_list); // Ensure clean state
        file_list_init(&file_list); // Re-initialise
    }

    if (file_list_add(&file_list, output_file, original_size, processed_size) != 0)
    {
        if (!quiet)
        {
            fprintf(stderr, "Warning: Failed to add entry '%s' to file list structure in memory.\n", output_file);
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
    unsigned long read_size, file_size = 0, original_size_val = 0;
    int result_flag = 0;
    unsigned long final_output_size = 0;

    if (!quiet)
    {
        print_section_header("File Encryption");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
    }

    in = fopen(input_file, "rb");
    if (in == NULL)
    {
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0;
    }

    if (fseek(in, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "Error: Could not seek to end of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    original_size_val = ftell(in);
    if (fseek(in, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "Error: Could not seek to start of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    if (original_size_out)
    {
        *original_size_out = original_size_val;
    }

    out = fopen(output_file, "wb");
    if (out == NULL)
    {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0;
    }

    if (generate_salt(salt, DEFAULT_SALT_SIZE) != 0)
    {
        fprintf(stderr, "Error: Failed to generate salt.\n");
        result_flag = -1;
        goto cleanup_encrypt;
    }

    if (fwrite(salt, 1, DEFAULT_SALT_SIZE, out) != DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "Error: Failed to write salt to output file '%s'.\n", output_file);
        result_flag = -1;
        goto cleanup_encrypt;
    }
    final_output_size += DEFAULT_SALT_SIZE;

    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, KEY_DERIVATION_ITERATIONS,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0)
    {
        fprintf(stderr, "Error: Failed to derive key and nonce from password.\n");
        result_flag = -1;
        goto cleanup_encrypt;
    }

    if (chacha20_init(&ctx, key, nonce, 1) != 0)
    {
        fprintf(stderr, "Error: Failed to initialise ChaCha20 context.\n");
        result_flag = -1;
        goto cleanup_encrypt;
    }

    buffer = (unsigned char *)malloc(BUFFER_SIZE);
    output_buffer = (unsigned char *)malloc(BUFFER_SIZE);

    if (buffer == NULL || output_buffer == NULL)
    {
        fprintf(stderr, "Error: Memory allocation failed for buffers.\n");
        result_flag = -1;
        goto cleanup_encrypt;
    }

    if (!quiet)
    {
        printf("\nEncrypting file...\n");
        print_progress_bar(0, original_size_val, PROGRESS_WIDTH);
    }

    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0)
    {
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0)
        {
            fprintf(stderr, "\nError: ChaCha20 encryption failed during processing.\n");
            result_flag = -1;
            goto cleanup_encrypt;
        }
        if (fwrite(output_buffer, 1, read_size, out) != read_size)
        {
            fprintf(stderr, "\nError: Failed to write encrypted data to output file '%s'.\n", output_file);
            result_flag = -1;
            goto cleanup_encrypt;
        }
        file_size += read_size;
        if (!quiet)
        {
            print_progress_bar(file_size, original_size_val, PROGRESS_WIDTH);
        }
    }

    if (ferror(in))
    {
        fprintf(stderr, "\nError: Failed reading from input file '%s'.\n", input_file);
        result_flag = -1;
        goto cleanup_encrypt;
    }
    final_output_size += file_size;

    if (!quiet)
    {
        if (result_flag == 0 && original_size_val > 0)
        {
            print_progress_bar(original_size_val, original_size_val, PROGRESS_WIDTH);
        }
        printf("\n");
    }

cleanup_encrypt:
    if (in != NULL)
        fclose(in);
    if (out != NULL)
        fclose(out);
    if (buffer != NULL)
    {
        memset(buffer, 0, BUFFER_SIZE);
        free(buffer);
    }
    if (output_buffer != NULL)
    {
        memset(output_buffer, 0, BUFFER_SIZE);
        free(output_buffer);
    }
    chacha20_cleanup(&ctx);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    memset(salt, 0, DEFAULT_SALT_SIZE);
    if (result_flag != 0 && output_file != NULL)
    {
        remove(output_file);
    }
    return (result_flag == 0) ? final_output_size : 0;
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
    int result_flag = 0;
    unsigned long final_output_size = 0;

    if (!quiet)
    {
        print_section_header("File Decryption");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
    }

    in = fopen(input_file, "rb");
    if (in == NULL)
    {
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0;
    }

    if (fseek(in, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "Error: Could not seek to end of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    total_input_size = ftell(in);
    if (fseek(in, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "Error: Could not seek to start of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    if (original_size_out)
    {
        *original_size_out = total_input_size;
    }

    if (total_input_size <= DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "Error: Input file '%s' is too small (%lu bytes) to be valid encrypted data.\n", input_file, total_input_size);
        fclose(in);
        return 0;
    }

    out = fopen(output_file, "wb");
    if (out == NULL)
    {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0;
    }

    if (fread(salt, 1, DEFAULT_SALT_SIZE, in) != DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "Error: Failed to read salt from input file '%s'.\n", input_file);
        result_flag = -2;
        goto cleanup_decrypt;
    }

    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, KEY_DERIVATION_ITERATIONS,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0)
    {
        fprintf(stderr, "Error: Failed to derive key and nonce from password.\n");
        result_flag = -2;
        goto cleanup_decrypt;
    }

    if (chacha20_init(&ctx, key, nonce, 1) != 0)
    {
        fprintf(stderr, "Error: Failed to initialise ChaCha20 context.\n");
        result_flag = -2;
        goto cleanup_decrypt;
    }

    buffer = (unsigned char *)malloc(BUFFER_SIZE);
    output_buffer = (unsigned char *)malloc(BUFFER_SIZE);
    if (buffer == NULL || output_buffer == NULL)
    {
        fprintf(stderr, "Error: Memory allocation failed for buffers.\n");
        result_flag = -2;
        goto cleanup_decrypt;
    }

    unsigned long data_to_decrypt_size = total_input_size - DEFAULT_SALT_SIZE;
    if (!quiet)
    {
        printf("\nDecrypting file...\n");
        print_progress_bar(0, data_to_decrypt_size, PROGRESS_WIDTH);
    }

    while (file_size < data_to_decrypt_size)
    {
        read_size = fread(buffer, 1, (data_to_decrypt_size - file_size < BUFFER_SIZE ? data_to_decrypt_size - file_size : BUFFER_SIZE), in);
        if (read_size == 0 && feof(in) && file_size < data_to_decrypt_size)
        {
            fprintf(stderr, "\nError: Unexpected end of file while reading encrypted data.\n");
            result_flag = -2;
            goto cleanup_decrypt;
        }
        if (read_size == 0 && ferror(in))
        {
            fprintf(stderr, "\nError: File read error during decryption.\n");
            result_flag = -2;
            goto cleanup_decrypt;
        }
        if (read_size == 0)
            break;

        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0)
        {
            fprintf(stderr, "\nError: ChaCha20 decryption failed during processing (internal error).\n");
            result_flag = -2;
            goto cleanup_decrypt;
        }
        if (fwrite(output_buffer, 1, read_size, out) != read_size)
        {
            fprintf(stderr, "\nError: Failed to write decrypted data to output file '%s'.\n", output_file);
            result_flag = -2;
            goto cleanup_decrypt;
        }
        file_size += read_size;
        if (!quiet)
        {
            print_progress_bar(file_size, data_to_decrypt_size, PROGRESS_WIDTH);
        }
    }

    if (ferror(in))
    {
        fprintf(stderr, "\nError: Failed reading from input file '%s'.\n", input_file);
        result_flag = -2;
        goto cleanup_decrypt;
    }
    final_output_size = file_size;

    if (!quiet)
    {
        if (result_flag == 0 && data_to_decrypt_size > 0)
        {
            print_progress_bar(data_to_decrypt_size, data_to_decrypt_size, PROGRESS_WIDTH);
        }
        printf("\n");
    }

cleanup_decrypt:
    if (in != NULL)
        fclose(in);
    if (out != NULL)
        fclose(out);
    if (buffer != NULL)
    {
        memset(buffer, 0, BUFFER_SIZE);
        free(buffer);
    }
    if (output_buffer != NULL)
    {
        memset(output_buffer, 0, BUFFER_SIZE);
        free(output_buffer);
    }
    chacha20_cleanup(&ctx);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    memset(salt, 0, DEFAULT_SALT_SIZE);
    if (result_flag == -2 && output_file != NULL)
    {
        remove(output_file);
        final_output_size = 0;
    }
    return (result_flag == -2) ? 0 : final_output_size;
}

unsigned long compress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buffer = NULL, *output_buffer = NULL;
    unsigned long read_size_val, output_size_val, total_input_size_val = 0;
    int result_flag = 0;
    unsigned long total_output_size_val = 0;

    if (!quiet)
    {
        print_section_header("File Compression");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
    }

    in = fopen(input_file, "rb");
    if (in == NULL)
    {
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0;
    }

    if (fseek(in, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "Error: Could not seek to end of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    total_input_size_val = ftell(in);
    if (fseek(in, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "Error: Could not seek to start of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    if (original_size_out)
    {
        *original_size_out = total_input_size_val;
    }

    out = fopen(output_file, "wb");
    if (out == NULL)
    {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0;
    }

    // Write the original file size to the output file header (as unsigned long)
    if (fwrite(&total_input_size_val, sizeof(unsigned long), 1, out) != 1)
    {
        fprintf(stderr, "Error: Failed to write file size header to output file '%s'.\n", output_file);
        result_flag = -1;
        goto cleanup_compress;
    }
    total_output_size_val += sizeof(unsigned long);

    if (total_input_size_val > 0)
    {
        buffer = (unsigned char *)malloc(total_input_size_val);
        if (buffer == NULL)
        {
            fprintf(stderr, "Error: Memory allocation failed for input buffer (%lu bytes).\n", total_input_size_val);
            result_flag = -1;
            goto cleanup_compress;
        }
        read_size_val = fread(buffer, 1, total_input_size_val, in);
        if (read_size_val != total_input_size_val || ferror(in))
        {
            fprintf(stderr, "Error: Failed to read entire input file '%s'.\n", input_file);
            result_flag = -1;
            goto cleanup_compress;
        }
    }
    else
    {
        buffer = NULL;
        read_size_val = 0;
    }

    unsigned long output_max_len_val = huffman_worst_case_size(read_size_val);
    output_buffer = (unsigned char *)malloc(output_max_len_val > 0 ? output_max_len_val : 1);
    if (output_buffer == NULL)
    {
        fprintf(stderr, "Error: Memory allocation failed for output buffer.\n");
        result_flag = -1;
        goto cleanup_compress;
    }

    if (!quiet)
    {
        printf("\nCompressing file...\n");
        print_progress_bar(0, total_input_size_val, PROGRESS_WIDTH);
    }

    if (huffman_compress(buffer, read_size_val, output_buffer,
                         output_max_len_val, &output_size_val) != 0)
    {
        fprintf(stderr, "\nError: Huffman compression failed.\n");
        result_flag = -1;
        goto cleanup_compress;
    }

    if (output_size_val > 0)
    {
        if (fwrite(output_buffer, 1, output_size_val, out) != output_size_val)
        {
            fprintf(stderr, "\nError: Failed to write compressed data to output file '%s'.\n", output_file);
            result_flag = -1;
            goto cleanup_compress;
        }
    }
    total_output_size_val += output_size_val;

    if (!quiet)
    {
        print_progress_bar(total_input_size_val, total_input_size_val, PROGRESS_WIDTH);
        printf("\n");
    }

cleanup_compress:
    if (in != NULL)
        fclose(in);
    if (out != NULL)
        fclose(out);
    if (buffer != NULL)
        free(buffer);
    if (output_buffer != NULL)
        free(output_buffer);
    if (result_flag != 0 && output_file != NULL)
    {
        remove(output_file);
    }
    return (result_flag == 0) ? total_output_size_val : 0;
}

unsigned long decompress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buffer = NULL, *output_buffer = NULL;
    unsigned long compressed_data_size, output_size_val, expected_original_size = 0;
    int result_flag = 0;
    unsigned long input_actual_file_size = 0;

    if (!quiet)
    {
        print_section_header("File Decompression");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
    }

    in = fopen(input_file, "rb");
    if (in == NULL)
    {
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0;
    }

    if (fseek(in, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "Error: Could not seek to end of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    input_actual_file_size = ftell(in);
    if (fseek(in, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "Error: Could not seek to start of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    if (original_size_out)
    {
        *original_size_out = input_actual_file_size;
    }

    if (input_actual_file_size < sizeof(unsigned long))
    {
        fprintf(stderr, "Error: Input file '%s' is too small (%lu bytes) to contain header.\n", input_file, input_actual_file_size);
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
    if (out == NULL)
    {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0;
    }

    compressed_data_size = input_actual_file_size - sizeof(unsigned long);
    if (compressed_data_size > 0)
    {
        buffer = (unsigned char *)malloc(compressed_data_size);
        if (buffer == NULL)
        {
            fprintf(stderr, "Error: Memory allocation failed for compressed data buffer (%lu bytes).\n", compressed_data_size);
            result_flag = -1;
            goto cleanup_decompress;
        }
        if (fread(buffer, 1, compressed_data_size, in) != compressed_data_size || ferror(in))
        {
            fprintf(stderr, "Error: Failed to read compressed data from input file '%s'.\n", input_file);
            result_flag = -1;
            goto cleanup_decompress;
        }
    }
    else if (expected_original_size > 0)
    {
        fprintf(stderr, "Error: Compressed file format error - header indicates %lu original bytes, but no compressed data found.\n", expected_original_size);
        result_flag = -1;
        goto cleanup_decompress;
    }
    else
    {
        buffer = NULL;
    }

    output_buffer = (unsigned char *)malloc(expected_original_size > 0 ? expected_original_size : 1);
    if (output_buffer == NULL)
    {
        fprintf(stderr, "Error: Memory allocation failed for output buffer (%lu bytes).\n", expected_original_size);
        result_flag = -1;
        goto cleanup_decompress;
    }

    if (!quiet)
    {
        printf("\nDecompressing file...\n");
        print_progress_bar(0, expected_original_size, PROGRESS_WIDTH);
    }

    if (huffman_decompress(buffer, compressed_data_size, output_buffer, expected_original_size, &output_size_val) != 0)
    {
        fprintf(stderr, "\nError: Huffman decompression failed. Input file might be corrupted or not compressed with this tool.\n");
        result_flag = -1;
        goto cleanup_decompress;
    }

    if (output_size_val != expected_original_size)
    {
        fprintf(stderr, "\nError: Decompressed size (%lu) does not match expected size from header (%lu). File might be corrupted.\n", output_size_val, expected_original_size);
        result_flag = -1;
        goto cleanup_decompress;
    }

    if (output_size_val > 0)
    {
        if (fwrite(output_buffer, 1, output_size_val, out) != output_size_val)
        {
            fprintf(stderr, "\nError: Failed to write decompressed data to output file '%s'.\n", output_file);
            result_flag = -1;
            goto cleanup_decompress;
        }
    }

    if (!quiet)
    {
        print_progress_bar(expected_original_size, expected_original_size, PROGRESS_WIDTH);
        printf("\n");
    }

cleanup_decompress:
    if (in != NULL)
        fclose(in);
    if (out != NULL)
        fclose(out);
    if (buffer != NULL)
        free(buffer);
    if (output_buffer != NULL)
        free(output_buffer);
    if (result_flag != 0 && output_file != NULL)
    {
        remove(output_file);
    }
    return (result_flag == 0) ? expected_original_size : 0;
}

unsigned long process_file(const char *input_file, const char *output_file,
                           const char *password, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long compressed_size_val = 0;
    unsigned long final_size_val = 0;
    unsigned long original_input_size_val = 0;

    snprintf(temp_file, sizeof(temp_file), "%s.tmp_compress", output_file);
    temp_file[sizeof(temp_file) - 1] = '\0';

    if (!quiet)
    {
        print_section_header("File Processing (Compress + Encrypt)");
    }

    if (!quiet)
        printf("\n--- Compression Step ---\n");
    compressed_size_val = compress_file(input_file, temp_file, quiet, &original_input_size_val);
    if (original_size_out)
    {
        *original_size_out = original_input_size_val;
    }
    if (compressed_size_val == 0 && original_input_size_val > 0)
    {
        fprintf(stderr, "Error: Compression step failed for input '%s'.\n", input_file);
        remove(temp_file);
        return 0;
    }

    if (!quiet)
        printf("\n--- Encryption Step ---\n");
    final_size_val = encrypt_file(temp_file, output_file, password, quiet, NULL);
    if (final_size_val == 0 && compressed_size_val > 0)
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
                                 original_input_size_val, final_size_val);
        print_operation_result(0, "File processing (compress + encrypt)");
    }
    return final_size_val;
}

unsigned long extract_file(const char *input_file, const char *output_file,
                           const char *password, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long decrypted_size_val = 0;
    unsigned long final_size_val = 0;
    unsigned long original_input_size_val = 0;

    snprintf(temp_file, sizeof(temp_file), "%s.tmp_decrypt", output_file);
    temp_file[sizeof(temp_file) - 1] = '\0';

    if (!quiet)
    {
        print_section_header("File Extraction (Decrypt + Decompress)");
    }

    if (!quiet)
        printf("\n--- Decryption Step ---\n");
    decrypted_size_val = decrypt_file(input_file, temp_file, password, quiet, &original_input_size_val);
    if (original_size_out)
    {
        *original_size_out = original_input_size_val;
    }
    if (decrypted_size_val == 0 && original_input_size_val > DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "Error: Decryption step failed for input '%s' (I/O or memory error).\n", input_file);
        remove(temp_file);
        return 0;
    }

    if (!quiet)
        printf("\n--- Decompression Step ---\n");
    final_size_val = decompress_file(temp_file, output_file, quiet, NULL);
    if (final_size_val == 0 && decrypted_size_val > sizeof(unsigned long))
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
                                 original_input_size_val, final_size_val);
        print_operation_result(0, "File extraction (decrypt + decompress)");
    }
    return final_size_val;
}

int handle_file_list(const char *command, const char *filename_pattern, int quiet)
{
    file_list_t file_list;
    file_entry_t *found_entry;
    int op_result = 0;

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
            print_section_header("File List Contents");
        printf("Source: %s\n", DEFAULT_FILE_LIST);
        file_list_print(&file_list);
    }
    else if (strcmp(command, "find") == 0)
    {
        if (filename_pattern == NULL || filename_pattern[0] == '\0')
        {
            fprintf(stderr, "Error: No filename pattern specified for find command.\n");
            op_result = -1;
        }
        else
        {
            if (!quiet)
            {
                print_section_header("File Search");
                printf("Pattern: '%s'\n\n", filename_pattern);
            }
            found_entry = file_list_find(&file_list, filename_pattern);
            if (found_entry)
            {
                printf("Found matching file:\n");
                printf("--> Filename: %s\n", found_entry->filename);
                printf("    Sequence: #%lu\n", found_entry->sequence_num);
                printf("    Original size: %lu bytes\n", found_entry->original_size);
                printf("    Processed size: %lu bytes\n", found_entry->processed_size);
                if (found_entry->original_size > 0)
                {
                    printf("    Compression ratio: %.2f%%\n",
                           (float)found_entry->processed_size * 100.0f / found_entry->original_size);
                }
                else
                {
                    printf("    Compression ratio: N/A\n");
                }
            }
            else
            {
                printf("No matching file found in the list for pattern '%s'.\n", filename_pattern);
            }
        }
    }
    else
    {
        fprintf(stderr, "Error: Unknown internal file list command: %s\n", command);
        op_result = -1;
    }

    file_list_free(&file_list);
    return op_result;
}