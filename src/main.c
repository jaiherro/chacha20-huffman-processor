/**
 * main.c - Secure File Processor with ChaCha20 encryption and Huffman compression
 *
 * This program provides:
 * 1. ChaCha20 encryption/decryption (RFC 8439)
 * 2. Huffman compression/decompression
 * 3. Password-based key derivation
 * 4. File tracking using linked lists
 *
 * Only uses standard C libraries: stdio.h, stdlib.h, string.h, math.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "operations/file_operations.h"
#include "operations/batch.h"
#include "utils/ui.h"
#include "utils/password.h"
#include "utils/filesystem.h"

/* Program modes */
#define MODE_COMPRESS 1   /* Compress a file */
#define MODE_DECOMPRESS 2 /* Decompress a file */
#define MODE_ENCRYPT 3    /* Encrypt a file */
#define MODE_DECRYPT 4    /* Decrypt a file */
#define MODE_PROCESS 5    /* Process (compress+encrypt) a file */
#define MODE_EXTRACT 6    /* Extract (decrypt+decompress) a file */
#define MODE_LIST 7       /* List processed files */
#define MODE_FIND 8       /* Find a file in the list */
#define MODE_BATCH 9      /* Batch process multiple files */
#define MODE_HELP 10      /* Show help information */

int main(int argc, char *argv[])
{
    int operation_mode = MODE_HELP;
    char *input_file_arg = NULL, *output_file_arg = NULL;
    char current_password[MAX_PASSWORD];
    int quiet_operation = 0;
    char *batch_input_files[MAX_BATCH_FILES];
    int num_batch_input_files = 0;
    char *batch_output_dir = DEFAULT_OUTPUT_DIR;
    int final_result = 0;
    unsigned long original_op_size = 0, processed_op_size = 0;

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    /* Parse the main mode */
    if (strcmp(argv[1], "-e") == 0)
    {
        operation_mode = MODE_ENCRYPT;
    }
    else if (strcmp(argv[1], "-d") == 0)
    {
        operation_mode = MODE_DECRYPT;
    }
    else if (strcmp(argv[1], "-c") == 0)
    {
        operation_mode = MODE_COMPRESS;
    }
    else if (strcmp(argv[1], "-x") == 0)
    {
        operation_mode = MODE_DECOMPRESS;
    }
    else if (strcmp(argv[1], "-p") == 0)
    {
        operation_mode = MODE_PROCESS;
    }
    else if (strcmp(argv[1], "-u") == 0)
    {
        operation_mode = MODE_EXTRACT;
    }
    else if (strcmp(argv[1], "-l") == 0)
    {
        operation_mode = MODE_LIST;
    }
    else if (strcmp(argv[1], "-f") == 0)
    {
        operation_mode = MODE_FIND;
    }
    else if (strcmp(argv[1], "-b") == 0)
    {
        operation_mode = MODE_BATCH;
    }
    else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
    {
        operation_mode = MODE_HELP;
    }
    else
    {
        fprintf(stderr, "Error: Unknown mode or option: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    /* Parse mode-specific arguments */
    int arg_parse_index = 2;

    switch (operation_mode)
    {
    case MODE_COMPRESS:
    case MODE_DECOMPRESS:
    case MODE_ENCRYPT:
    case MODE_DECRYPT:
    case MODE_PROCESS:
    case MODE_EXTRACT:
        if (argc < 4)
        {
            fprintf(stderr, "Error: Missing <input> and <output> file arguments for mode '%s'.\n", argv[1]);
            print_usage(argv[0]);
            return 1;
        }
        input_file_arg = argv[2];
        output_file_arg = argv[3];
        arg_parse_index = 4;
        break;
    case MODE_FIND:
        if (argc < 3)
        {
            fprintf(stderr, "Error: Missing <pattern> argument for find mode '-f'.\n");
            print_usage(argv[0]);
            return 1;
        }
        input_file_arg = argv[2];
        arg_parse_index = 3;
        break;
    case MODE_BATCH:
        if (argc < 4)
        {
            fprintf(stderr, "Error: Missing <outdir> and at least one <file> argument for batch mode '-b'.\n");
            print_usage(argv[0]);
            return 1;
        }
        batch_output_dir = argv[2];
        arg_parse_index = 3;
        break;
    case MODE_LIST:
    case MODE_HELP:
        arg_parse_index = 2;
        break;
    }

    /* Parse optional arguments */
    for (int i = arg_parse_index; i < argc; i++)
    {
        if (strcmp(argv[i], "-q") == 0)
        {
            quiet_operation = 1;
        }
        else if (operation_mode == MODE_BATCH)
        {
            if (num_batch_input_files < MAX_BATCH_FILES)
            {
                batch_input_files[num_batch_input_files++] = argv[i];
            }
            else
            {
                if (!quiet_operation)
                {
                    fprintf(stderr, "Warning: Exceeded maximum number of batch files (%d). Ignoring '%s' and subsequent files.\n", MAX_BATCH_FILES, argv[i]);
                }
                break;
            }
        }
        else
        {
            fprintf(stderr, "Error: Unknown option or unexpected argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Validate batch mode arguments */
    if (operation_mode == MODE_BATCH && num_batch_input_files == 0)
    {
        fprintf(stderr, "Error: No input files specified after <outdir> for batch mode '-b'.\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Execute the selected operation */
    switch (operation_mode)
    {
    case MODE_COMPRESS:
        if (!file_exists(input_file_arg))
        {
            fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file_arg);
            return 1;
        }
        processed_op_size = compress_file(input_file_arg, output_file_arg, quiet_operation, &original_op_size);
        if (processed_op_size > 0 || original_op_size == 0)
        {
            final_result = 0;
            if (add_entry_to_file_list(output_file_arg, original_op_size, processed_op_size, quiet_operation) != 0)
            { /* Warning already printed by helper */
            }
        }
        else
        {
            final_result = 1;
        }
        break;

    case MODE_DECOMPRESS:
        if (!file_exists(input_file_arg))
        {
            fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file_arg);
            return 1;
        }
        processed_op_size = decompress_file(input_file_arg, output_file_arg, quiet_operation, &original_op_size);
        if (processed_op_size == 0 && original_op_size > sizeof(unsigned long))
        {
            final_result = 1;
            if (!quiet_operation)
                fprintf(stderr, "Decompression failed (corrupted file or I/O error).\n");
        }
        else
        {
            final_result = 0;
        }
        break;

    case MODE_ENCRYPT:
        if (get_password(current_password, sizeof(current_password), 1) != 0)
            return 1;
        if (!file_exists(input_file_arg))
        {
            fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file_arg);
            memset(current_password, 0, sizeof(current_password));
            return 1;
        }
        processed_op_size = encrypt_file(input_file_arg, output_file_arg, current_password, quiet_operation, &original_op_size);
        memset(current_password, 0, sizeof(current_password));
        if (processed_op_size > 0)
        {
            final_result = 0;
            if (add_entry_to_file_list(output_file_arg, original_op_size, processed_op_size, quiet_operation) != 0)
            { /* Warning already printed by helper */
            }
        }
        else
        {
            final_result = 1;
        }
        break;

    case MODE_DECRYPT:
        if (get_password(current_password, sizeof(current_password), 0) != 0)
            return 1;
        if (!file_exists(input_file_arg))
        {
            fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file_arg);
            memset(current_password, 0, sizeof(current_password));
            return 1;
        }
        processed_op_size = decrypt_file(input_file_arg, output_file_arg, current_password, quiet_operation, &original_op_size);
        memset(current_password, 0, sizeof(current_password));
        if (processed_op_size == 0 && original_op_size > DEFAULT_SALT_SIZE)
        {
            final_result = 1;
            if (!quiet_operation)
                fprintf(stderr, "Decryption failed (I/O error or file too small).\n");
        }
        else
        {
            final_result = 0;
        }
        break;

    case MODE_PROCESS:
        if (get_password(current_password, sizeof(current_password), 1) != 0)
            return 1;
        if (!file_exists(input_file_arg))
        {
            fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file_arg);
            memset(current_password, 0, sizeof(current_password));
            return 1;
        }
        processed_op_size = process_file(input_file_arg, output_file_arg, current_password, quiet_operation, &original_op_size);
        memset(current_password, 0, sizeof(current_password));
        if (processed_op_size > 0)
        {
            final_result = 0;
            if (add_entry_to_file_list(output_file_arg, original_op_size, processed_op_size, quiet_operation) != 0)
            { /* Warning already printed by helper */
            }
        }
        else
        {
            final_result = 1;
        }
        break;

    case MODE_EXTRACT:
        if (get_password(current_password, sizeof(current_password), 0) != 0)
            return 1;
        if (!file_exists(input_file_arg))
        {
            fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file_arg);
            memset(current_password, 0, sizeof(current_password));
            return 1;
        }
        processed_op_size = extract_file(input_file_arg, output_file_arg, current_password, quiet_operation, &original_op_size);
        memset(current_password, 0, sizeof(current_password));
        if (processed_op_size == 0 && original_op_size > DEFAULT_SALT_SIZE + sizeof(unsigned long))
        {
            final_result = 1;
            if (!quiet_operation)
                fprintf(stderr, "Extraction failed (decryption or decompression error).\n");
        }
        else
        {
            final_result = 0;
        }
        break;

    case MODE_LIST:
        final_result = handle_file_list("list", NULL, quiet_operation);
        break;

    case MODE_FIND:
        final_result = handle_file_list("find", input_file_arg, quiet_operation);
        break;

    case MODE_BATCH:
        if (get_password(current_password, sizeof(current_password), 1) != 0)
            return 1;
        final_result = batch_process(batch_input_files, num_batch_input_files, batch_output_dir, current_password, quiet_operation);
        memset(current_password, 0, sizeof(current_password));
        break;

    case MODE_HELP:
    default:
        print_usage(argv[0]);
        final_result = (operation_mode == MODE_HELP) ? 0 : 1;
        break;
    }

    return (final_result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
