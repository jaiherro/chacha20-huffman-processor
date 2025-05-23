/**
 * main.c - Secure File Processor with ChaCha20 encryption and Huffman compression
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
#define MODE_COMPRESS 1
#define MODE_DECOMPRESS 2
#define MODE_ENCRYPT 3
#define MODE_DECRYPT 4
#define MODE_PROCESS 5
#define MODE_EXTRACT 6
#define MODE_LIST 7
#define MODE_FIND 8
#define MODE_BATCH 9
#define MODE_HELP 10

/* Operation handler function prototypes */
static int handle_compression_operation(int mode, const char *input_file, const char *output_file, int quiet);
static int handle_crypto_operation(int mode, const char *input_file, const char *output_file, int quiet);
static int handle_batch_operation(char *input_files[], int num_files, const char *output_dir, int quiet);
static int parse_command_line(int argc, char *argv[], int *mode, char **input_file, char **output_file,
                              char **batch_output_dir, char batch_input_files[][MAX_FILENAME],
                              int *num_batch_files, int *quiet);
static int validate_file_input(const char *filename);

/* Helper function implementations */
static int validate_file_input(const char *filename)
{
    if (!file_exists(filename))
    {
        fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", filename);
        return -1;
    }
    return 0;
}

static int handle_compression_operation(int mode, const char *input_file, const char *output_file, int quiet)
{
    unsigned long original_size, processed_size;

    if (validate_file_input(input_file) != 0)
        return 1;

    if (mode == MODE_COMPRESS)
    {
        processed_size = compress_file(input_file, output_file, quiet, &original_size);
        if (processed_size > 0 || original_size == 0)
        {
            add_entry_to_file_list(input_file, output_file, original_size, processed_size, quiet);
            return 0;
        }
        return 1;
    }
    else if (mode == MODE_DECOMPRESS)
    {
        processed_size = decompress_file(input_file, output_file, quiet, &original_size);
        if (processed_size == 0 && original_size > sizeof(unsigned long))
        {
            if (!quiet)
                fprintf(stderr, "Decompression failed (corrupted file or I/O error).\n");
            return 1;
        }
        return 0;
    }

    return 1;
}

static int handle_crypto_operation(int mode, const char *input_file, const char *output_file, int quiet)
{
    char password[MAX_PASSWORD];
    unsigned long original_size, processed_size;
    int password_confirm = (mode == MODE_ENCRYPT || mode == MODE_PROCESS);

    if (get_password(password, sizeof(password), password_confirm) != 0)
        return 1;

    if (validate_file_input(input_file) != 0)
    {
        memset(password, 0, sizeof(password));
        return 1;
    }

    switch (mode)
    {
    case MODE_ENCRYPT:
        processed_size = encrypt_file(input_file, output_file, password, quiet, &original_size);
        if (processed_size > 0)
        {
            add_entry_to_file_list(input_file, output_file, original_size, processed_size, quiet);
            memset(password, 0, sizeof(password));
            return 0;
        }
        break;

    case MODE_DECRYPT:
        processed_size = decrypt_file(input_file, output_file, password, quiet, &original_size);
        if (processed_size == 0 && original_size > DEFAULT_SALT_SIZE)
        {
            if (!quiet)
                fprintf(stderr, "Decryption failed (I/O error or file too small).\n");
            memset(password, 0, sizeof(password));
            return 1;
        }
        memset(password, 0, sizeof(password));
        return 0;

    case MODE_PROCESS:
        processed_size = process_file(input_file, output_file, password, quiet, &original_size);
        if (processed_size > 0)
        {
            add_entry_to_file_list(input_file, output_file, original_size, processed_size, quiet);
            memset(password, 0, sizeof(password));
            return 0;
        }
        break;

    case MODE_EXTRACT:
        processed_size = extract_file(input_file, output_file, password, quiet, &original_size);
        if (processed_size == 0 && original_size > DEFAULT_SALT_SIZE + sizeof(unsigned long))
        {
            if (!quiet)
                fprintf(stderr, "Extraction failed (decryption or decompression error).\n");
            memset(password, 0, sizeof(password));
            return 1;
        }
        memset(password, 0, sizeof(password));
        return 0;
    }

    memset(password, 0, sizeof(password));
    return 1;
}

static int handle_batch_operation(char *input_files[], int num_files, const char *output_dir, int quiet)
{
    char password[MAX_PASSWORD];
    int result;

    if (get_password(password, sizeof(password), 1) != 0)
        return 1;

    result = batch_process(input_files, num_files, output_dir, password, quiet);
    memset(password, 0, sizeof(password));

    return result;
}

static int parse_command_line(int argc, char *argv[], int *mode, char **input_file, char **output_file,
                              char **batch_output_dir, char batch_input_files[][MAX_FILENAME],
                              int *num_batch_files, int *quiet)
{
    *mode = MODE_HELP;
    *input_file = NULL;
    *output_file = NULL;
    *batch_output_dir = DEFAULT_OUTPUT_DIR;
    *num_batch_files = 0;
    *quiet = 0;

    if (argc < 2)
        return 0;

    /* Parse the main mode */
    if (strcmp(argv[1], "-e") == 0)
        *mode = MODE_ENCRYPT;
    else if (strcmp(argv[1], "-d") == 0)
        *mode = MODE_DECRYPT;
    else if (strcmp(argv[1], "-c") == 0)
        *mode = MODE_COMPRESS;
    else if (strcmp(argv[1], "-x") == 0)
        *mode = MODE_DECOMPRESS;
    else if (strcmp(argv[1], "-p") == 0)
        *mode = MODE_PROCESS;
    else if (strcmp(argv[1], "-u") == 0)
        *mode = MODE_EXTRACT;
    else if (strcmp(argv[1], "-l") == 0)
        *mode = MODE_LIST;
    else if (strcmp(argv[1], "-f") == 0)
        *mode = MODE_FIND;
    else if (strcmp(argv[1], "-b") == 0)
        *mode = MODE_BATCH;
    else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
        *mode = MODE_HELP;
    else
    {
        fprintf(stderr, "Error: Unknown mode or option: %s\n", argv[1]);
        return -1;
    }

    /* Parse mode-specific arguments */
    int arg_index = 2;

    switch (*mode)
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
            return -1;
        }
        *input_file = argv[2];
        *output_file = argv[3];
        arg_index = 4;
        break;

    case MODE_FIND:
        if (argc < 3)
        {
            fprintf(stderr, "Error: Missing <pattern> argument for find mode '-f'.\n");
            return -1;
        }
        *input_file = argv[2];
        arg_index = 3;
        break;

    case MODE_BATCH:
        if (argc < 4)
        {
            fprintf(stderr, "Error: Missing <outdir> and at least one <file> argument for batch mode '-b'.\n");
            return -1;
        }
        *batch_output_dir = argv[2];
        arg_index = 3;
        break;

    case MODE_LIST:
    case MODE_HELP:
        arg_index = 2;
        break;
    }

    /* Parse optional arguments */
    for (int i = arg_index; i < argc; i++)
    {
        if (strcmp(argv[i], "-q") == 0)
        {
            *quiet = 1;
        }
        else if (*mode == MODE_BATCH)
        {
            if (*num_batch_files < MAX_BATCH_FILES)
            {
                strncpy(batch_input_files[*num_batch_files], argv[i], MAX_FILENAME - 1);
                batch_input_files[*num_batch_files][MAX_FILENAME - 1] = '\0';
                (*num_batch_files)++;
            }
            else
            {
                if (!*quiet)
                {
                    fprintf(stderr, "Warning: Exceeded maximum number of batch files (%d). Ignoring '%s' and subsequent files.\n",
                            MAX_BATCH_FILES, argv[i]);
                }
                break;
            }
        }
        else
        {
            fprintf(stderr, "Error: Unknown option or unexpected argument: %s\n", argv[i]);
            return -1;
        }
    }

    /* Validate batch mode arguments */
    if (*mode == MODE_BATCH && *num_batch_files == 0)
    {
        fprintf(stderr, "Error: No input files specified after <outdir> for batch mode '-b'.\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int operation_mode;
    char *input_file_arg = NULL, *output_file_arg = NULL;
    char *batch_output_dir = NULL;
    char batch_input_files[MAX_BATCH_FILES][MAX_FILENAME];
    int num_batch_input_files = 0;
    int quiet_operation = 0;
    int result = 0;

    /* Parse command line arguments */
    if (parse_command_line(argc, argv, &operation_mode, &input_file_arg, &output_file_arg,
                           &batch_output_dir, batch_input_files, &num_batch_input_files,
                           &quiet_operation) != 0)
    {
        print_usage(argv[0]);
        return 1;
    }

    /* Execute the selected operation */
    switch (operation_mode)
    {
    case MODE_COMPRESS:
    case MODE_DECOMPRESS:
        result = handle_compression_operation(operation_mode, input_file_arg, output_file_arg, quiet_operation);
        break;

    case MODE_ENCRYPT:
    case MODE_DECRYPT:
    case MODE_PROCESS:
    case MODE_EXTRACT:
        result = handle_crypto_operation(operation_mode, input_file_arg, output_file_arg, quiet_operation);
        break;

    case MODE_LIST:
        result = handle_file_list("list", NULL, quiet_operation);
        break;

    case MODE_FIND:
        result = handle_file_list("find", input_file_arg, quiet_operation);
        break;

    case MODE_BATCH:
    {
        char *batch_file_ptrs[MAX_BATCH_FILES];
        for (int i = 0; i < num_batch_input_files; i++)
        {
            batch_file_ptrs[i] = batch_input_files[i];
        }
        result = handle_batch_operation(batch_file_ptrs, num_batch_input_files, batch_output_dir, quiet_operation);
    }
    break;

    case MODE_HELP:
    default:
        print_usage(argv[0]);
        result = (operation_mode == MODE_HELP) ? 0 : 1;
        break;
    }

    return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
