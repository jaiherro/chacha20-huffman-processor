/*
 * Group Members: Ethan Hall, Jai Herro
 * Group: 01
 * Lab: 06
 *
 * Dependencies: Standard C libraries only (stdio, stdlib, string, math)
 * C Standard: C99
 * 
 * Built by: Ethan Hall and Jai Herro
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "operations/file_operations.h"
#include "operations/batch.h"
#include "utils/ui.h"
#include "utils/password.h"
#include "utils/filesystem.h"
#include "utils/debug.h"

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
                              int *num_batch_files, int *quiet, int *debug);
static int validate_file_input(const char *filename);

/* Helper function implementations */
static int validate_file_input(const char *filename)
{
    if (!file_exists(filename))
    {
        fprintf(stderr, "ERROR: Input file '%s' does not exist or cannot be accessed.\n", filename);
        return -1;
    }
    return 0;
}

static int handle_compression_operation(int mode, const char *input_file, const char *output_file, int quiet)
{
    unsigned long original_size, processed_size;

    DEBUG_FUNCTION_ENTER("handle_compression_operation");
    DEBUG_INFO("Compression operation - mode: %s, input: '%s', output: '%s', quiet: %s",
               (mode == MODE_COMPRESS) ? "COMPRESS" : "DECOMPRESS",
               input_file, output_file, quiet ? "yes" : "no");

    if (validate_file_input(input_file) != 0)
    {
        DEBUG_ERROR("File validation failed for input: '%s'", input_file);
        DEBUG_FUNCTION_EXIT("handle_compression_operation", 1);
        return 1;
    }

    if (mode == MODE_COMPRESS)
    {
        DEBUG_TRACE("Starting file compression: %s", "begin");
        processed_size = compress_file(input_file, output_file, quiet, &original_size);
        DEBUG_INFO("Compression result - original: %lu bytes, compressed: %lu bytes",
                   original_size, processed_size);

        if (processed_size > 0 || original_size == 0)
        {
            add_entry_to_file_list(input_file, output_file, original_size, processed_size, quiet);
            DEBUG_FUNCTION_EXIT("handle_compression_operation", 0);
            return 0;
        }
        DEBUG_ERROR("Compression failed: %s", "error");
        DEBUG_FUNCTION_EXIT("handle_compression_operation", 1);
        return 1;
    }
    else if (mode == MODE_DECOMPRESS)
    {
        DEBUG_TRACE("Starting file decompression: %s", "begin");
        processed_size = decompress_file(input_file, output_file, quiet, &original_size);
        DEBUG_INFO("Decompression result - compressed: %lu bytes, decompressed: %lu bytes",
                   original_size, processed_size);

        if (processed_size == 0 && original_size > sizeof(unsigned long))
        {
            if (!quiet)
                fprintf(stderr, "Decompression failed (corrupted file or I/O error).\n");
            DEBUG_ERROR("Decompression failed - invalid result sizes: %s", "error");
            DEBUG_FUNCTION_EXIT("handle_compression_operation", 1);
            return 1;
        }
        DEBUG_FUNCTION_EXIT("handle_compression_operation", 0);
        return 0;
    }

    DEBUG_ERROR("Unknown compression mode: %d", mode);
    DEBUG_FUNCTION_EXIT("handle_compression_operation", 1);
    return 1;
}

static int handle_crypto_operation(int mode, const char *input_file, const char *output_file, int quiet)
{
    char password[MAX_PASSWORD];
    unsigned long original_size, processed_size;
    int password_confirm = (mode == MODE_ENCRYPT || mode == MODE_PROCESS);

    DEBUG_FUNCTION_ENTER("handle_crypto_operation");
    const char *mode_names[] = {"", "COMPRESS", "DECOMPRESS", "ENCRYPT", "DECRYPT", "PROCESS", "EXTRACT"};
    DEBUG_INFO("Crypto operation - mode: %s, input: '%s', output: '%s', quiet: %s",
               (mode >= 1 && mode <= 6) ? mode_names[mode] : "UNKNOWN",
               input_file, output_file, quiet ? "yes" : "no");
    if (get_password(password, sizeof(password), password_confirm) != 0)
    {
        DEBUG_ERROR("Failed to get password from user: %s", "failed");
        DEBUG_FUNCTION_EXIT("handle_crypto_operation", 1);
        return 1;
    }
    DEBUG_INFO_MSG("Password obtained successfully");

    if (validate_file_input(input_file) != 0)
    {
        DEBUG_ERROR("File validation failed for input: '%s'", input_file);
        memset(password, 0, sizeof(password));
        DEBUG_FUNCTION_EXIT("handle_crypto_operation", 1);
        return 1;
    }
    switch (mode)
    {
    case MODE_ENCRYPT:
        DEBUG_INFO_MSG("Starting file encryption");
        processed_size = encrypt_file(input_file, output_file, password, quiet, &original_size);
        DEBUG_INFO("Encryption result - original: %lu bytes, encrypted: %lu bytes",
                   original_size, processed_size);
        if (processed_size > 0)
        {
            add_entry_to_file_list(input_file, output_file, original_size, processed_size, quiet);
            memset(password, 0, sizeof(password));
            DEBUG_FUNCTION_EXIT("handle_crypto_operation", 0);
            return 0;
        }
        DEBUG_ERROR_MSG("Encryption failed");
        break;
    case MODE_DECRYPT:
        DEBUG_INFO_MSG("Starting file decryption");
        processed_size = decrypt_file(input_file, output_file, password, quiet, &original_size);
        DEBUG_INFO("Decryption result - encrypted: %lu bytes, decrypted: %lu bytes",
                   original_size, processed_size);
        if (processed_size == 0 && original_size > DEFAULT_SALT_SIZE)
        {
            if (!quiet)
                fprintf(stderr, "Decryption failed (I/O error or file too small).\n");
            DEBUG_ERROR_MSG("Decryption failed - invalid result sizes");
            memset(password, 0, sizeof(password));
            DEBUG_FUNCTION_EXIT("handle_crypto_operation", 1);
            return 1;
        }
        memset(password, 0, sizeof(password));
        DEBUG_FUNCTION_EXIT("handle_crypto_operation", 0);
        return 0;
    case MODE_PROCESS:
        DEBUG_INFO_MSG("Starting file processing (compress + encrypt)");
        processed_size = process_file(input_file, output_file, password, quiet, &original_size);
        DEBUG_INFO("Processing result - original: %lu bytes, processed: %lu bytes",
                   original_size, processed_size);
        if (processed_size > 0)
        {
            add_entry_to_file_list(input_file, output_file, original_size, processed_size, quiet);
            memset(password, 0, sizeof(password));
            DEBUG_FUNCTION_EXIT("handle_crypto_operation", 0);
            return 0;
        }
        DEBUG_ERROR_MSG("Processing failed");
        break;
    case MODE_EXTRACT:
        DEBUG_INFO_MSG("Starting file extraction (decrypt + decompress)");
        processed_size = extract_file(input_file, output_file, password, quiet, &original_size);
        DEBUG_INFO("Extraction result - processed: %lu bytes, extracted: %lu bytes",
                   original_size, processed_size);
        if (processed_size == 0 && original_size > DEFAULT_SALT_SIZE + sizeof(unsigned long))
        {
            if (!quiet)
                fprintf(stderr, "Extraction failed (decryption or decompression error).\n");
            DEBUG_ERROR_MSG("Extraction failed - invalid result sizes");
            memset(password, 0, sizeof(password));
            DEBUG_FUNCTION_EXIT("handle_crypto_operation", 1);
            return 1;
        }
        memset(password, 0, sizeof(password));
        DEBUG_FUNCTION_EXIT("handle_crypto_operation", 0);
        return 0;
    }

    DEBUG_ERROR("Unknown crypto operation mode: %d", mode);
    memset(password, 0, sizeof(password));
    DEBUG_FUNCTION_EXIT("handle_crypto_operation", 1);
    return 1;
}

static int handle_batch_operation(char *input_files[], int num_files, const char *output_dir, int quiet)
{
    char password[MAX_PASSWORD];
    int result;

    DEBUG_FUNCTION_ENTER("handle_batch_operation");
    DEBUG_INFO("Batch operation - files: %d, output_dir: '%s', quiet: %s",
               num_files, output_dir, quiet ? "yes" : "no");

    for (int i = 0; i < num_files; i++)
    {
        DEBUG_INFO("  File %d: '%s'", i + 1, input_files[i]);
    }

    if (get_password(password, sizeof(password), 1) != 0)
    {
        DEBUG_ERROR("Failed to get password for batch operation: %s", "failed");
        DEBUG_FUNCTION_EXIT("handle_batch_operation", 1);
        return 1;
    }
    DEBUG_INFO("Password obtained for batch operation: %s", "success");

    result = batch_process(input_files, num_files, output_dir, password, quiet);
    DEBUG_INFO("Batch operation completed with result: %d", result);
    memset(password, 0, sizeof(password));

    DEBUG_FUNCTION_EXIT("handle_batch_operation", result);
    return result;
}

static int parse_command_line(int argc, char *argv[], int *mode, char **input_file, char **output_file,
                              char **batch_output_dir, char batch_input_files[][MAX_FILENAME],
                              int *num_batch_files, int *quiet, int *debug)
{
    *mode = MODE_HELP;
    *input_file = NULL;
    *output_file = NULL;
    *batch_output_dir = DEFAULT_OUTPUT_DIR;
    *num_batch_files = 0;
    *quiet = 0;
    *debug = 0;

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
        fprintf(stderr, "ERROR: Unknown command '%s'. Use -h for help.\n", argv[1]);
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
            fprintf(stderr, "ERROR: Mode '%s' requires both input and output file arguments.\n", argv[1]);
            fprintf(stderr, "Usage: %s %s <input_file> <output_file>\n", argv[0], argv[1]);
            return -1;
        }
        *input_file = argv[2];
        *output_file = argv[3];
        arg_index = 4;
        break;

    case MODE_FIND:
        if (argc < 3)
        {
            fprintf(stderr, "ERROR: Find mode requires a search pattern.\n");
            fprintf(stderr, "Usage: %s -f <search_pattern>\n", argv[0]);
            return -1;
        }
        *input_file = argv[2];
        arg_index = 3;
        break;

    case MODE_BATCH:
        if (argc < 4)
        {
            fprintf(stderr, "ERROR: Batch mode requires output directory and at least one input file.\n");
            fprintf(stderr, "Usage: %s -b <output_directory> <file1> [file2] ...\n", argv[0]);
            return -1;
        }
        *batch_output_dir = argv[2];
        arg_index = 3;
        break;

    case MODE_LIST:
    case MODE_HELP:
        arg_index = 2;
        break;
    } /* Parse optional arguments */
    for (int i = arg_index; i < argc; i++)
    {
        if (strcmp(argv[i], "-q") == 0)
        {
            *quiet = 1;
        }
        else if (strcmp(argv[i], "--debug") == 0)
        {
            *debug = 1;
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
                    fprintf(stderr, "WARNING: Maximum batch file limit (%d) exceeded.\n", MAX_BATCH_FILES);
                    fprintf(stderr, "         Ignoring '%s' and subsequent files.\n", argv[i]);
                }
                break;
            }
        }
        else
        {
            fprintf(stderr, "ERROR: Unknown option '%s'. Use -h for help.\n", argv[i]);
            return -1;
        }
    }

    /* Validate batch mode arguments */
    if (*mode == MODE_BATCH && *num_batch_files == 0)
    {
        fprintf(stderr, "ERROR: No input files specified for batch processing.\n");
        fprintf(stderr, "Usage: %s -b <output_directory> <file1> [file2] ...\n", argv[0]);
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
    int debug_operation = 0;
    int result = 0;

    /* Parse command line arguments */
    if (parse_command_line(argc, argv, &operation_mode, &input_file_arg, &output_file_arg,
                           &batch_output_dir, batch_input_files, &num_batch_input_files,
                           &quiet_operation, &debug_operation) != 0)
    {
        print_usage(argv[0]);
        return 1;
    } /* Initialise debug mode */
    if (debug_operation)
    {
        debug_init(1, DEBUG_LEVEL_TRACE);
        DEBUG_INFO("Debug mode enabled for Secure File Processor: %s", "enabled");
        DEBUG_INFO("Command line arguments: argc=%d", argc);
        for (int i = 0; i < argc; i++)
        {
            DEBUG_INFO("  argv[%d] = \"%s\"", i, argv[i]);
        }
    }

    DEBUG_INFO("Starting operation mode: %d", operation_mode);

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
        DEBUG_INFO_MSG("Preparing batch operation");
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
        if (operation_mode != MODE_HELP)
        {
            DEBUG_ERROR("Unknown operation mode: %d", operation_mode);
        }
        print_usage(argv[0]);
        result = (operation_mode == MODE_HELP) ? 0 : 1;
        break;
    }

    DEBUG_INFO("Operation completed with result: %d", result);
    DEBUG_INFO("Program exiting with status: %s", (result == 0) ? "SUCCESS" : "FAILURE");
    return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
