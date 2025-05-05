/**
 * main.c - Secure File Processor with ChaCha20 encryption and Huffman compression
 * 
 * Group: [Your Group Number]
 * Lab: [Your Lab Number]
 * 
 * Compiling instructions:
 * To compile this program, use the provided makefile with the command:
 *   make
 * 
 * This will produce an executable named 'secure_processor'.
 * 
 * For a debug build with verbose output:
 *   make DEBUG=1
 * 
 * Alternatively, compile manually with:
 *   gcc -Wall -Iinclude -o secure_processor src/main.c src/encryption/chacha20.c 
 *       src/encryption/key_derivation.c src/compression/huffman.c src/utils/file_list.c
 *   
 * For debug build:
 *   gcc -Wall -DDEBUG -Iinclude -o secure_processor src/main.c src/encryption/chacha20.c 
 *       src/encryption/key_derivation.c src/compression/huffman.c src/utils/file_list.c
 * 
 * This program provides a comprehensive file security solution with:
 * 1. ChaCha20 encryption/decryption (RFC 8439)
 * 2. Huffman compression/decompression
 * 3. Password-based key derivation
 * 4. File tracking using linked lists
 * 
 * Only uses the following standard C libraries as required:
 * - stdio.h
 * - stdlib.h
 * - string.h
 * - math.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "compression/huffman.h"
#include "encryption/chacha20.h"
#include "encryption/key_derivation.h"
#include "utils/file_list.h"

/* Debug mode can be enabled via makefile (make DEBUG=1) */
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[Main] " fmt, ##__VA_ARGS__)
#define PRINT_HEX(label, data, len) print_hex(label, data, len)
#else
#define DEBUG_PRINT(fmt, ...)
#define PRINT_HEX(label, data, len)
#endif

/* Console formatting */
#define CLEAR_LINE "\r                                                                               \r"
#define PROGRESS_WIDTH 30

/* Program modes */
#define MODE_ENCRYPT     1  /* Encrypt a file */
#define MODE_DECRYPT     2  /* Decrypt a file */
#define MODE_COMPRESS    3  /* Compress a file */
#define MODE_DECOMPRESS  4  /* Decompress a file */
#define MODE_PROCESS     5  /* Process (encrypt+compress) a file */
#define MODE_EXTRACT     6  /* Extract (decompress+decrypt) a file */
#define MODE_LIST        7  /* List processed files */
#define MODE_FIND        8  /* Find a file in the list */
#define MODE_BATCH       9  /* Batch process multiple files */
#define MODE_HELP       10  /* Show help information */

/* Default values */
#define DEFAULT_KEY_ITERATIONS  10000   /* Default iterations for key derivation */
#define DEFAULT_SALT_SIZE       16      /* Default salt size in bytes */
#define DEFAULT_FILE_LIST       "file_list.dat" /* Default file list filename */
#define DEFAULT_OUTPUT_DIR      "output"        /* Default output directory */
#define MAX_FILENAME            256     /* Maximum filename length */
#define MAX_PASSWORD            128     /* Maximum password length */
#define MAX_BATCH_FILES         100     /* Maximum number of files in batch mode */
#define BUFFER_SIZE             4096    /* Buffer size for file processing */

/* Simple performance counter for operation timing */
typedef struct {
    unsigned long count;
} performance_counter_t;

/* Function prototypes */
void print_hex(const char *label, const uint8_t *data, size_t len);
void print_usage(const char *program_name);
void print_banner(void);
void print_section_header(const char *title);
void print_progress_bar(size_t current, size_t total, size_t width);
void print_operation_result(int result, const char *operation);
void print_file_info(const char *filename, size_t size);
void print_processing_summary(const char *operation, const char *input_file, const char *output_file,
                             size_t input_size, size_t output_size);
int get_password(char *password, size_t max_len, int confirm);
int ensure_directory_exists(const char *directory);
int file_exists(const char *filename);
void perf_counter_start(performance_counter_t *counter);
unsigned long perf_counter_elapsed(performance_counter_t *counter);
int encrypt_file(const char *input_file, const char *output_file, 
                const char *password, int iterations, int quiet);
int decrypt_file(const char *input_file, const char *output_file, 
                const char *password, int iterations, int quiet);
int compress_file(const char *input_file, const char *output_file, int quiet);
int decompress_file(const char *input_file, const char *output_file, int quiet);
int process_file(const char *input_file, const char *output_file, 
                const char *password, int iterations, int quiet);
int extract_file(const char *input_file, const char *output_file, 
                const char *password, int iterations, int quiet);
int handle_file_list(const char *command, const char *filename, int quiet);
int batch_process(char *filenames[], int num_files, const char *output_dir, 
                  const char *password, int iterations, int quiet);

/**
 * Print binary data in a readable hexadecimal format
 * 
 * @param label Label to print before the data
 * @param data  Data to print
 * @param len   Length of the data in bytes
 */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 4 == 0) printf(" ");
    }
    printf("\n");
}

/**
 * Print a progress bar to show operation progress
 * 
 * @param current Current progress value
 * @param total   Total expected value
 * @param width   Width of the progress bar in characters
 */
void print_progress_bar(size_t current, size_t total, size_t width) {
    float percent = (float)current / total;
    size_t filled_width = (size_t)(width * percent);
    
    printf(CLEAR_LINE);
    printf("[");
    
    /* Print filled portion */
    size_t i;
    for (i = 0; i < filled_width; i++) {
        printf("=");
    }
    
    /* Print cursor */
    if (filled_width < width) {
        printf(">");
        i++;
    }
    
    /* Print empty portion */
    for (; i < width; i++) {
        printf(" ");
    }
    
    /* Print percentage */
    printf("] %5.1f%% (%zu/%zu)", percent * 100, current, total);
    fflush(stdout);
}

/**
 * Print operation result with appropriate formatting
 * 
 * @param result    Result code (0 for success, non-zero for failure)
 * @param operation Description of the operation performed
 */
void print_operation_result(int result, const char *operation) {
    if (result == 0) {
        printf("\n--> %s completed successfully.\n", operation);
    } else {
        printf("\n--> ERROR: %s failed.\n", operation);
    }
}

/**
 * Print information about a file
 * 
 * @param filename Filename to display
 * @param size     Size of the file in bytes
 */
void print_file_info(const char *filename, size_t size) {
    char size_str[32];
    
    /* Format the size as KB, MB, etc. */
    if (size < 1024) {
        sprintf(size_str, "%zu bytes", size);
    } else if (size < 1024 * 1024) {
        sprintf(size_str, "%.2f KB", (float)size / 1024);
    } else if (size < 1024 * 1024 * 1024) {
        sprintf(size_str, "%.2f MB", (float)size / (1024 * 1024));
    } else {
        sprintf(size_str, "%.2f GB", (float)size / (1024 * 1024 * 1024));
    }
    
    printf("  File: %s\n", filename);
    printf("  Size: %s\n", size_str);
}

/**
 * Print a summary of file processing operation
 * 
 * @param operation   Type of operation performed
 * @param input_file  Input filename
 * @param output_file Output filename
 * @param input_size  Size of input file
 * @param output_size Size of output file
 */
void print_processing_summary(const char *operation, const char *input_file, const char *output_file,
                             size_t input_size, size_t output_size) {
    float ratio = (float)output_size * 100 / input_size;
    
    printf("\n--> %s Summary:\n", operation);
    printf("  Input:  %s (%zu bytes)\n", input_file, input_size);
    printf("  Output: %s (%zu bytes)\n", output_file, output_size);
    printf("  Ratio:  %.2f%%\n", ratio);
    
    if (ratio < 100) {
        printf("  Saved:  %.2f%%\n", 100 - ratio);
    }
}

/**
 * Print a section header
 * 
 * @param title Title of the section
 */
void print_section_header(const char *title) {
    printf("\n--- %s ---\n", title);
}

/**
 * Print the usage information for the program
 * 
 * @param program_name The name of the program executable
 */
void print_usage(const char *program_name) {
    printf("Secure File Processor\n\n");
    
    printf("USAGE:\n");
    printf("  %s [MODE] [OPTIONS] [FILE(S)]\n\n", program_name);
    
    printf("MODES:\n");
    printf("  -e <input> <output>    Encrypt a file (with password prompt)\n");
    printf("  -d <input> <output>    Decrypt a file (with password prompt)\n");
    printf("  -c <input> <output>    Compress a file\n");
    printf("  -x <input> <output>    Decompress a file\n");
    printf("  -p <input> <output>    Process a file (compress+encrypt)\n");
    printf("  -u <input> <output>    Extract a file (decrypt+decompress)\n");
    printf("  -l                     List processed files\n");
    printf("  -f <pattern>           Find files matching pattern\n");
    printf("  -b <outdir> <files>    Batch process multiple files\n");
    printf("  -h                     Show this help information\n\n");
    
    printf("OPTIONS:\n");
    printf("  -i <num>               Number of iterations for key derivation (default: %d)\n", DEFAULT_KEY_ITERATIONS);
    printf("  -q                     Quiet mode (minimal output)\n\n");
    
    printf("EXAMPLES:\n");
    printf("  %s -e document.txt document.enc         # Encrypt a file\n", program_name);
    printf("  %s -d document.enc document.txt         # Decrypt a file\n", program_name);
    printf("  %s -p document.txt document.sec         # Compress and encrypt\n", program_name);
    printf("  %s -b output file1.txt file2.txt        # Batch process files\n", program_name);
    printf("  %s -l                                   # List all processed files\n\n", program_name);
    
    printf("Note: For operations requiring encryption/decryption, you will be prompted for a password.\n");
}

/**
 * Check if a file exists
 * 
 * @param filename Filename to check
 * @return         1 if file exists, 0 otherwise
 */
int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1;
    }
    return 0;
}

/**
 * Create a directory if it doesn't exist
 * 
 * @param directory Directory path to create
 * @return          0 on success, non-zero on failure
 */
int ensure_directory_exists(const char *directory) {
    /* This is a simplified approach for creating a directory
     * A more robust solution would involve checking if the directory
     * already exists, but that would require platform-specific code
     * or additional libraries, which are not allowed for this assignment.
     */
    
    /* For Windows systems */
    #ifdef _WIN32
    char command[MAX_FILENAME * 2];
    sprintf(command, "mkdir %s 2> nul", directory);
    return system(command);
    
    /* For Unix-like systems */
    #else
    char command[MAX_FILENAME * 2];
    sprintf(command, "mkdir -p %s 2> /dev/null", directory);
    return system(command);
    #endif
}

/**
 * Prompt for a password with optional confirmation
 * 
 * @param password  Buffer to store the password
 * @param max_len   Maximum length of password
 * @param confirm   Whether to request password confirmation
 * @return          0 on success, non-zero on failure
 */
int get_password(char *password, size_t max_len, int confirm) {
    char confirm_password[MAX_PASSWORD];
    
    /* First password prompt */
    printf("Enter password: ");
    if (fgets(password, max_len, stdin) == NULL) {
        fprintf(stderr, "Error reading password\n");
        return -1;
    }
    
    /* Remove trailing newline */
    password[strcspn(password, "\n")] = '\0';
    
    /* Check if password is empty */
    if (strlen(password) == 0) {
        fprintf(stderr, "Error: Password cannot be empty\n");
        return -1;
    }
    
    /* Confirmation prompt if requested */
    if (confirm) {
        printf("Confirm password: ");
        if (fgets(confirm_password, max_len, stdin) == NULL) {
            fprintf(stderr, "Error reading password\n");
            return -1;
        }
        
        /* Remove trailing newline */
        confirm_password[strcspn(confirm_password, "\n")] = '\0';
        
        /* Check if passwords match */
        if (strcmp(password, confirm_password) != 0) {
            fprintf(stderr, "Error: Passwords do not match\n");
            return -1;
        }
    }
    
    return 0;
}

/**
 * Encrypt a file using ChaCha20
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param password    Password for encryption
 * @param iterations  Number of iterations for key derivation
 * @param quiet       Flag for quiet mode
 * @return            0 on success, non-zero on failure
 */
int encrypt_file(const char *input_file, const char *output_file, 
                const char *password, int iterations, int quiet) {
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t salt[DEFAULT_SALT_SIZE];
    size_t read_size, file_size = 0, original_size = 0;
    int result = 0;
    
    if (!quiet) {
        print_section_header("File Encryption");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
        printf("Using %d iterations for key derivation\n", iterations);
    }
        
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return -1;
    }
    
    /* Get file size */
    fseek(in, 0, SEEK_END);
    original_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open output file '%s'\n", output_file);
        fclose(in);
        return -1;
    }
    
    /* Generate a random salt */
    if (generate_salt(salt, DEFAULT_SALT_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to generate salt\n");
        result = -1;
        goto cleanup;
    }
    
    /* Write the salt to the output file */
    if (fwrite(salt, 1, DEFAULT_SALT_SIZE, out) != DEFAULT_SALT_SIZE) {
        fprintf(stderr, "Error: Failed to write salt to output file\n");
        result = -1;
        goto cleanup;
    }
    
    /* Derive key and nonce from password */
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, iterations,
                            key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to derive key and nonce from password\n");
        result = -1;
        goto cleanup;
    }
    
    DEBUG_PRINT("Using %d iterations for key derivation\n", iterations);
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);
    
    /* Initialize ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, 1) != 0) {
        fprintf(stderr, "Error: Failed to initialize ChaCha20 context\n");
        result = -1;
        goto cleanup;
    }
    
    /* Allocate buffers */
    buffer = (uint8_t *)malloc(BUFFER_SIZE);
    output_buffer = (uint8_t *)malloc(BUFFER_SIZE);
    
    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    if (!quiet) {
        printf("\nEncrypting file...\n");
    }
    
    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        /* Encrypt the chunk */
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0) {
            fprintf(stderr, "Error: ChaCha20 encryption failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Write the encrypted chunk to the output file */
        if (fwrite(output_buffer, 1, read_size, out) != read_size) {
            fprintf(stderr, "Error: Failed to write to output file\n");
            result = -1;
            goto cleanup;
        }
        
        file_size += read_size;
        
        /* Update progress bar if not in quiet mode */
        if (!quiet) {
            print_progress_bar(file_size, original_size, PROGRESS_WIDTH);
        }
    }
        
    if (!quiet) {
        printf("\n\nEncryption operation completed.\n");
        print_processing_summary("Encryption", input_file, output_file, 
                               original_size, file_size + DEFAULT_SALT_SIZE);
    }
    
    /* Add to file list */
    file_list_t file_list;
    file_list_init(&file_list);
    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0) {
        /* File doesn't exist or error loading - just continue with empty list */
        DEBUG_PRINT("Creating new file list\n");
    }
    
    file_list_add(&file_list, output_file, original_size, file_size + DEFAULT_SALT_SIZE);
    if (file_list_save(&file_list, DEFAULT_FILE_LIST) != 0) {
        if (!quiet) {
            fprintf(stderr, "Warning: Failed to save file list\n");
        }
    }
    
    file_list_free(&file_list);
    
cleanup:
    /* Close files */
    if (in != NULL) fclose(in);
    if (out != NULL) fclose(out);
    
    /* Free allocated memory */
    if (buffer != NULL) {
        memset(buffer, 0, BUFFER_SIZE);
        free(buffer);
    }
    if (output_buffer != NULL) {
        memset(output_buffer, 0, BUFFER_SIZE);
        free(output_buffer);
    }
    
    /* Clear sensitive data */
    chacha20_cleanup(&ctx);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    
    return result;
}

/**
 * Decrypt a file using ChaCha20
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param password    Password for decryption
 * @param iterations  Number of iterations for key derivation
 * @param quiet       Flag for quiet mode
 * @return            0 on success, non-zero on failure
 */
int decrypt_file(const char *input_file, const char *output_file, 
                const char *password, int iterations, int quiet) {
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t salt[DEFAULT_SALT_SIZE];
    size_t read_size, file_size = 0, total_size = 0;
    int result = 0;
    
    if (!quiet) {
        print_section_header("File Decryption");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
        printf("Using %d iterations for key derivation\n", iterations);
    }
        
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return -1;
    }
    
    /* Get file size */
    fseek(in, 0, SEEK_END);
    total_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    if (total_size <= DEFAULT_SALT_SIZE) {
        fprintf(stderr, "Error: Input file is too small to be valid\n");
        fclose(in);
        return -1;
    }
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open output file '%s'\n", output_file);
        fclose(in);
        return -1;
    }
    
    /* Read the salt from the input file */
    if (fread(salt, 1, DEFAULT_SALT_SIZE, in) != DEFAULT_SALT_SIZE) {
        fprintf(stderr, "Error: Failed to read salt from input file\n");
        result = -1;
        goto cleanup;
    }
    
    PRINT_HEX("Read salt", salt, DEFAULT_SALT_SIZE);
    
    /* Derive key and nonce from password */
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, iterations,
                            key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to derive key and nonce from password\n");
        result = -1;
        goto cleanup;
    }
    
    DEBUG_PRINT("Using %d iterations for key derivation\n", iterations);
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);
    
    /* Initialize ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, 1) != 0) {
        fprintf(stderr, "Error: Failed to initialize ChaCha20 context\n");
        result = -1;
        goto cleanup;
    }
    
    /* Allocate buffers */
    buffer = (uint8_t *)malloc(BUFFER_SIZE);
    output_buffer = (uint8_t *)malloc(BUFFER_SIZE);
    
    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    if (!quiet) {
        printf("\nDecrypting file...\n");
    }
    
    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        /* Decrypt the chunk */
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0) {
            fprintf(stderr, "Error: ChaCha20 decryption failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Write the decrypted chunk to the output file */
        if (fwrite(output_buffer, 1, read_size, out) != read_size) {
            fprintf(stderr, "Error: Failed to write to output file\n");
            result = -1;
            goto cleanup;
        }
        
        file_size += read_size;
        
        /* Update progress bar if not in quiet mode */
        if (!quiet) {
            print_progress_bar(file_size, total_size - DEFAULT_SALT_SIZE, PROGRESS_WIDTH);
        }
    }
        
    if (!quiet) {
        printf("\n\nDecryption operation completed.\n");
        
        size_t output_size = file_size;
        print_processing_summary("Decryption", input_file, output_file, 
                               total_size, output_size);
    }
    
cleanup:
    /* Close files */
    if (in != NULL) fclose(in);
    if (out != NULL) fclose(out);
    
    /* Free allocated memory */
    if (buffer != NULL) {
        memset(buffer, 0, BUFFER_SIZE);
        free(buffer);
    }
    if (output_buffer != NULL) {
        memset(output_buffer, 0, BUFFER_SIZE);
        free(output_buffer);
    }
    
    /* Clear sensitive data */
    chacha20_cleanup(&ctx);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    
    return result;
}

/**
 * Compress a file using Huffman coding
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param quiet       Flag for quiet mode
 * @return            0 on success, non-zero on failure
 */
int compress_file(const char *input_file, const char *output_file, int quiet) {
    FILE *in = NULL, *out = NULL;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    size_t read_size, output_size, file_size = 0, total_size = 0;
    int result = 0;

    if (!quiet) {
        print_section_header("File Compression");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
    }
        
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return -1;
    }
    
    /* Get file size */
    fseek(in, 0, SEEK_END);
    total_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open output file '%s'\n", output_file);
        fclose(in);
        return -1;
    }
    
    /* Write the original file size to the output file */
    if (fwrite(&total_size, sizeof(size_t), 1, out) != 1) {
        fprintf(stderr, "Error: Failed to write file size to output file\n");
        result = -1;
        goto cleanup;
    }
    
    /* Allocate buffers */
    buffer = (uint8_t *)malloc(BUFFER_SIZE);
    output_buffer = (uint8_t *)malloc(huffman_worst_case_size(BUFFER_SIZE));
    
    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    if (!quiet) {
        printf("\nCompressing file...\n");
    }
    
    size_t total_output_size = sizeof(size_t); /* Account for the file size header */
    
    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        /* Compress the chunk */
        if (huffman_compress(buffer, read_size, output_buffer, 
                      huffman_worst_case_size(BUFFER_SIZE), &output_size) != 0) {
            fprintf(stderr, "Error: Huffman compression failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Write the compressed chunk size and data to the output file */
        if (fwrite(&output_size, sizeof(size_t), 1, out) != 1) {
            fprintf(stderr, "Error: Failed to write chunk size to output file\n");
            result = -1;
            goto cleanup;
        }
        
        if (fwrite(output_buffer, 1, output_size, out) != output_size) {
            fprintf(stderr, "Error: Failed to write to output file\n");
            result = -1;
            goto cleanup;
        }
        
        file_size += read_size;
        total_output_size += output_size + sizeof(size_t);
        
        /* Update progress bar if not in quiet mode */
        if (!quiet) {
            print_progress_bar(file_size, total_size, PROGRESS_WIDTH);
        }
    }
        
    if (!quiet) {
        printf("\n\nCompression operation completed.\n");
        print_processing_summary("Compression", input_file, output_file, 
                               total_size, total_output_size);
    }
    
    /* Add to file list */
    file_list_t file_list;
    file_list_init(&file_list);
    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0) {
        /* File doesn't exist or error loading - just continue with empty list */
        DEBUG_PRINT("Creating new file list\n");
    }
    
    file_list_add(&file_list, output_file, total_size, total_output_size);
    if (file_list_save(&file_list, DEFAULT_FILE_LIST) != 0) {
        if (!quiet) {
            fprintf(stderr, "Warning: Failed to save file list\n");
        }
    }
    
    file_list_free(&file_list);
    
cleanup:
    /* Close files */
    if (in != NULL) fclose(in);
    if (out != NULL) fclose(out);
    
    /* Free allocated memory */
    if (buffer != NULL) free(buffer);
    if (output_buffer != NULL) free(output_buffer);
    
    return result;
}

/**
 * Decompress a file that was compressed using Huffman coding
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param quiet       Flag for quiet mode
 * @return            0 on success, non-zero on failure
 */
int decompress_file(const char *input_file, const char *output_file, int quiet) {
    FILE *in = NULL, *out = NULL;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    size_t chunk_size, output_size, file_size = 0, original_size = 0;
    int result = 0;
    
    if (!quiet) {
        print_section_header("File Decompression");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
    }
    
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return -1;
    }
    
    /* Read the original file size from the input file */
    if (fread(&original_size, sizeof(size_t), 1, in) != 1) {
        fprintf(stderr, "Error: Failed to read original file size from input file\n");
        fclose(in);
        return -1;
    }
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open output file '%s'\n", output_file);
        fclose(in);
        return -1;
    }
    
    /* Allocate buffers */
    buffer = (uint8_t *)malloc(huffman_worst_case_size(BUFFER_SIZE));
    output_buffer = (uint8_t *)malloc(BUFFER_SIZE);
    
    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    if (!quiet) {
        printf("\nDecompressing file...\n");
    }
    
    while (fread(&chunk_size, sizeof(size_t), 1, in) == 1) {
        /* Check if chunk size is reasonable */
        if (chunk_size > huffman_worst_case_size(BUFFER_SIZE)) {
            fprintf(stderr, "Error: Invalid chunk size: %zu\n", chunk_size);
            result = -1;
            goto cleanup;
        }
        
        /* Read the compressed chunk */
        if (fread(buffer, 1, chunk_size, in) != chunk_size) {
            fprintf(stderr, "Error: Failed to read compressed chunk from input file\n");
            result = -1;
            goto cleanup;
        }
        
        /* Decompress the chunk */
        if (huffman_decompress(buffer, chunk_size, output_buffer, BUFFER_SIZE, &output_size) != 0) {
            fprintf(stderr, "Error: Huffman decompression failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Write the decompressed chunk to the output file */
        if (fwrite(output_buffer, 1, output_size, out) != output_size) {
            fprintf(stderr, "Error: Failed to write to output file\n");
            result = -1;
            goto cleanup;
        }
        
        file_size += output_size;
        
        /* Update progress bar if not in quiet mode */
        if (!quiet) {
            print_progress_bar(file_size, original_size, PROGRESS_WIDTH);
        }
    }

    if (!quiet) {
        printf("\n\nDecompression operation completed.\n");
        
        /* Get the actual size of the input file */
        fseek(in, 0, SEEK_END);
        size_t input_actual_size = ftell(in);
        
        print_processing_summary("Decompression", input_file, output_file, 
                               input_actual_size, file_size);
    }
    
cleanup:
    /* Close files */
    if (in != NULL) fclose(in);
    if (out != NULL) fclose(out);
    
    /* Free allocated memory */
    if (buffer != NULL) free(buffer);
    if (output_buffer != NULL) free(output_buffer);
    
    return result;
}

/**
 * Process a file (compress and encrypt)
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param password    Password for encryption
 * @param iterations  Number of iterations for key derivation
 * @param quiet       Flag for quiet mode
 * @return            0 on success, non-zero on failure
 */
int process_file(const char *input_file, const char *output_file, 
                const char *password, int iterations, int quiet) {
    char temp_file[MAX_FILENAME];
    int result;
    
    /* Create a temporary filename */
    snprintf(temp_file, MAX_FILENAME, "%s.tmp", output_file);
    
    if (!quiet) {
        print_section_header("File Processing (Compress + Encrypt)");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
        printf("Using %d iterations for key derivation\n", iterations);
    }
    
    /* First compress the file */
    result = compress_file(input_file, temp_file, quiet);
    if (result != 0) {
        fprintf(stderr, "Error: Compression failed\n");
        remove(temp_file);
        return result;
    }
    
    /* Then encrypt the compressed file */
    result = encrypt_file(temp_file, output_file, password, iterations, quiet);
    if (result != 0) {
        fprintf(stderr, "Error: Encryption failed\n");
        remove(temp_file);
        return result;
    }
    
    /* Remove the temporary file */
    remove(temp_file);
    
    if (!quiet) {
        print_operation_result(0, "File processing (compress + encrypt)");
    }
    
    return 0;
}

/**
 * Extract a file (decrypt and decompress)
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param password    Password for decryption
 * @param iterations  Number of iterations for key derivation
 * @param quiet       Flag for quiet mode
 * @return            0 on success, non-zero on failure
 */
int extract_file(const char *input_file, const char *output_file, 
                const char *password, int iterations, int quiet) {
    char temp_file[MAX_FILENAME];
    int result;
    
    /* Create a temporary filename */
    snprintf(temp_file, MAX_FILENAME, "%s.tmp", output_file);
    
    if (!quiet) {
        print_section_header("File Extraction (Decrypt + Decompress)");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
        printf("Using %d iterations for key derivation\n", iterations);
    }
    
    /* First decrypt the file */
    result = decrypt_file(input_file, temp_file, password, iterations, quiet);
    if (result != 0) {
        fprintf(stderr, "Error: Decryption failed\n");
        remove(temp_file);
        return result;
    }
    
    /* Then decompress the file */
    result = decompress_file(temp_file, output_file, quiet);
    if (result != 0) {
        fprintf(stderr, "Error: Decompression failed\n");
        remove(temp_file);
        return result;
    }
    
    /* Remove the temporary file */
    remove(temp_file);
    
    if (!quiet) {
        print_operation_result(0, "File extraction (decrypt + decompress)");
    }
    
    return 0;
}

/**
 * Handle file list operations (list, find)
 * 
 * @param command   Command to execute ("list" or "find")
 * @param filename  Filename to find (only used for "find" command)
 * @param quiet     Flag for quiet mode
 * @return          0 on success, non-zero on failure
 */
int handle_file_list(const char *command, const char *filename, int quiet) {
    file_list_t file_list;
    file_entry_t *found;
    
    /* Initialize the file list */
    file_list_init(&file_list);
    
    /* Load the file list */
    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0) {
        fprintf(stderr, "Error: Failed to load file list or file list doesn't exist\n");
        return -1;
    }
    
    /* Execute the command */
    if (strcmp(command, "list") == 0) {
        /* List all files */
        if (!quiet) {
            print_section_header("File List");
        }
        
        printf("Total entries: %zu\n\n", file_list.count);
        file_list_print(&file_list);
    } else if (strcmp(command, "find") == 0) {
        /* Find a file */
        if (filename == NULL) {
            fprintf(stderr, "Error: No filename specified for find command\n");
            file_list_free(&file_list);
            return -1;
        }
        
        if (!quiet) {
            print_section_header("File Search");
            printf("Pattern: '%s'\n\n", filename);
        }
        
        found = file_list_find(&file_list, filename);
        
        if (found) {
            printf("Found matching file:\n");
            
            printf("  Filename: %s\n", found->filename);
            printf("  Sequence: #%lu\n", found->sequence_num);
            printf("  Original size: %zu bytes\n", found->original_size);
            printf("  Processed size: %zu bytes\n", found->processed_size);
            printf("  Compression ratio: %.2f%%\n",
                  (float)found->processed_size * 100 / found->original_size);
        } else {
            printf("No matching file found for pattern '%s'\n", filename);
        }
    } else {
        fprintf(stderr, "Error: Unknown file list command: %s\n", command);
        file_list_free(&file_list);
        return -1;
    }
    
    /* Free the file list */
    file_list_free(&file_list);
    
    return 0;
}

/**
 * Process multiple files in batch mode
 * 
 * @param filenames   Array of input filenames
 * @param num_files   Number of files in the array
 * @param output_dir  Output directory
 * @param password    Password for encryption
 * @param iterations  Number of iterations for key derivation
 * @param quiet       Flag for quiet mode
 * @return            0 on success, non-zero on failure
 */
int batch_process(char *filenames[], int num_files, const char *output_dir, 
                 const char *password, int iterations, int quiet) {
    char output_file[MAX_FILENAME];
    char *filename_only;
    int result = 0;
    int i, success_count = 0;
    
    if (!quiet) {
        print_section_header("Batch Processing");
        printf("Files to process: %d\n", num_files);
        printf("Output directory: %s\n", output_dir);
        printf("Using %d iterations for key derivation\n", iterations);
    }
    
    /* Ensure output directory exists */
    if (ensure_directory_exists(output_dir) != 0) {
        fprintf(stderr, "Error: Failed to create output directory '%s'\n", output_dir);
        return -1;
    }
    
    /* Process each file */
    for (i = 0; i < num_files; i++) {
        /* Extract filename from path */
        filename_only = strrchr(filenames[i], '/');
        if (filename_only == NULL) {
            filename_only = strrchr(filenames[i], '\\');
        }
        
        if (filename_only == NULL) {
            filename_only = filenames[i];
        } else {
            filename_only++; /* Skip the separator */
        }
        
        /* Create output filename */
        snprintf(output_file, MAX_FILENAME, "%s/%s.sec", output_dir, filename_only);
        
        if (!quiet) {
            printf("\n[%d/%d] Processing file:\n", i + 1, num_files);
            printf("  Input:  %s\n", filenames[i]);
            printf("  Output: %s\n", output_file);
        }
        
        /* Process the file */
        result = process_file(filenames[i], output_file, password, iterations, quiet);
        if (result == 0) {
            success_count++;
            if (!quiet) {
                printf("  Status: Success\n");
            }
        } else {
            if (!quiet) {
                fprintf(stderr, "  Status: Failed\n");
            }
            /* Continue with next file */
        }
    }
    
    if (!quiet) {
        print_section_header("Batch Processing Summary");
        printf("Total files: %d\n", num_files);
        printf("Successful:  %d\n", success_count);
        printf("Failed:      %d\n", num_files - success_count);
        
        if (success_count == num_files) {
            printf("\nAll files processed successfully!\n");
        } else {
            printf("\nSome files failed to process. Check the output for details.\n");
        }
    }
    
    return (success_count == num_files) ? 0 : -1;
}

int main(int argc, char *argv[]) {
    int mode = MODE_HELP;
    char *input_file = NULL, *output_file = NULL;
    char password[MAX_PASSWORD];
    int iterations = DEFAULT_KEY_ITERATIONS;
    int quiet_mode = 0;
    char *batch_files[MAX_BATCH_FILES];
    int num_batch_files = 0;
    char *output_dir = NULL;
    int result;
    
    /* Parse command line arguments */
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Parse mode */
    if (strcmp(argv[1], "-e") == 0) {
        /* Encrypt mode */
        mode = MODE_ENCRYPT;
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for encryption mode\n");
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
        output_file = argv[3];
    } else if (strcmp(argv[1], "-d") == 0) {
        /* Decrypt mode */
        mode = MODE_DECRYPT;
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for decryption mode\n");
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
        output_file = argv[3];
    } else if (strcmp(argv[1], "-c") == 0) {
        /* Compress mode */
        mode = MODE_COMPRESS;
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for compression mode\n");
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
        output_file = argv[3];
    } else if (strcmp(argv[1], "-x") == 0) {
        /* Decompress mode */
        mode = MODE_DECOMPRESS;
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for decompression mode\n");
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
        output_file = argv[3];
    } else if (strcmp(argv[1], "-p") == 0) {
        /* Process mode (encrypt+compress) */
        mode = MODE_PROCESS;
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for processing mode\n");
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
        output_file = argv[3];
    } else if (strcmp(argv[1], "-u") == 0) {
        /* Extract mode (decompress+decrypt) */
        mode = MODE_EXTRACT;
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for extraction mode\n");
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
        output_file = argv[3];
    } else if (strcmp(argv[1], "-l") == 0) {
        /* List mode */
        mode = MODE_LIST;
    } else if (strcmp(argv[1], "-f") == 0) {
        /* Find mode */
        mode = MODE_FIND;
        if (argc < 3) {
            fprintf(stderr, "Error: Missing filename pattern for find mode\n");
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2]; /* Using input_file to store the filename to find */
    } else if (strcmp(argv[1], "-b") == 0) {
        /* Batch mode */
        mode = MODE_BATCH;
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for batch mode\n");
            print_usage(argv[0]);
            return 1;
        }
        output_dir = argv[2];
        
        /* Gather the list of files */
        for (int i = 3; i < argc; i++) {
            /* Skip options */
            if (argv[i][0] == '-') {
                if (strcmp(argv[i], "-q") == 0) {
                    quiet_mode = 1;
                } else if (strcmp(argv[i], "-i") == 0) {
                    if (i + 1 < argc) {
                        iterations = atoi(argv[i + 1]);
                        i++; /* Skip the next argument */
                    }
                } else {
                    fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
                    print_usage(argv[0]);
                    return 1;
                }
            } else {
                /* Add file to the list */
                if (num_batch_files < MAX_BATCH_FILES) {
                    batch_files[num_batch_files++] = argv[i];
                } else {
                    fprintf(stderr, "Error: Too many files specified (maximum: %d)\n", MAX_BATCH_FILES);
                    break;
                }
            }
        }
        
        if (num_batch_files == 0) {
            fprintf(stderr, "Error: No files specified for batch processing\n");
            print_usage(argv[0]);
            return 1;
        }
    } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        /* Help mode */
        mode = MODE_HELP;
    } else {
        /* Unknown mode */
        fprintf(stderr, "Error: Unknown mode: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }
    
    /* Parse additional options */
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            /* Set iterations */
            if (i + 1 < argc) {
                iterations = atoi(argv[i + 1]);
                i++; /* Skip the next argument */
            }
        } else if (strcmp(argv[i], "-q") == 0) {
            /* Set quiet mode */
            quiet_mode = 1;
        } else {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    /* Execute the selected mode */
    switch (mode) {
        case MODE_ENCRYPT:
            /* Get password */
            if (get_password(password, MAX_PASSWORD, 0) != 0) {
                return 1;
            }
            
            /* Check if input file exists */
            if (!file_exists(input_file)) {
                fprintf(stderr, "Error: Input file '%s' does not exist\n", input_file);
                return 1;
            }
            
            /* Encrypt the file */
            result = encrypt_file(input_file, output_file, password, iterations, quiet_mode);
            
            /* Clear the password from memory */
            memset(password, 0, MAX_PASSWORD);
            
            if (!quiet_mode) {
                print_operation_result(result, "Encryption");
            }
            break;
            
        case MODE_DECRYPT:
            /* Get password */
            if (get_password(password, MAX_PASSWORD, 0) != 0) {
                return 1;
            }
            
            /* Check if input file exists */
            if (!file_exists(input_file)) {
                fprintf(stderr, "Error: Input file '%s' does not exist\n", input_file);
                return 1;
            }
            
            /* Decrypt the file */
            result = decrypt_file(input_file, output_file, password, iterations, quiet_mode);
            
            /* Clear the password from memory */
            memset(password, 0, MAX_PASSWORD);
            
            if (!quiet_mode) {
                print_operation_result(result, "Decryption");
            }
            break;
            
        case MODE_COMPRESS:
            /* Check if input file exists */
            if (!file_exists(input_file)) {
                fprintf(stderr, "Error: Input file '%s' does not exist\n", input_file);
                return 1;
            }
            
            /* Compress the file */
            result = compress_file(input_file, output_file, quiet_mode);
            
            if (!quiet_mode) {
                print_operation_result(result, "Compression");
            }
            break;
            
        case MODE_DECOMPRESS:
            /* Check if input file exists */
            if (!file_exists(input_file)) {
                fprintf(stderr, "Error: Input file '%s' does not exist\n", input_file);
                return 1;
            }
            
            /* Decompress the file */
            result = decompress_file(input_file, output_file, quiet_mode);
            
            if (!quiet_mode) {
                print_operation_result(result, "Decompression");
            }
            break;
            
        case MODE_PROCESS:
            /* Get password */
            if (get_password(password, MAX_PASSWORD, 1) != 0) {
                return 1;
            }
            
            /* Check if input file exists */
            if (!file_exists(input_file)) {
                fprintf(stderr, "Error: Input file '%s' does not exist\n", input_file);
                return 1;
            }
            
            /* Process the file */
            result = process_file(input_file, output_file, password, iterations, quiet_mode);
            
            /* Clear the password from memory */
            memset(password, 0, MAX_PASSWORD);
            
            if (!quiet_mode) {
                print_operation_result(result, "Processing");
            }
            break;
            
        case MODE_EXTRACT:
            /* Get password */
            if (get_password(password, MAX_PASSWORD, 0) != 0) {
                return 1;
            }
            
            /* Check if input file exists */
            if (!file_exists(input_file)) {
                fprintf(stderr, "Error: Input file '%s' does not exist\n", input_file);
                return 1;
            }
            
            /* Extract the file */
            result = extract_file(input_file, output_file, password, iterations, quiet_mode);
            
            /* Clear the password from memory */
            memset(password, 0, MAX_PASSWORD);
            
            if (!quiet_mode) {
                print_operation_result(result, "Extraction");
            }
            break;
            
        case MODE_LIST:
            /* List files */
            result = handle_file_list("list", NULL, quiet_mode);
            break;
            
        case MODE_FIND:
            /* Find files */
            result = handle_file_list("find", input_file, quiet_mode);
            break;
            
        case MODE_BATCH:
            /* Get password */
            if (get_password(password, MAX_PASSWORD, 1) != 0) {
                return 1;
            }
            
            /* Process files in batch */
            result = batch_process(batch_files, num_batch_files, output_dir, password, iterations, quiet_mode);
            
            /* Clear the password from memory */
            memset(password, 0, MAX_PASSWORD);
            break;
            
        case MODE_HELP:
        default:
            print_usage(argv[0]);
            result = 0;
            break;
    }
    
    return result;
}