/**
 * main.c - Secure File Processor with ChaCha20 encryption and Huffman compression
 *
 * Compiling instructions:
 * Use the provided makefile: `make`
 * Debug build: `make debug`
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
// #include <math.h> // Not strictly needed in main.c itself, but allowed
#include "compression/huffman.h"
#include "encryption/chacha20.h"
#include "encryption/key_derivation.h"
#include "utils/file_list.h"

/* Debug mode can be enabled via makefile (make debug) */
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[Main] " fmt, ##__VA_ARGS__)
#define PRINT_HEX(label, data, len) print_hex(label, data, len)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0) // Ensure no code generation for empty macro
#define PRINT_HEX(label, data, len) ((void)0)
#endif

/* Console formatting */
#define CLEAR_LINE "\r                                                                          \r" // Clear line macro
#define PROGRESS_WIDTH 30 // Width of the progress bar

/* Program modes */
#define MODE_COMPRESS    1  /* Compress a file */
#define MODE_DECOMPRESS  2  /* Decompress a file */
#define MODE_ENCRYPT     3  /* Encrypt a file */
#define MODE_DECRYPT     4  /* Decrypt a file */
#define MODE_PROCESS     5  /* Process (compress+encrypt) a file */
#define MODE_EXTRACT     6  /* Extract (decrypt+decompress) a file */
#define MODE_LIST        7  /* List processed files */
#define MODE_FIND        8  /* Find a file in the list */
#define MODE_BATCH       9  /* Batch process multiple files */
#define MODE_HELP       10  /* Show help information */

/* Default values */
#define DEFAULT_KEY_ITERATIONS  10000           /* Default iterations for key derivation */
#define DEFAULT_SALT_SIZE       16              /* Default salt size in bytes */
#define DEFAULT_FILE_LIST       "file_list.dat" /* Default file list filename */
#define DEFAULT_OUTPUT_DIR      "output"        /* Default output directory for batch */
#define MAX_FILENAME            256             /* Maximum filename length */
#define MAX_PASSWORD            128             /* Maximum password length */
#define MAX_BATCH_FILES         100             /* Maximum number of files in batch mode */
#define BUFFER_SIZE             4096            /* Buffer size for file processing */

/* Function prototypes */
void print_hex(const char *label, const uint8_t *data, size_t len);
void print_usage(const char *program_name);
void print_progress_bar(size_t current, size_t total, size_t width);
void print_operation_result(int result, const char *operation);
void print_processing_summary(const char *operation, const char *input_file, const char *output_file,
                              size_t input_size, size_t output_size);
void print_section_header(const char *title);
int get_password(char *password, size_t max_len, int confirm);
int ensure_directory_exists(const char *directory);
int file_exists(const char *filename);
int add_entry_to_file_list(const char *output_file, size_t original_size, size_t processed_size, int quiet);
size_t encrypt_file(const char *input_file, const char *output_file,
                    const char *password, int iterations, int quiet, size_t *original_size_out);
size_t decrypt_file(const char *input_file, const char *output_file,
                    const char *password, int iterations, int quiet, size_t *original_size_out);
size_t compress_file(const char *input_file, const char *output_file, int quiet, size_t *original_size_out);
size_t decompress_file(const char *input_file, const char *output_file, int quiet, size_t *original_size_out);
size_t process_file(const char *input_file, const char *output_file,
                    const char *password, int iterations, int quiet, size_t *original_size_out);
size_t extract_file(const char *input_file, const char *output_file,
                    const char *password, int iterations, int quiet, size_t *original_size_out);
int handle_file_list(const char *command, const char *filename, int quiet);
int batch_process(char *filenames[], int num_files, const char *output_dir,
                  const char *password, int iterations, int quiet);


/**
 * Print binary data in a readable hexadecimal format (only if DEBUG defined)
 */
#ifdef DEBUG
void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("[Main] %s: ", label);
    // Limit printing for very long data to avoid excessive output
    size_t print_len = (len > 64) ? 64 : len;
    for (i = 0; i < print_len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 4 == 0 && i + 1 < print_len) printf(" ");
    }
    if (len > 64) printf("... (%zu bytes total)", len);
    printf("\n");
}
#endif // DEBUG (print_hex is defined only in debug mode)

/**
 * Print a progress bar to show operation progress
 */
void print_progress_bar(size_t current, size_t total, size_t width) {
    // Avoid division by zero if total is 0 (e.g., empty file)
    float percent = (total == 0) ? 1.0f : (float)current / total;
    // Ensure percent doesn't exceed 1.0 due to potential rounding issues
    if (percent > 1.0f) percent = 1.0f;

    size_t filled_width = (size_t)(width * percent);

    printf(CLEAR_LINE); // Clear the current line
    printf("[");

    /* Print filled portion */
    size_t i;
    for (i = 0; i < filled_width; i++) {
        printf("=");
    }

    /* Print cursor if not full */
    if (filled_width < width) {
        printf(">");
        i++;
    }

    /* Print empty portion */
    for (; i < width; i++) {
        printf(" ");
    }

    /* Print percentage */
    // Use %zu for size_t which is standard C99
    printf("] %5.1f%% (%zu/%zu bytes)", percent * 100.0f, current, total);
    fflush(stdout); // Ensure progress bar updates immediately
}

/**
 * Print operation result with appropriate formatting
 */
void print_operation_result(int result, const char *operation) {
    // Add newline before result for better spacing if progress bar was used
    printf("\n");
    if (result == 0) {
        printf("--> %s completed successfully.\n", operation);
    } else {
        // Use fprintf to stderr for errors
        fprintf(stderr, "--> ERROR: %s failed.\n", operation);
    }
}

/**
 * Print a summary of file processing operation
 */
void print_processing_summary(const char *operation, const char *input_file, const char *output_file,
                              size_t input_size, size_t output_size) {
    // Avoid division by zero for ratio calculation
    float ratio = (input_size == 0) ? 0.0f : (float)output_size * 100.0f / input_size;

    printf("\n--> %s Summary:\n", operation);
    printf("    Input:  %s (%zu bytes)\n", input_file, input_size);
    printf("    Output: %s (%zu bytes)\n", output_file, output_size);
    // Only show ratio if input size is non-zero
    if (input_size > 0) {
        printf("    Ratio:  %.2f%%\n", ratio);
        // Only show savings if ratio is less than 100%
        if (ratio < 100.0f) {
            printf("    Saved:  %.2f%%\n", 100.0f - ratio);
        }
    } else {
        printf("    Ratio:  N/A (input size is 0)\n");
    }
}

/**
 * Print a section header
 */
void print_section_header(const char *title) {
    printf("\n--- %s ---\n", title);
}

/**
 * Print the usage information for the program
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
    printf("  -p <input> <output>    Process a file (compress then encrypt)\n");
    printf("  -u <input> <output>    Extract a file (decrypt then decompress)\n");
    printf("  -l                     List processed files (from %s)\n", DEFAULT_FILE_LIST);
    printf("  -f <pattern>           Find files matching pattern in list\n");
    printf("  -b <outdir> <files..>  Batch process (compress+encrypt) multiple files\n");
    printf("  -h, --help             Show this help information\n\n");

    printf("OPTIONS:\n");
    printf("  -i <num>               Number of iterations for key derivation (default: %d)\n", DEFAULT_KEY_ITERATIONS);
    printf("  -q                     Quiet mode (minimal output, suppresses progress bars and summaries)\n\n");

    printf("EXAMPLES:\n");
    printf("  %s -e document.txt document.enc                 # Encrypt a file\n", program_name);
    printf("  %s -d document.enc document.txt                 # Decrypt a file\n", program_name);
    printf("  %s -p report.pdf report.pdf.sec -i 20000        # Compress and encrypt with more iterations\n", program_name);
    printf("  %s -u report.pdf.sec report.pdf                 # Decrypt and decompress\n", program_name);
    printf("  %s -b secure_files file1.txt image.jpg          # Batch process files into 'secure_files' dir\n", program_name);
    printf("  %s -l                                           # List all processed files\n", program_name);
    printf("  %s -f report                                    # Find files containing 'report' in the list\n\n", program_name);

    printf("Note: For operations requiring encryption/decryption (-e, -d, -p, -u, -b), you will be prompted for a password.\n");
}

/**
 * Check if a file exists and is readable
 */
int file_exists(const char *filename) {
    FILE *file = fopen(filename, "rb"); // Open for binary read
    if (file) {
        fclose(file);
        return 1; // File exists and is readable
    }
    return 0; // File does not exist or cannot be opened
}

/**
 * Create a directory if it doesn't exist (basic cross-platform attempt)
 */
int ensure_directory_exists(const char *directory) {
    /* This is a simplified approach using system calls.
     * A more robust solution might use stat() and mkdir() directly,
     * but requires platform-specific headers (#ifdef _WIN32 vs POSIX).
     */
    char command[MAX_FILENAME * 2]; // Allocate sufficient buffer

    // Check if directory is NULL or empty
    if (directory == NULL || directory[0] == '\0') {
        fprintf(stderr, "Error: Invalid directory path provided.\n");
        return -1;
    }

    // Construct the command based on the platform
    #ifdef _WIN32
        // Use 'mkdir' on Windows. Redirect errors to nul.
        // The `2> nul` part suppresses error messages if the directory already exists.
        snprintf(command, sizeof(command), "mkdir \"%s\" 2> nul", directory);
    #else
        // Use 'mkdir -p' on Unix-like systems. Redirect errors to /dev/null.
        // The '-p' flag ensures parent directories are created if needed,
        // and it doesn't error if the directory already exists.
        snprintf(command, sizeof(command), "mkdir -p \"%s\" 2> /dev/null", directory);
    #endif

    // Execute the command
    int status = system(command);

    // system() returns 0 on success for many shells when the command executes successfully.
    // On Windows, mkdir might return non-zero even if it succeeds (if dir exists).
    // On Linux, mkdir -p returns 0 if the directory exists or was created.
    // We rely on the error redirection to hide "already exists" errors.
    // A non-zero status *might* indicate a real error (e.g., permission denied).
    if (status != 0) {
        // It's hard to be certain if it was a real error without more checks,
        // but we can issue a warning.
        DEBUG_PRINT("system(\"%s\") returned status %d. Directory might not have been created if it didn't exist.\n", command, status);
        // We won't return -1 here, as the directory might actually exist.
        // The subsequent fopen() calls will fail if the directory truly doesn't exist and couldn't be created.
    }

    return 0; // Assume success or directory already exists
}


/**
 * Prompt for a password with optional confirmation.
 * Handles potential errors during input.
 */
int get_password(char *password, size_t max_len, int confirm) {
    char confirm_password[MAX_PASSWORD]; // Use defined max length

    /* First password prompt */
    printf("Enter password: ");
    fflush(stdout); // Ensure prompt is displayed before input
    if (fgets(password, max_len, stdin) == NULL) {
        // Check for EOF or read error
        if (feof(stdin)) {
            fprintf(stderr, "\nError: End-of-file reached while reading password.\n");
        } else {
            fprintf(stderr, "\nError reading password.\n");
        }
        clearerr(stdin); // Clear error/EOF indicators for potential future input
        return -1;
    }

    /* Remove trailing newline, if present */
    password[strcspn(password, "\n")] = '\0';

    /* Check if password is empty */
    if (password[0] == '\0') { // More reliable check than strlen
        fprintf(stderr, "Error: Password cannot be empty.\n");
        return -1;
    }

    /* Confirmation prompt if requested */
    if (confirm) {
        printf("Confirm password: ");
        fflush(stdout);
        if (fgets(confirm_password, sizeof(confirm_password), stdin) == NULL) {
            if (feof(stdin)) {
                fprintf(stderr, "\nError: End-of-file reached while reading password confirmation.\n");
            } else {
                fprintf(stderr, "\nError reading password confirmation.\n");
            }
            clearerr(stdin);
            // Clear the first password buffer for security before returning
            memset(password, 0, max_len);
            return -1;
        }

        /* Remove trailing newline */
        confirm_password[strcspn(confirm_password, "\n")] = '\0';

        /* Check if passwords match */
        if (strcmp(password, confirm_password) != 0) {
            fprintf(stderr, "Error: Passwords do not match.\n");
            // Clear both buffers for security
            memset(password, 0, max_len);
            memset(confirm_password, 0, sizeof(confirm_password));
            return -1;
        }
        // Clear confirmation buffer immediately after successful comparison
        memset(confirm_password, 0, sizeof(confirm_password));
    }

    return 0; // Success
}


// --- Helper function to add entry to file list ---
// Moved list handling logic here to be called from main's switch statement
int add_entry_to_file_list(const char *output_file, size_t original_size, size_t processed_size, int quiet) {
    file_list_t file_list;
    file_list_init(&file_list);

    // Attempt to load the existing list. It's okay if it fails (e.g., first run).
    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0) {
        DEBUG_PRINT("Creating new file list or failed to load existing one from %s.\n", DEFAULT_FILE_LIST);
        // Reset the list just in case loading partially failed
        file_list_free(&file_list);
        file_list_init(&file_list);
    }

    // Add the new entry to the list structure in memory
    if (file_list_add(&file_list, output_file, original_size, processed_size) != 0) {
        if (!quiet) {
            // Use fprintf to stderr for warnings/errors
            fprintf(stderr, "Warning: Failed to add entry '%s' to file list structure in memory.\n", output_file);
        }
        file_list_free(&file_list); // Clean up memory
        return -1; // Indicate failure to add
    }

    // Save the updated list structure back to the file
    if (file_list_save(&file_list, DEFAULT_FILE_LIST) != 0) {
        if (!quiet) {
            fprintf(stderr, "Warning: Failed to save updated file list to %s\n", DEFAULT_FILE_LIST);
        }
        file_list_free(&file_list); // Clean up memory
        return -1; // Indicate failure to save
    }

    // Successfully added and saved, now free the list from memory
    file_list_free(&file_list);
    return 0; // Success
}


/**
 * Encrypt a file using ChaCha20
 * NOTE: Removed file list handling from this function. It's now done in main.
 * Returns the final size of the encrypted file (including salt) on success, or 0 on failure.
 */
size_t encrypt_file(const char *input_file, const char *output_file,
                    const char *password, int iterations, int quiet, size_t *original_size_out) {
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t salt[DEFAULT_SALT_SIZE];
    size_t read_size, file_size = 0, original_size = 0;
    int result = 0; // 0 for success, -1 for failure
    size_t final_output_size = 0; // Track final size including salt

    if (!quiet) {
        print_section_header("File Encryption");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
        printf("Using %d iterations for key derivation\n", iterations);
    }

    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0; // Indicate failure
    }

    /* Get file size */
    if (fseek(in, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: Could not seek to end of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    original_size = ftell(in);
    if (fseek(in, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Could not seek to start of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    if (original_size_out) {
        *original_size_out = original_size; // Pass original size back if pointer provided
    }


    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0; // Indicate failure
    }

    /* Generate a random salt */
    if (generate_salt(salt, DEFAULT_SALT_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to generate salt.\n");
        result = -1;
        goto cleanup_encrypt;
    }

    /* Write the salt to the output file */
    if (fwrite(salt, 1, DEFAULT_SALT_SIZE, out) != DEFAULT_SALT_SIZE) {
        fprintf(stderr, "Error: Failed to write salt to output file '%s'.\n", output_file);
        result = -1;
        goto cleanup_encrypt;
    }
    final_output_size += DEFAULT_SALT_SIZE; // Add salt size to final output size

    /* Derive key and nonce from password */
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, iterations,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to derive key and nonce from password.\n");
        result = -1;
        goto cleanup_encrypt;
    }

    DEBUG_PRINT("Using %d iterations for key derivation\n", iterations);
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);

    /* Initialize ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, 1) != 0) { // Start with counter 1 as per RFC recommendation
        fprintf(stderr, "Error: Failed to initialize ChaCha20 context.\n");
        result = -1;
        goto cleanup_encrypt;
    }

    /* Allocate buffers */
    buffer = (uint8_t *)malloc(BUFFER_SIZE);
    output_buffer = (uint8_t *)malloc(BUFFER_SIZE);

    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for buffers.\n");
        result = -1;
        goto cleanup_encrypt;
    }

    /* Process the file in chunks */
    if (!quiet) {
        printf("\nEncrypting file...\n");
        // Initialize progress bar only if not quiet
        print_progress_bar(0, original_size, PROGRESS_WIDTH);
    }

    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        /* Encrypt the chunk */
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0) {
            fprintf(stderr, "\nError: ChaCha20 encryption failed during processing.\n");
            result = -1;
            goto cleanup_encrypt;
        }

        /* Write the encrypted chunk to the output file */
        if (fwrite(output_buffer, 1, read_size, out) != read_size) {
            fprintf(stderr, "\nError: Failed to write encrypted data to output file '%s'.\n", output_file);
            result = -1;
            goto cleanup_encrypt;
        }

        file_size += read_size;

        /* Update progress bar if not in quiet mode */
        if (!quiet) {
            print_progress_bar(file_size, original_size, PROGRESS_WIDTH);
        }
    }

    // Check for read errors after the loop
    if (ferror(in)) {
        fprintf(stderr, "\nError: Failed reading from input file '%s'.\n", input_file);
        result = -1;
        goto cleanup_encrypt;
    }

    final_output_size += file_size; // Add encrypted data size

    if (!quiet) {
        // Ensure progress bar shows 100% if successful and file not empty
        if (result == 0 && original_size > 0) {
            print_progress_bar(original_size, original_size, PROGRESS_WIDTH);
        }
        printf("\n"); // Newline after progress bar
        // Summary is printed in main now
    }

cleanup_encrypt:
    /* Close files */
    if (in != NULL) fclose(in);
    if (out != NULL) fclose(out);

    /* Free allocated memory */
    if (buffer != NULL) {
        memset(buffer, 0, BUFFER_SIZE); // Clear buffer content
        free(buffer);
    }
    if (output_buffer != NULL) {
        memset(output_buffer, 0, BUFFER_SIZE); // Clear buffer content
        free(output_buffer);
    }

    /* Clear sensitive data */
    chacha20_cleanup(&ctx);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    memset(salt, 0, DEFAULT_SALT_SIZE); // Also clear salt buffer

    // If an error occurred, potentially delete partially written output file
    if (result != 0 && output_file != NULL) {
        remove(output_file);
    }


    return (result == 0) ? final_output_size : 0; // Return final size on success, 0 on failure
}

/**
 * Decrypt a file using ChaCha20
 * Returns the final size of the decrypted file on success, or 0 on failure.
 */
size_t decrypt_file(const char *input_file, const char *output_file,
                    const char *password, int iterations, int quiet, size_t *original_size_out) {
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t salt[DEFAULT_SALT_SIZE];
    size_t read_size, file_size = 0, total_size = 0;
    int result = 0; // 0=success, -1=potential decrypt error, -2=definite I/O/mem error
    size_t final_output_size = 0;

    if (!quiet) {
        print_section_header("File Decryption");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
        printf("Using %d iterations for key derivation\n", iterations);
    }

    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0; // Indicate failure
    }

    /* Get file size */
     if (fseek(in, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: Could not seek to end of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    total_size = ftell(in);
     if (fseek(in, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Could not seek to start of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
     if (original_size_out) {
        *original_size_out = total_size; // Pass original (encrypted) size back if pointer provided
    }


    if (total_size <= DEFAULT_SALT_SIZE) {
        fprintf(stderr, "Error: Input file '%s' is too small (%zu bytes) to be valid encrypted data (requires salt).\n", input_file, total_size);
        fclose(in);
        return 0; // Indicate failure
    }

    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0; // Indicate failure
    }

    /* Read the salt from the input file */
    if (fread(salt, 1, DEFAULT_SALT_SIZE, in) != DEFAULT_SALT_SIZE) {
        fprintf(stderr, "Error: Failed to read salt from input file '%s'.\n", input_file);
        result = -2; // Definite I/O error
        goto cleanup_decrypt;
    }

    PRINT_HEX("Read salt", salt, DEFAULT_SALT_SIZE);

    /* Derive key and nonce from password */
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, iterations,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to derive key and nonce from password.\n");
        result = -2; // Treat as definite error
        goto cleanup_decrypt;
    }

    DEBUG_PRINT("Using %d iterations for key derivation\n", iterations);
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);

    /* Initialize ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, 1) != 0) {
        fprintf(stderr, "Error: Failed to initialize ChaCha20 context.\n");
        result = -2;
        goto cleanup_decrypt;
    }

    /* Allocate buffers */
    buffer = (uint8_t *)malloc(BUFFER_SIZE);
    output_buffer = (uint8_t *)malloc(BUFFER_SIZE);

    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for buffers.\n");
        result = -2;
        goto cleanup_decrypt;
    }

    /* Process the file in chunks */
    if (!quiet) {
        printf("\nDecrypting file...\n");
         // Initialize progress bar only if not quiet
        print_progress_bar(0, total_size - DEFAULT_SALT_SIZE, PROGRESS_WIDTH);
    }

    size_t remaining_size = total_size - DEFAULT_SALT_SIZE;
    while ((read_size = fread(buffer, 1, (remaining_size < BUFFER_SIZE ? remaining_size : BUFFER_SIZE), in)) > 0) {
        /* Decrypt the chunk */
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0) {
            // This internal error in chacha20_process is unlikely unless parameters are wrong,
            // but we treat it as a definite failure. Wrong password doesn't cause this.
            fprintf(stderr, "\nError: ChaCha20 decryption failed during processing (internal error).\n");
            result = -2; // Mark as definite failure
            goto cleanup_decrypt;
        }

        /* Write the decrypted chunk to the output file */
        if (fwrite(output_buffer, 1, read_size, out) != read_size) {
            fprintf(stderr, "\nError: Failed to write decrypted data to output file '%s'.\n", output_file);
            result = -2; // Mark as definite failure
            goto cleanup_decrypt; // Stop processing on write error
        }

        file_size += read_size;
        remaining_size -= read_size;


        /* Update progress bar if not in quiet mode */
        if (!quiet) {
            print_progress_bar(file_size, total_size - DEFAULT_SALT_SIZE, PROGRESS_WIDTH);
        }
    }

     // Check for read errors after the loop
    if (ferror(in)) {
        fprintf(stderr, "\nError: Failed reading from input file '%s'.\n", input_file);
        result = -2; // Definite I/O error
        goto cleanup_decrypt;
    }


    final_output_size = file_size; // Final size is the decrypted data size

    if (!quiet) {
         // Ensure progress bar shows 100% if successful and file not empty
         if (result == 0 && (total_size - DEFAULT_SALT_SIZE) > 0) {
             print_progress_bar(total_size - DEFAULT_SALT_SIZE, total_size - DEFAULT_SALT_SIZE, PROGRESS_WIDTH);
         }
        printf("\n"); // Newline after progress bar
        // Summary is printed in main now
        // Note: We can't definitively know if the password was correct here without authenticated encryption.
        // The output file might contain garbage data if the password was wrong.
    }

cleanup_decrypt:
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
    memset(salt, 0, DEFAULT_SALT_SIZE);

    // If a definite error occurred, delete potentially corrupted output file
    if (result == -2 && output_file != NULL) {
         remove(output_file);
         final_output_size = 0; // Ensure 0 is returned on definite failure
    }


    // Return final size on success or potential password error, 0 on definite failure
    return (result == -2) ? 0 : final_output_size;
}


/**
 * Compress a file using Huffman coding
 * NOTE: Removed file list handling from this function. It's now done in main.
 * Uses a single pass for simplicity (reads whole file).
 * Returns the final size of the compressed file (including header) on success, or 0 on failure.
 */
size_t compress_file(const char *input_file, const char *output_file, int quiet, size_t *original_size_out) {
    FILE *in = NULL, *out = NULL;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    size_t read_size, output_size, total_size = 0;
    int result = 0; // 0 for success, -1 for failure
    size_t total_output_size = 0; // Track final size including header

    if (!quiet) {
        print_section_header("File Compression");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
    }

    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0; // Indicate failure
    }

    /* Get file size */
    if (fseek(in, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: Could not seek to end of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    total_size = ftell(in);
     if (fseek(in, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Could not seek to start of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    if (original_size_out) {
        *original_size_out = total_size; // Pass original size back if pointer provided
    }

    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0; // Indicate failure
    }

    /* Write the original file size to the output file header */
    // This header is specific to this implementation's compression format
    if (fwrite(&total_size, sizeof(size_t), 1, out) != 1) {
        fprintf(stderr, "Error: Failed to write file size header to output file '%s'.\n", output_file);
        result = -1;
        goto cleanup_compress;
    }
    total_output_size += sizeof(size_t); // Account for the file size header

    /* Allocate buffer for the entire input file */
    // Note: For very large files, this is inefficient. A streaming approach would be better.
    if (total_size > 0) {
        buffer = (uint8_t *)malloc(total_size);
        if (buffer == NULL) {
             fprintf(stderr, "Error: Memory allocation failed for input buffer (%zu bytes).\n", total_size);
             result = -1;
             goto cleanup_compress;
        }
        // Read the entire file
        read_size = fread(buffer, 1, total_size, in);
        if (read_size != total_size || ferror(in)) {
            fprintf(stderr, "Error: Failed to read entire input file '%s'.\n", input_file);
            result = -1;
            goto cleanup_compress;
        }
    } else {
        // Handle empty file case
        buffer = NULL; // No buffer needed
        read_size = 0;
    }


    /* Allocate output buffer (worst-case size) */
    size_t output_max_len = huffman_worst_case_size(read_size);
    // Ensure allocation size is at least 1 to avoid malloc(0) issues
    output_buffer = (uint8_t *)malloc(output_max_len > 0 ? output_max_len : 1);

    if (output_buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for output buffer.\n");
        result = -1;
        goto cleanup_compress;
    }


    /* Process the file */
    if (!quiet) {
        printf("\nCompressing file...\n");
        // Since we read the whole file, show immediate progress
        print_progress_bar(0, total_size, PROGRESS_WIDTH);
    }

    /* Compress the entire buffer */
    if (huffman_compress(buffer, read_size, output_buffer,
                         output_max_len, &output_size) != 0) {
        fprintf(stderr, "\nError: Huffman compression failed.\n");
        result = -1;
        goto cleanup_compress;
    }

    /* Write the compressed data to the output file */
    if (output_size > 0) { // Only write if there's compressed data
        if (fwrite(output_buffer, 1, output_size, out) != output_size) {
            fprintf(stderr, "\nError: Failed to write compressed data to output file '%s'.\n", output_file);
            result = -1;
            goto cleanup_compress;
        }
    }
    total_output_size += output_size; // Add compressed data size

    if (!quiet) {
        // Show 100% progress
        print_progress_bar(total_size, total_size, PROGRESS_WIDTH);
        printf("\n"); // Newline after progress bar
        // Summary is printed in main now
    }

cleanup_compress:
    /* Close files */
    if (in != NULL) fclose(in);
    if (out != NULL) fclose(out);

    /* Free allocated memory */
    if (buffer != NULL) free(buffer);
    if (output_buffer != NULL) free(output_buffer);

     // If an error occurred, potentially delete partially written output file
    if (result != 0 && output_file != NULL) {
        remove(output_file);
    }

    return (result == 0) ? total_output_size : 0; // Return final size on success, 0 on failure
}


/**
 * Decompress a file that was compressed using Huffman coding
 * Uses a single pass (reads whole compressed file).
 * Returns the final size of the decompressed file on success, or 0 on failure.
 */
size_t decompress_file(const char *input_file, const char *output_file, int quiet, size_t *original_size_out) {
    FILE *in = NULL, *out = NULL;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    size_t compressed_size, output_size, original_size = 0; // original_size is the expected decompressed size
    int result = 0; // 0 for success, -1 for failure
    size_t input_actual_size = 0; // Size of the compressed input file

    if (!quiet) {
        print_section_header("File Decompression");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
    }

    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s' for reading.\n", input_file);
        return 0; // Indicate failure
    }

     /* Get the actual size of the input file */
    if (fseek(in, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: Could not seek to end of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    input_actual_size = ftell(in);
    if (fseek(in, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Could not seek to start of input file '%s'.\n", input_file);
        fclose(in);
        return 0;
    }
    if (original_size_out) {
        *original_size_out = input_actual_size; // Pass compressed size back if pointer provided
    }

    // Check if file is large enough for the header
    if (input_actual_size < sizeof(size_t)) {
         fprintf(stderr, "Error: Input file '%s' is too small (%zu bytes) to contain header.\n", input_file, input_actual_size);
         fclose(in);
         return 0;
    }

    /* Read the original (decompressed) file size from the input file header */
    if (fread(&original_size, sizeof(size_t), 1, in) != 1) {
        fprintf(stderr, "Error: Failed to read original file size header from input file '%s'.\n", input_file);
        fclose(in);
        return 0; // Indicate failure
    }

    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open output file '%s' for writing.\n", output_file);
        fclose(in);
        return 0; // Indicate failure
    }

    /* Allocate buffer for the compressed data */
    compressed_size = input_actual_size - sizeof(size_t);
    // Ensure allocation size is at least 1 to avoid malloc(0) issues
    if (compressed_size > 0) {
        buffer = (uint8_t *)malloc(compressed_size);
        if (buffer == NULL) {
             fprintf(stderr, "Error: Memory allocation failed for compressed data buffer (%zu bytes).\n", compressed_size);
             result = -1;
             goto cleanup_decompress;
        }
        // Read the compressed data
        if (fread(buffer, 1, compressed_size, in) != compressed_size || ferror(in)) {
            fprintf(stderr, "Error: Failed to read compressed data from input file '%s'.\n", input_file);
            result = -1;
            goto cleanup_decompress;
        }
    } else {
        // Handle case where compressed data size is 0 (e.g., original file was empty)
        buffer = NULL;
    }


    /* Allocate output buffer for decompressed data */
     // Ensure allocation size is at least 1 to avoid malloc(0) issues
    output_buffer = (uint8_t *)malloc(original_size > 0 ? original_size : 1);
    if (output_buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for output buffer (%zu bytes).\n", original_size);
        result = -1;
        goto cleanup_decompress;
    }

    /* Process the file */
    if (!quiet) {
        printf("\nDecompressing file...\n");
         // Show immediate progress
        print_progress_bar(0, original_size, PROGRESS_WIDTH);
    }

    /* Decompress the entire buffer */
    if (huffman_decompress(buffer, compressed_size, output_buffer, original_size, &output_size) != 0) {
        fprintf(stderr, "\nError: Huffman decompression failed. Input file might be corrupted or not compressed with this tool.\n");
        result = -1;
        goto cleanup_decompress;
    }

    /* Check if decompressed size matches expected size from header */
    if (output_size != original_size) {
         fprintf(stderr, "\nError: Decompressed size (%zu) does not match expected size from header (%zu). File might be corrupted.\n", output_size, original_size);
         result = -1;
         // Don't write potentially corrupted data
         goto cleanup_decompress;
    }


    /* Write the decompressed data to the output file */
    if (output_size > 0) { // Only write if there is data
        if (fwrite(output_buffer, 1, output_size, out) != output_size) {
            fprintf(stderr, "\nError: Failed to write decompressed data to output file '%s'.\n", output_file);
            result = -1;
            goto cleanup_decompress;
        }
    }

    if (!quiet) {
        // Show 100% progress
        print_progress_bar(original_size, original_size, PROGRESS_WIDTH);
        printf("\n"); // Newline after progress bar
       // Summary is printed in main now
    }

cleanup_decompress:
    /* Close files */
    if (in != NULL) fclose(in);
    if (out != NULL) fclose(out);

    /* Free allocated memory */
    if (buffer != NULL) free(buffer);
    if (output_buffer != NULL) free(output_buffer);

     // If an error occurred, potentially delete partially written output file
    if (result != 0 && output_file != NULL) {
        remove(output_file);
    }

    // Return final (decompressed) size on success, 0 on failure
    return (result == 0) ? original_size : 0;
}


/**
 * Process a file (compress and encrypt)
 * Returns the final size of the processed file on success, or 0 on failure.
 */
size_t process_file(const char *input_file, const char *output_file,
                    const char *password, int iterations, int quiet, size_t *original_size_out) {
    char temp_file[MAX_FILENAME];
    size_t compressed_size = 0;
    size_t final_size = 0;
    size_t original_input_size = 0; // Size of the very first input file

    /* Create a temporary filename */
    // Using snprintf for safety against buffer overflows
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", output_file);
    // Ensure null termination even if output_file was too long
    temp_file[sizeof(temp_file) - 1] = '\0';


    if (!quiet) {
        print_section_header("File Processing (Compress + Encrypt)");
        // No need to print details here, sub-functions will do it if not quiet
    }

    /* --- Step 1: Compress the file --- */
    if (!quiet) printf("\n--- Compression Step ---\n");
    compressed_size = compress_file(input_file, temp_file, quiet, &original_input_size);

    // Check if compression failed (returns 0 on failure)
    // Also handle the case where the input file was empty (original_input_size == 0)
    // In that case, compress_file should succeed and return the header size.
    if (compressed_size == 0 && original_input_size > 0) {
        fprintf(stderr, "Error: Compression step failed for input '%s'.\n", input_file);
        remove(temp_file); // Clean up temp file on failure
        return 0; // Indicate overall failure
    }
     if (original_size_out) {
        *original_size_out = original_input_size; // Pass original size back if pointer provided
    }


    /* --- Step 2: Encrypt the compressed file --- */
    if (!quiet) printf("\n--- Encryption Step ---\n");
    // Note: The 'original_size' for encrypt_file here is the *compressed* size,
    // which we don't need to pass back out, so the last arg is NULL.
    final_size = encrypt_file(temp_file, output_file, password, iterations, quiet, NULL);

    // Check if encryption failed (returns 0 on failure)
    // Also handle the case where the compressed file was empty (e.g., only header)
    if (final_size == 0 && compressed_size > 0) {
        fprintf(stderr, "Error: Encryption step failed for temporary file '%s'.\n", temp_file);
        remove(temp_file); // Clean up temp file
        remove(output_file); // Clean up potentially partial final file
        return 0; // Indicate overall failure
    }

    /* Remove the temporary file */
    if (remove(temp_file) != 0) {
         // Don't treat failure to remove temp file as critical error, but warn
         if (!quiet) {
             fprintf(stderr, "Warning: Could not remove temporary file '%s'.\n", temp_file);
         }
    }


    if (!quiet) {
        printf("\n"); // Add spacing before summary
        print_processing_summary("Process (Compress+Encrypt)", input_file, output_file,
                                 original_input_size, final_size);
        print_operation_result(0, "File processing (compress + encrypt)"); // Assuming success if we got here
    }

    return final_size; // Return final processed size
}

/**
 * Extract a file (decrypt and decompress)
 * Returns the final size of the extracted file on success, or 0 on failure.
 */
size_t extract_file(const char *input_file, const char *output_file,
                    const char *password, int iterations, int quiet, size_t *original_size_out) {
    char temp_file[MAX_FILENAME];
    size_t decrypted_size = 0;
    size_t final_size = 0;
    size_t original_input_size = 0; // Size of the encrypted input file

    /* Create a temporary filename */
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", output_file);
    temp_file[sizeof(temp_file) - 1] = '\0'; // Ensure null termination


    if (!quiet) {
        print_section_header("File Extraction (Decrypt + Decompress)");
         // No need to print details here, sub-functions will do it if not quiet
    }

    /* --- Step 1: Decrypt the file --- */
     if (!quiet) printf("\n--- Decryption Step ---\n");
    decrypted_size = decrypt_file(input_file, temp_file, password, iterations, quiet, &original_input_size);

    // Check for definite failure (I/O, memory), not just potential password error
    // If original_input_size was large enough to hold salt, a 0 return is a definite error.
    if (decrypted_size == 0 && original_input_size > DEFAULT_SALT_SIZE) {
        fprintf(stderr, "Error: Decryption step failed for input '%s' (I/O or memory error).\n", input_file);
        remove(temp_file); // Clean up temp file on failure
        return 0; // Indicate overall failure
    }
     if (original_size_out) {
        *original_size_out = original_input_size; // Pass original encrypted size back if pointer provided
    }


    /* --- Step 2: Decompress the decrypted file --- */
     if (!quiet) printf("\n--- Decompression Step ---\n");
    // Note: The 'original_size' for decompress_file here is the *decrypted* size.
    final_size = decompress_file(temp_file, output_file, quiet, NULL); // Don't need original size from decompress

    // Check if decompression failed (returns 0 on failure)
    // Also handle case where decrypted file was empty (decrypted_size might be 0 or just header size)
    if (final_size == 0 && decrypted_size > sizeof(size_t)) { // Check if decrypted size had at least the header
        fprintf(stderr, "Error: Decompression step failed for temporary file '%s'. Decrypted data might be corrupted.\n", temp_file);
        remove(temp_file); // Clean up temp file
        remove(output_file); // Clean up potentially partial final file
        return 0; // Indicate overall failure
    }

    /* Remove the temporary file */
    if (remove(temp_file) != 0) {
        if (!quiet) {
             fprintf(stderr, "Warning: Could not remove temporary file '%s'.\n", temp_file);
         }
    }

    if (!quiet) {
        printf("\n"); // Add spacing before summary
        print_processing_summary("Extract (Decrypt+Decompress)", input_file, output_file,
                                 original_input_size, final_size);
        print_operation_result(0, "File extraction (decrypt + decompress)"); // Assuming success if we got here
    }

    return final_size; // Return final extracted size
}


/**
 * Handle file list operations (list, find)
 */
int handle_file_list(const char *command, const char *filename_pattern, int quiet) {
    file_list_t file_list;
    file_entry_t *found;
    int result = 0; // 0 for success

    /* Initialize the file list */
    file_list_init(&file_list);

    /* Load the file list */
    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0) {
        // It's not necessarily an error if the list doesn't exist yet
        if (!quiet) {
            printf("Info: File list '%s' not found or is empty.\n", DEFAULT_FILE_LIST);
        }
        // If the command was 'find', we report no matches found.
        // If the command was 'list', we proceed to print the empty list info.
        if (strcmp(command, "find") == 0) {
             if (!quiet) print_section_header("File Search");
             printf("Pattern: '%s'\n\n", filename_pattern ? filename_pattern : "");
             printf("No matching file found (list is empty or not found).\n");
             return 0; // Not an error state, just no matches
        }
    }

    /* Execute the command */
    if (strcmp(command, "list") == 0) {
        /* List all files */
        if (!quiet) {
            print_section_header("File List Contents");
        }
        printf("Source: %s\n", DEFAULT_FILE_LIST);
        printf("Total entries found: %zu\n", file_list.count);
        if (file_list.count > 0) {
             printf("\n");
             file_list_print(&file_list); // Use the utility print function
        } else {
            printf("(List is empty)\n");
        }

    } else if (strcmp(command, "find") == 0) {
        /* Find a file */
        if (filename_pattern == NULL || filename_pattern[0] == '\0') {
            fprintf(stderr, "Error: No filename pattern specified for find command.\n");
            result = -1; // Error state
        } else {
            if (!quiet) {
                 print_section_header("File Search");
                 printf("Pattern: '%s'\n\n", filename_pattern);
            }

            found = file_list_find(&file_list, filename_pattern);

            if (found) {
                printf("Found matching file:\n");
                // Print details using a similar format as file_list_print
                printf("--> Filename: %s\n", found->filename);
                printf("    Sequence: #%lu\n", found->sequence_num);
                printf("    Original size: %zu bytes\n", found->original_size);
                printf("    Processed size: %zu bytes\n", found->processed_size);
                // Avoid division by zero for ratio
                if (found->original_size > 0) {
                    printf("    Compression ratio: %.2f%%\n",
                           (float)found->processed_size * 100.0f / found->original_size);
                } else {
                    printf("    Compression ratio: N/A\n");
                }
            } else {
                printf("No matching file found in the list for pattern '%s'.\n", filename_pattern);
            }
        }
    } else {
        fprintf(stderr, "Error: Unknown internal file list command: %s\n", command);
        result = -1; // Error state
    }

    /* Free the file list memory */
    file_list_free(&file_list);

    return result; // 0 on success, -1 on error
}

/**
 * Process multiple files in batch mode (Compress + Encrypt)
 * NOTE: Updated to use new function return values and list handling
 */
int batch_process(char *filenames[], int num_files, const char *output_dir,
                  const char *password, int iterations, int quiet) {
    char output_file[MAX_FILENAME];
    char *filename_only;
    int overall_result = 0; // Overall result for the batch (0=all success, -1=any failure)
    int i, success_count = 0;
    size_t original_size, processed_size;

    if (!quiet) {
        print_section_header("Batch Processing (Compress + Encrypt)");
        printf("Files to process: %d\n", num_files);
        printf("Output directory: %s\n", output_dir);
        printf("Using %d iterations for key derivation\n", iterations);
    }

    /* Ensure output directory exists */
    if (ensure_directory_exists(output_dir) != 0) {
        // ensure_directory_exists now prints its own error, but we still return
        return -1;
    }

    /* Process each file */
    for (i = 0; i < num_files; i++) {
        // --- Construct output path ---
        // Find last path separator (works for / and \)
        filename_only = strrchr(filenames[i], '/');
        char *filename_only_bs = strrchr(filenames[i], '\\');
        if (filename_only_bs > filename_only) { // Check if backslash is later
             filename_only = filename_only_bs;
        }

        if (filename_only == NULL) {
            filename_only = filenames[i]; // No separator, use the whole name
        } else {
            filename_only++; /* Move past the separator */
        }

        // Check for empty filename after stripping path
        if (*filename_only == '\0') {
             fprintf(stderr, "\n[%d/%d] Skipping invalid input filename: '%s'\n", i + 1, num_files, filenames[i]);
             overall_result = -1; // Mark batch as failed
             continue;
        }


        /* Create output filename path */
        snprintf(output_file, sizeof(output_file), "%s/%s.sec", output_dir, filename_only);
        output_file[sizeof(output_file)-1] = '\0'; // Ensure null termination

        if (!quiet) {
            printf("\n[%d/%d] Processing file:\n", i + 1, num_files);
            printf("    Input:  %s\n", filenames[i]);
            printf("    Output: %s\n", output_file);
        }

        /* Check if input file exists before processing */
         if (!file_exists(filenames[i])) {
             fprintf(stderr, "    Status: Failed (Input file '%s' not found)\n", filenames[i]);
             overall_result = -1; // Mark batch as failed
             continue; // Skip to next file
         }


        /* Process the file (Compress + Encrypt) */
        processed_size = process_file(filenames[i], output_file, password, iterations, quiet, &original_size);

        if (processed_size > 0) {
            success_count++;
             if (!quiet) {
                 // process_file already prints summary and result if not quiet
                 // printf("    Status: Success\n"); // Redundant if not quiet
             }
            // Add entry to file list for successful processing
            if (add_entry_to_file_list(output_file, original_size, processed_size, quiet) != 0) {
                 if (!quiet) {
                     // Use stderr for warnings
                     fprintf(stderr, "    Warning: Failed to add '%s' to file list '%s'.\n", output_file, DEFAULT_FILE_LIST);
                 }
                 // Don't mark the whole batch as failed just for list error
            }
        } else {
            // process_file already prints errors if not quiet
            overall_result = -1; // Mark batch as failed if any file fails
            if (!quiet) {
                 // fprintf(stderr, "    Status: Failed\n"); // Redundant if not quiet
            }
            // Don't add to list if processing failed
        }
    } // End of loop through files

    if (!quiet) {
        print_section_header("Batch Processing Summary");
        printf("Total files attempted: %d\n", num_files);
        printf("Successful:            %d\n", success_count);
        printf("Failed:                %d\n", num_files - success_count);

        if (overall_result == 0) {
            printf("\nAll files processed successfully!\n");
        } else {
            printf("\nSome files failed to process. Check the output above for details.\n");
        }
    }

    return overall_result; // 0 if all succeeded, -1 if any failed
}


int main(int argc, char *argv[]) {
    int mode = MODE_HELP; // Default to showing help
    char *input_file = NULL, *output_file = NULL;
    char password[MAX_PASSWORD];
    int iterations = DEFAULT_KEY_ITERATIONS;
    int quiet_mode = 0;
    char *batch_files[MAX_BATCH_FILES];
    int num_batch_files = 0;
    // Initialise output_dir with the default value
    char *output_dir = DEFAULT_OUTPUT_DIR;
    int result = 0; // Use 0 for success, non-zero for failure convention
    size_t original_size=0, processed_size=0; // For list adding in main scope

    /* --- Argument Parsing --- */
    if (argc < 2) {
        print_usage(argv[0]);
        return 1; // Exit if no arguments provided
    }

    // Determine mode based on the first argument
    if (strcmp(argv[1], "-e") == 0) { mode = MODE_ENCRYPT; }
    else if (strcmp(argv[1], "-d") == 0) { mode = MODE_DECRYPT; }
    else if (strcmp(argv[1], "-c") == 0) { mode = MODE_COMPRESS; }
    else if (strcmp(argv[1], "-x") == 0) { mode = MODE_DECOMPRESS; }
    else if (strcmp(argv[1], "-p") == 0) { mode = MODE_PROCESS; }
    else if (strcmp(argv[1], "-u") == 0) { mode = MODE_EXTRACT; }
    else if (strcmp(argv[1], "-l") == 0) { mode = MODE_LIST; }
    else if (strcmp(argv[1], "-f") == 0) { mode = MODE_FIND; }
    else if (strcmp(argv[1], "-b") == 0) { mode = MODE_BATCH; }
    else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) { mode = MODE_HELP; }
    else {
        fprintf(stderr, "Error: Unknown mode or option: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    // --- Argument Validation and Assignment based on Mode ---
    int file_arg_start_index = 2; // Default starting index for options/files

    switch (mode) {
        case MODE_COMPRESS:
        case MODE_DECOMPRESS:
        case MODE_ENCRYPT:
        case MODE_DECRYPT:
        case MODE_PROCESS:
        case MODE_EXTRACT:
            if (argc < 4) {
                fprintf(stderr, "Error: Missing <input> and <output> file arguments for mode '%s'.\n", argv[1]);
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2];
            output_file = argv[3];
            file_arg_start_index = 4;
            break;
        case MODE_FIND:
            if (argc < 3) {
                fprintf(stderr, "Error: Missing <pattern> argument for find mode '-f'.\n");
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2]; // Use input_file to store the pattern
            file_arg_start_index = 3;
            break;
        case MODE_BATCH:
             if (argc < 4) {
                 fprintf(stderr, "Error: Missing <outdir> and at least one <file> argument for batch mode '-b'.\n");
                 print_usage(argv[0]);
                 return 1;
             }
             output_dir = argv[2]; // Overwrite default if provided
             file_arg_start_index = 3; // Files/options start from index 3
             // Batch file list gathering happens in the next loop
             break;
        case MODE_LIST:
        case MODE_HELP:
             file_arg_start_index = 2; // Options start from index 2
             break;
        // No default needed as initial check caught unknown modes
    }

    /* --- Parse Options and Gather Batch Files --- */
    for (int i = file_arg_start_index; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            if (++i < argc) { // Increment i *before* checking bounds and accessing argv[i]
                iterations = atoi(argv[i]);
                if (iterations <= 0) {
                    fprintf(stderr, "Error: Invalid number of iterations '%s'. Must be positive.\n", argv[i]);
                    return 1;
                }
            } else {
                 fprintf(stderr, "Error: Missing argument for -i option.\n");
                 print_usage(argv[0]);
                 return 1;
            }
        } else if (strcmp(argv[i], "-q") == 0) {
            quiet_mode = 1;
        } else if (mode == MODE_BATCH) {
             // If in batch mode, treat non-option arguments as input files
             if (num_batch_files < MAX_BATCH_FILES) {
                 batch_files[num_batch_files++] = argv[i];
             } else {
                 // Only warn if not quiet
                 if (!quiet_mode) {
                     fprintf(stderr, "Warning: Exceeded maximum number of batch files (%d). Ignoring '%s' and subsequent files.\n", MAX_BATCH_FILES, argv[i]);
                 }
                 break; // Stop processing further arguments as files
             }
        } else {
             // If not in batch mode, any other argument is an error
             fprintf(stderr, "Error: Unknown option or unexpected argument: %s\n", argv[i]);
             print_usage(argv[0]);
             return 1;
        }
    }

     // Final check for batch mode: ensure at least one file was provided
    if (mode == MODE_BATCH && num_batch_files == 0) {
        fprintf(stderr, "Error: No input files specified after <outdir> for batch mode '-b'.\n");
        print_usage(argv[0]);
        return 1;
    }


    /* --- Execute Selected Mode --- */
    switch (mode) {
        case MODE_COMPRESS:
             if (!file_exists(input_file)) {
                 fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file);
                 return 1;
             }
            processed_size = compress_file(input_file, output_file, quiet_mode, &original_size);
             // Allow success for empty file (processed_size will be header size)
             if (processed_size > 0 || original_size == 0) {
                 result = 0; // Success
                 // Add to list after successful operation
                 if (add_entry_to_file_list(output_file, original_size, processed_size, quiet_mode) != 0) {
                     // Warning handled by helper
                 }
             } else {
                 result = 1; // Failure
             }
            // print_operation_result handled by compress_file if not quiet
            break;

        case MODE_DECOMPRESS:
             if (!file_exists(input_file)) {
                 fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file);
                 return 1;
             }
            processed_size = decompress_file(input_file, output_file, quiet_mode, &original_size);
             // Check for definite failure (return 0 when input size > header size)
             if (processed_size == 0 && original_size > sizeof(size_t)) {
                 result = 1; // Failure
                 if (!quiet_mode) fprintf(stderr, "Decompression failed (corrupted file or I/O error).\n");
             } else {
                 result = 0; // Success (includes empty file case)
                 // We don't add decompressed files to the list by default
             }
            // print_operation_result handled by decompress_file if not quiet
            break;

        case MODE_ENCRYPT:
            if (get_password(password, sizeof(password), 1) != 0) return 1; // Request confirmation
            if (!file_exists(input_file)) {
                fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file);
                memset(password, 0, sizeof(password)); // Clear password before exiting
                return 1;
            }
            processed_size = encrypt_file(input_file, output_file, password, iterations, quiet_mode, &original_size);
            memset(password, 0, sizeof(password)); // Clear password immediately after use

            if (processed_size > 0) {
                result = 0; // Success
                // Add to list after successful operation
                if (add_entry_to_file_list(output_file, original_size, processed_size, quiet_mode) != 0) {
                     // Warning already printed by helper function if not quiet
                }
            } else {
                result = 1; // Failure indicated by encrypt_file returning 0
            }
            // print_operation_result handled by encrypt_file if not quiet
            break;

        case MODE_DECRYPT:
            if (get_password(password, sizeof(password), 0) != 0) return 1;
             if (!file_exists(input_file)) {
                 fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file);
                 memset(password, 0, sizeof(password));
                 return 1;
             }
            processed_size = decrypt_file(input_file, output_file, password, iterations, quiet_mode, &original_size);
            memset(password, 0, sizeof(password));

            // Check for definite failure (return 0 when input size > salt size)
            if (processed_size == 0 && original_size > DEFAULT_SALT_SIZE) {
                 result = 1; // Definite failure
                 if (!quiet_mode) fprintf(stderr, "Decryption failed (I/O error or file too small).\n");
            } else {
                 // Assume success otherwise (might be garbage output on wrong password)
                 result = 0;
                 // We don't add decrypted files to the list by default
            }
            // print_operation_result handled by decrypt_file if not quiet
            break;

        case MODE_PROCESS: // Compress + Encrypt
            if (get_password(password, sizeof(password), 1) != 0) return 1; // Request confirmation
             if (!file_exists(input_file)) {
                 fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file);
                 memset(password, 0, sizeof(password));
                 return 1;
             }
            processed_size = process_file(input_file, output_file, password, iterations, quiet_mode, &original_size);
            memset(password, 0, sizeof(password)); // Clear password

             if (processed_size > 0) {
                 result = 0; // Success
                 // Add to list after successful operation
                 if (add_entry_to_file_list(output_file, original_size, processed_size, quiet_mode) != 0) {
                     // Warning handled by helper
                 }
             } else {
                 result = 1; // Failure
             }
            // process_file prints its own summary and result if not quiet
            break;

        case MODE_EXTRACT: // Decrypt + Decompress
            if (get_password(password, sizeof(password), 0) != 0) return 1;
             if (!file_exists(input_file)) {
                 fprintf(stderr, "Error: Input file '%s' does not exist or cannot be read.\n", input_file);
                 memset(password, 0, sizeof(password));
                 return 1;
             }
            processed_size = extract_file(input_file, output_file, password, iterations, quiet_mode, &original_size);
            memset(password, 0, sizeof(password)); // Clear password

             // Check for definite failure
             if (processed_size == 0 && original_size > DEFAULT_SALT_SIZE + sizeof(size_t)) {
                 result = 1; // Failure
                 if (!quiet_mode) fprintf(stderr, "Extraction failed (decryption or decompression error).\n");
             } else {
                 result = 0; // Assume success otherwise
                 // We don't add extracted files to the list by default
             }
            // extract_file prints its own summary and result if not quiet
            break;

        case MODE_LIST:
            result = handle_file_list("list", NULL, quiet_mode);
            break;

        case MODE_FIND:
            result = handle_file_list("find", input_file, quiet_mode); // input_file holds the pattern here
            break;

        case MODE_BATCH:
            if (get_password(password, sizeof(password), 1) != 0) return 1; // Request confirmation
            result = batch_process(batch_files, num_batch_files, output_dir, password, iterations, quiet_mode);
            memset(password, 0, sizeof(password)); // Clear password
            // batch_process prints its own summary and result if not quiet
            break;

        case MODE_HELP:
        default: // Should not be reached if initial mode check is correct
            print_usage(argv[0]);
            result = (mode == MODE_HELP) ? 0 : 1; // Showing help isn't an error
            break;
    }

    return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE; // Use standard exit codes
}