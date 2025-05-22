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
#define PROGRESS_WIDTH 30                                                                           // Width of the progress bar

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

/* Default values */
#define DEFAULT_KEY_ITERATIONS 10000      /* Default iterations for key derivation */
#define DEFAULT_SALT_SIZE 16              /* Default salt size in bytes */
#define DEFAULT_FILE_LIST "file_list.dat" /* Default file list filename */
#define DEFAULT_OUTPUT_DIR "output"       /* Default output directory for batch */
#define MAX_FILENAME 256                  /* Maximum filename length */
#define MAX_PASSWORD 128                  /* Maximum password length */
#define MAX_BATCH_FILES 100               /* Maximum number of files in batch mode */
#define BUFFER_SIZE 4096                  /* Buffer size for file processing */

/* Function prototypes */
// Replaced uint8_t with unsigned char, size_t with unsigned long where appropriate
void print_hex(const char *label, const unsigned char *data, unsigned long len);
void print_usage(const char *program_name);
void print_progress_bar(unsigned long current, unsigned long total, unsigned long width);
void print_operation_result(int result, const char *operation);
void print_processing_summary(const char *operation, const char *input_file, const char *output_file,
                              unsigned long input_size, unsigned long output_size);
void print_section_header(const char *title);
int get_password(char *password, unsigned long max_len, int confirm);
int ensure_directory_exists(const char *directory);
int file_exists(const char *filename);
int add_entry_to_file_list(const char *output_file, unsigned long original_size, unsigned long processed_size, int quiet);
unsigned long encrypt_file(const char *input_file, const char *output_file,
                           const char *password, int iterations, int quiet, unsigned long *original_size_out);
unsigned long decrypt_file(const char *input_file, const char *output_file,
                           const char *password, int iterations, int quiet, unsigned long *original_size_out);
unsigned long compress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out);
unsigned long decompress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out);
unsigned long process_file(const char *input_file, const char *output_file,
                           const char *password, int iterations, int quiet, unsigned long *original_size_out);
unsigned long extract_file(const char *input_file, const char *output_file,
                           const char *password, int iterations, int quiet, unsigned long *original_size_out);
int handle_file_list(const char *command, const char *filename, int quiet);
int batch_process(char *filenames[], int num_files, const char *output_dir,
                  const char *password, int iterations, int quiet);

/**
 * Print binary data in a readable hexadecimal format (only if DEBUG defined)
 */
#ifdef DEBUG
// Replaced uint8_t with unsigned char, size_t with unsigned long
void print_hex(const char *label, const unsigned char *data, unsigned long len)
{
    unsigned long i; // Replaced size_t with unsigned long
    printf("[Main] %s: ", label);
    // Limit printing for very long data to avoid excessive output
    unsigned long print_len = (len > 64) ? 64 : len; // Replaced size_t with unsigned long
    for (i = 0; i < print_len; i++)
    {
        printf("%02x", data[i]);
        if ((i + 1) % 4 == 0 && i + 1 < print_len)
            printf(" ");
    }
    if (len > 64)
        printf("... (%lu bytes total)", len); // Use %lu for unsigned long
    printf("\n");
}
#endif // DEBUG (print_hex is defined only in debug mode)

/**
 * Print program usage instructions
 */
void print_usage(const char *program_name)
{
    printf("Secure File Processor\n\n");

    printf("USAGE:\n");
    printf("  %s [MODE] [OPTIONS] [FILE(S)]\n\n", program_name);

    printf("MODES:\n");
    printf("  -c <input> <output>    Compress a file\n");
    printf("  -x <input> <output>    Decompress a file\n");
    printf("  -e <input> <output>    Encrypt a file (with password prompt)\n");
    printf("  -d <input> <output>    Decrypt a file (with password prompt)\n");
    printf("  -p <input> <output>    Process a file (compress then encrypt)\n");
    printf("  -u <input> <output>    Extract a file (decrypt then decompress)\n");
    printf("  -l                     List processed files (from %s)\n", DEFAULT_FILE_LIST);
    printf("  -f <pattern>           Find files matching pattern in list\n");
    printf("  -b <outdir> <files..>  Batch process (compress+encrypt) multiple files\n");
    printf("  -h, --help             Show this help information\n\n");

    printf("OPTIONS:\n");
    printf("  -i <num>                 Number of iterations for key derivation (default: %d)\n", DEFAULT_KEY_ITERATIONS);
    printf("  -q                       Quiet mode (minimal output, suppresses progress bars and summaries)\n\n");

    printf("EXAMPLES:\n");
    printf("  %s -e document.txt document.enc                   # Encrypt a file\n", program_name);
    printf("  %s -d document.enc document.txt                   # Decrypt a file\n", program_name);
    printf("  %s -p report.pdf report.pdf.sec -i 20000          # Compress and encrypt with more iterations\n", program_name);
    printf("  %s -u report.pdf.sec report.pdf                   # Decrypt and decompress\n", program_name);
    printf("  %s -b secure_files file1.txt image.jpg            # Batch process files into 'secure_files' dir\n", program_name);
    printf("  %s -l                                             # List all processed files\n", program_name);
    printf("  %s -f report                                      # Find files containing 'report' in the list\n\n", program_name);

    printf("Note: For operations requiring encryption/decryption (-e, -d, -p, -u, -b), you will be prompted for a password.\n");
}

/**
 * Print a progress bar to show operation progress
 */
// Replaced size_t with unsigned long
void print_progress_bar(unsigned long current, unsigned long total, unsigned long width)
{
    // Avoid division by zero if total is 0 (e.g., empty file)
    float percent = (total == 0) ? 1.0f : (float)current / total;
    // Ensure percent doesn't exceed 1.0 due to potential rounding issues
    if (percent > 1.0f)
        percent = 1.0f;

    unsigned long filled_width = (unsigned long)(width * percent); // Replaced size_t with unsigned long

    printf(CLEAR_LINE); // Clear the current line
    printf("[");

    /* Print filled portion */
    unsigned long i; // Replaced size_t with unsigned long
    for (i = 0; i < filled_width; i++)
    {
        printf("=");
    }

    /* Print cursor if not full */
    if (filled_width < width)
    {
        printf(">");
        i++;
    }

    /* Print empty portion */
    for (; i < width; i++)
    {
        printf(" ");
    }

    /* Print percentage */
    // Use %lu for unsigned long which is standard C99
    printf("] %5.1f%% (%lu/%lu bytes)", percent * 100.0f, current, total);
    fflush(stdout); // Ensure progress bar updates immediately
}

/**
 * Print operation result with appropriate formatting
 */
void print_operation_result(int result, const char *operation)
{
    // Add newline before result for better spacing if progress bar was used
    printf("\n");
    if (result == 0)
    {
        printf("--> %s completed successfully.\n", operation);
    }
    else
    {
        // Use fprintf to stderr for errors
        fprintf(stderr, "--> ERROR: %s failed.\n", operation);
    }
}

/**
 * Print a summary of file processing operation
 */
// Replaced size_t with unsigned long
void print_processing_summary(const char *operation, const char *input_file, const char *output_file,
                              unsigned long input_size, unsigned long output_size)
{
    // Avoid division by zero for ratio calculation
    float ratio = (input_size == 0) ? 0.0f : (float)output_size * 100.0f / input_size;

    printf("\n--> %s Summary:\n", operation);
    printf("    Input:  %s (%lu bytes)\n", input_file, input_size);   // Use %lu
    printf("    Output: %s (%lu bytes)\n", output_file, output_size); // Use %lu
    // Only show ratio if input size is non-zero
    if (input_size > 0)
    {
        printf("    Ratio:  %.2f%%\n", ratio);
        // Only show savings if ratio is less than 100%
        if (ratio < 100.0f && ratio >= 0.0f)
        { // ensure ratio is not negative (e.g. if output > input)
            printf("    Saved:  %.2f%%\n", 100.0f - ratio);
        }
        else if (ratio > 100.0f)
        {
            printf("    Growth: %.2f%%\n", ratio - 100.0f);
        }
    }
    else
    {
        printf("    Ratio:  N/A (input size is 0)\n");
    }
}

/**
 * Print a section header
 */
void print_section_header(const char *title)
{
    printf("\n--- %s ---\n", title);
}

/**
 * Check if a file exists and is readable
 */
int file_exists(const char *filename)
{
    FILE *file = fopen(filename, "rb"); // Open for binary read
    if (file)
    {
        fclose(file);
        return 1; // File exists and is readable
    }
    return 0; // File does not exist or cannot be opened
}

/**
 * Create a directory if it doesn't exist (basic cross-platform attempt)
 */
int ensure_directory_exists(const char *directory)
{
    char command[MAX_FILENAME * 2];

    if (directory == NULL || directory[0] == '\0')
    {
        fprintf(stderr, "Error: Invalid directory path provided.\n");
        return -1;
    }

    // Simple check: try to open the directory. This is not a perfect check.
    // A more robust way involves stat() which is POSIX, or platform specific APIs.
    // For this project, relying on mkdir's behavior is simpler.
    FILE *dir_check = fopen(directory, "r");
    if (dir_check)
    {
        fclose(dir_check);
        // Directory likely exists (or it's a file, mkdir will fail then)
        return 0;
    }

#ifdef _WIN32
    snprintf(command, sizeof(command), "mkdir \"%s\"", directory);
#else // POSIX-like systems
    snprintf(command, sizeof(command), "mkdir -p \"%s\"", directory);
#endif
    command[sizeof(command) - 1] = '\0'; // Ensure null termination

    int status = system(command);

    if (status != 0)
    {
        // system() return value is complex. mkdir -p returns 0 if dir exists or created.
        // On Windows, mkdir returns 0 on success.
        // A non-zero status might indicate a real error (e.g., permission denied).
        // We can't be certain without more checks, so we'll proceed and let fopen fail later if needed.
        DEBUG_PRINT("system(\"%s\") returned status %d. Directory might not have been created if it didn't exist or error occurred.\n", command, status);
    }
    return 0; // Assume success or directory already exists/will be handled by fopen
}

/**
 * Prompt for a password with optional confirmation.
 * Handles potential errors during input.
 */
// Replaced size_t with unsigned long for max_len
int get_password(char *password, unsigned long max_len, int confirm)
{
    char confirm_password[MAX_PASSWORD];

    if (max_len == 0)
        return -1; // Cannot read into zero-length buffer

    printf("Enter password: ");
    fflush(stdout);
    if (fgets(password, (int)max_len, stdin) == NULL)
    { // fgets expects int for size
        if (feof(stdin))
        {
            fprintf(stderr, "\nError: End-of-file reached while reading password.\n");
        }
        else
        {
            fprintf(stderr, "\nError reading password.\n");
        }
        clearerr(stdin);
        return -1;
    }
    password[strcspn(password, "\n")] = '\0';

    if (password[0] == '\0')
    {
        fprintf(stderr, "Error: Password cannot be empty.\n");
        return -1;
    }

    if (confirm)
    {
        printf("Confirm password: ");
        fflush(stdout);
        if (fgets(confirm_password, sizeof(confirm_password), stdin) == NULL)
        {
            if (feof(stdin))
            {
                fprintf(stderr, "\nError: End-of-file reached while reading password confirmation.\n");
            }
            else
            {
                fprintf(stderr, "\nError reading password confirmation.\n");
            }
            clearerr(stdin);
            memset(password, 0, max_len);
            return -1;
        }
        confirm_password[strcspn(confirm_password, "\n")] = '\0';

        if (strcmp(password, confirm_password) != 0)
        {
            fprintf(stderr, "Error: Passwords do not match.\n");
            memset(password, 0, max_len);
            memset(confirm_password, 0, sizeof(confirm_password));
            return -1;
        }
        memset(confirm_password, 0, sizeof(confirm_password));
    }
    return 0;
}

// Replaced size_t with unsigned long for original_size and processed_size
int add_entry_to_file_list(const char *output_file, unsigned long original_size, unsigned long processed_size, int quiet)
{
    file_list_t file_list;
    file_list_init(&file_list);

    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        DEBUG_PRINT("Creating new file list or failed to load existing one from %s.\n", DEFAULT_FILE_LIST);
        file_list_free(&file_list); // Ensure clean state
        file_list_init(&file_list); // Re-initialize
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

/**
 * Encrypt a file using ChaCha20
 * Returns the final size of the encrypted file (including salt) on success, or 0 on failure.
 */
// Replaced size_t with unsigned long
unsigned long encrypt_file(const char *input_file, const char *output_file,
                           const char *password, int iterations, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    unsigned char *buffer = NULL, *output_buffer = NULL;           // Replaced uint8_t with unsigned char
    unsigned char key[CHACHA20_KEY_SIZE];                          // Replaced uint8_t with unsigned char
    unsigned char nonce[CHACHA20_NONCE_SIZE];                      // Replaced uint8_t with unsigned char
    unsigned char salt[DEFAULT_SALT_SIZE];                         // Replaced uint8_t with unsigned char
    unsigned long read_size, file_size = 0, original_size_val = 0; // Replaced size_t with unsigned long
    int result_flag = 0;                                           // 0 for success, -1 for failure
    unsigned long final_output_size = 0;                           // Track final size including salt // Replaced size_t with unsigned long

    if (!quiet)
    {
        print_section_header("File Encryption");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
        printf("Using %d iterations for key derivation\n", iterations);
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
    original_size_val = ftell(in); // ftell returns long, assign to unsigned long
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

    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, iterations,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0)
    {
        fprintf(stderr, "Error: Failed to derive key and nonce from password.\n");
        result_flag = -1;
        goto cleanup_encrypt;
    }

    DEBUG_PRINT("Using %d iterations for key derivation\n", iterations);
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);

    if (chacha20_init(&ctx, key, nonce, 1) != 0)
    {
        fprintf(stderr, "Error: Failed to initialize ChaCha20 context.\n");
        result_flag = -1;
        goto cleanup_encrypt;
    }

    buffer = (unsigned char *)malloc(BUFFER_SIZE);        // Replaced uint8_t with unsigned char
    output_buffer = (unsigned char *)malloc(BUFFER_SIZE); // Replaced uint8_t with unsigned char

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

/**
 * Decrypt a file using ChaCha20
 * Returns the final size of the decrypted file on success, or 0 on failure.
 */
// Replaced size_t with unsigned long
unsigned long decrypt_file(const char *input_file, const char *output_file,
                           const char *password, int iterations, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    unsigned char *buffer = NULL, *output_buffer = NULL;          // Replaced uint8_t with unsigned char
    unsigned char key[CHACHA20_KEY_SIZE];                         // Replaced uint8_t with unsigned char
    unsigned char nonce[CHACHA20_NONCE_SIZE];                     // Replaced uint8_t with unsigned char
    unsigned char salt[DEFAULT_SALT_SIZE];                        // Replaced uint8_t with unsigned char
    unsigned long read_size, file_size = 0, total_input_size = 0; // Replaced size_t with unsigned long
    int result_flag = 0;                                          // 0=success, -1=potential decrypt error, -2=definite I/O/mem error
    unsigned long final_output_size = 0;                          // Replaced size_t with unsigned long

    if (!quiet)
    {
        print_section_header("File Decryption");
        printf("Input:  %s\n", input_file);
        printf("Output: %s\n", output_file);
        printf("Using %d iterations for key derivation\n", iterations);
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
        fprintf(stderr, "Error: Input file '%s' is too small (%lu bytes) to be valid encrypted data.\n", input_file, total_input_size); // Use %lu
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
    PRINT_HEX("Read salt", salt, DEFAULT_SALT_SIZE);

    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, iterations,
                             key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0)
    {
        fprintf(stderr, "Error: Failed to derive key and nonce from password.\n");
        result_flag = -2;
        goto cleanup_decrypt;
    }
    DEBUG_PRINT("Using %d iterations for key derivation\n", iterations);
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);

    if (chacha20_init(&ctx, key, nonce, 1) != 0)
    {
        fprintf(stderr, "Error: Failed to initialize ChaCha20 context.\n");
        result_flag = -2;
        goto cleanup_decrypt;
    }

    buffer = (unsigned char *)malloc(BUFFER_SIZE);        // Replaced uint8_t with unsigned char
    output_buffer = (unsigned char *)malloc(BUFFER_SIZE); // Replaced uint8_t with unsigned char
    if (buffer == NULL || output_buffer == NULL)
    {
        fprintf(stderr, "Error: Memory allocation failed for buffers.\n");
        result_flag = -2;
        goto cleanup_decrypt;
    }

    unsigned long data_to_decrypt_size = total_input_size - DEFAULT_SALT_SIZE; // Replaced size_t with unsigned long
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
            break; // Should not happen if logic above is correct

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

/**
 * Compress a file using Huffman coding
 * Returns the final size of the compressed file (including header) on success, or 0 on failure.
 */
// Replaced size_t with unsigned long
unsigned long compress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buffer = NULL, *output_buffer = NULL;                    // Replaced uint8_t with unsigned char
    unsigned long read_size_val, output_size_val, total_input_size_val = 0; // Replaced size_t with unsigned long
    int result_flag = 0;
    unsigned long total_output_size_val = 0; // Replaced size_t with unsigned long

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
        buffer = (unsigned char *)malloc(total_input_size_val); // Replaced uint8_t with unsigned char
        if (buffer == NULL)
        {
            fprintf(stderr, "Error: Memory allocation failed for input buffer (%lu bytes).\n", total_input_size_val); // Use %lu
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

    unsigned long output_max_len_val = huffman_worst_case_size(read_size_val);                // Replaced size_t with unsigned long
    output_buffer = (unsigned char *)malloc(output_max_len_val > 0 ? output_max_len_val : 1); // Replaced uint8_t with unsigned char
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

/**
 * Decompress a file that was compressed using Huffman coding
 * Returns the final size of the decompressed file on success, or 0 on failure.
 */
// Replaced size_t with unsigned long
unsigned long decompress_file(const char *input_file, const char *output_file, int quiet, unsigned long *original_size_out)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buffer = NULL, *output_buffer = NULL;                             // Replaced uint8_t with unsigned char
    unsigned long compressed_data_size, output_size_val, expected_original_size = 0; // Replaced size_t with unsigned long
    int result_flag = 0;
    unsigned long input_actual_file_size = 0; // Replaced size_t with unsigned long

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
        fprintf(stderr, "Error: Input file '%s' is too small (%lu bytes) to contain header.\n", input_file, input_actual_file_size); // Use %lu
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
        buffer = (unsigned char *)malloc(compressed_data_size); // Replaced uint8_t with unsigned char
        if (buffer == NULL)
        {
            fprintf(stderr, "Error: Memory allocation failed for compressed data buffer (%lu bytes).\n", compressed_data_size); // Use %lu
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
    { // Header says there should be data, but no compressed data found
        fprintf(stderr, "Error: Compressed file format error - header indicates %lu original bytes, but no compressed data found.\n", expected_original_size);
        result_flag = -1;
        goto cleanup_decompress;
    }
    else
    { // expected_original_size is 0 and compressed_data_size is 0
        buffer = NULL;
    }

    output_buffer = (unsigned char *)malloc(expected_original_size > 0 ? expected_original_size : 1); // Replaced uint8_t with unsigned char
    if (output_buffer == NULL)
    {
        fprintf(stderr, "Error: Memory allocation failed for output buffer (%lu bytes).\n", expected_original_size); // Use %lu
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
        fprintf(stderr, "\nError: Decompressed size (%lu) does not match expected size from header (%lu). File might be corrupted.\n", output_size_val, expected_original_size); // Use %lu
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

/**
 * Process a file (compress and encrypt)
 * Returns the final size of the processed file on success, or 0 on failure.
 */
// Replaced size_t with unsigned long
unsigned long process_file(const char *input_file, const char *output_file,
                           const char *password, int iterations, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long compressed_size_val = 0;     // Replaced size_t with unsigned long
    unsigned long final_size_val = 0;          // Replaced size_t with unsigned long
    unsigned long original_input_size_val = 0; // Replaced size_t with unsigned long

    snprintf(temp_file, sizeof(temp_file), "%s.tmp_compress", output_file); // More specific temp name
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
    // compress_file returns 0 on failure, or size of compressed file (which can be >0 even for empty original file due to header)
    if (compressed_size_val == 0 && original_input_size_val > 0)
    { // Failed if original was not empty but compressed is 0
        fprintf(stderr, "Error: Compression step failed for input '%s'.\n", input_file);
        remove(temp_file);
        return 0;
    }
    // If original was empty, compressed_size_val will be header size (non-zero). This is success.

    if (!quiet)
        printf("\n--- Encryption Step ---\n");
    final_size_val = encrypt_file(temp_file, output_file, password, iterations, quiet, NULL); // Last arg NULL as we don't need compressed size out
    if (final_size_val == 0 && compressed_size_val > 0)
    { // Failed if compressed was not empty but final is 0
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

/**
 * Extract a file (decrypt and decompress)
 * Returns the final size of the extracted file on success, or 0 on failure.
 */
// Replaced size_t with unsigned long
unsigned long extract_file(const char *input_file, const char *output_file,
                           const char *password, int iterations, int quiet, unsigned long *original_size_out)
{
    char temp_file[MAX_FILENAME];
    unsigned long decrypted_size_val = 0;      // Replaced size_t with unsigned long
    unsigned long final_size_val = 0;          // Replaced size_t with unsigned long
    unsigned long original_input_size_val = 0; // Replaced size_t with unsigned long

    snprintf(temp_file, sizeof(temp_file), "%s.tmp_decrypt", output_file); // More specific temp name
    temp_file[sizeof(temp_file) - 1] = '\0';

    if (!quiet)
    {
        print_section_header("File Extraction (Decrypt + Decompress)");
    }

    if (!quiet)
        printf("\n--- Decryption Step ---\n");
    decrypted_size_val = decrypt_file(input_file, temp_file, password, iterations, quiet, &original_input_size_val);
    if (original_size_out)
    {
        *original_size_out = original_input_size_val;
    }
    // decrypt_file returns 0 on definite I/O/mem error, or if input too small.
    // It returns >0 (decrypted size) on success or potential password error.
    if (decrypted_size_val == 0 && original_input_size_val > DEFAULT_SALT_SIZE)
    {
        fprintf(stderr, "Error: Decryption step failed for input '%s' (I/O or memory error).\n", input_file);
        remove(temp_file);
        return 0;
    }
    // If original_input_size_val <= DEFAULT_SALT_SIZE, decrypt_file already returned 0 for "too small" error.

    if (!quiet)
        printf("\n--- Decompression Step ---\n");
    final_size_val = decompress_file(temp_file, output_file, quiet, NULL); // Last arg NULL
    // decompress_file returns 0 on failure.
    // If decrypted_size_val was just header (e.g. empty original file was compressed then encrypted),
    // decompress should handle this and return 0 (final_size_val).
    if (final_size_val == 0 && decrypted_size_val > sizeof(unsigned long))
    { // Failed if decrypted had data but final is 0
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

/**
 * Handle file list operations (list, find)
 */
int handle_file_list(const char *command, const char *filename_pattern, int quiet)
{
    file_list_t file_list;
    file_entry_t *found_entry; // Renamed to avoid conflict
    int op_result = 0;         // 0 for success

    file_list_init(&file_list);

    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0)
    {
        // This is not an error if the file doesn't exist, it means an empty list.
        // file_list_load should handle this gracefully and initialize an empty list.
        // Or, if it returns error, we assume list is empty.
        if (!quiet)
        {
            DEBUG_PRINT("Info: File list '%s' not found or is empty/corrupted. Proceeding with empty list.\n", DEFAULT_FILE_LIST);
            // Ensure list is truly empty if load failed badly
            file_list_free(&file_list);
            file_list_init(&file_list);
        }
    }

    if (strcmp(command, "list") == 0)
    {
        if (!quiet)
            print_section_header("File List Contents");
        printf("Source: %s\n", DEFAULT_FILE_LIST);
        file_list_print(&file_list); // Uses %lu for list.count
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
                printf("    Sequence: #%lu\n", found_entry->sequence_num);              // %lu
                printf("    Original size: %lu bytes\n", found_entry->original_size);   // %lu
                printf("    Processed size: %lu bytes\n", found_entry->processed_size); // %lu
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

/**
 * Process multiple files in batch mode (Compress + Encrypt)
 */
int batch_process(char *filenames[], int num_files, const char *output_dir_path, // Renamed output_dir
                  const char *password, int iterations, int quiet)
{
    char output_file_path[MAX_FILENAME]; // Renamed output_file
    char *current_filename_only;         // Renamed filename_only
    int overall_op_result = 0;           // Renamed overall_result
    int i, success_count = 0;
    unsigned long original_file_size, processed_file_size; // Renamed and type changed // Replaced size_t with unsigned long

    if (!quiet)
    {
        print_section_header("Batch Processing (Compress + Encrypt)");
        printf("Files to process: %d\n", num_files);
        printf("Output directory: %s\n", output_dir_path);
        printf("Using %d iterations for key derivation\n", iterations);
    }

    if (ensure_directory_exists(output_dir_path) != 0)
    {
        // Error already printed by ensure_directory_exists
        return -1;
    }

    for (i = 0; i < num_files; i++)
    {
        current_filename_only = strrchr(filenames[i], '/');
        char *current_filename_only_bs = strrchr(filenames[i], '\\');
        if (current_filename_only_bs > current_filename_only)
        {
            current_filename_only = current_filename_only_bs;
        }
        current_filename_only = (current_filename_only == NULL) ? filenames[i] : current_filename_only + 1;

        if (*current_filename_only == '\0')
        {
            fprintf(stderr, "\n[%d/%d] Skipping invalid input filename: '%s'\n", i + 1, num_files, filenames[i]);
            overall_op_result = -1;
            continue;
        }

        snprintf(output_file_path, sizeof(output_file_path), "%s/%s.sec", output_dir_path, current_filename_only);
        output_file_path[sizeof(output_file_path) - 1] = '\0';

        if (!quiet)
        {
            printf("\n[%d/%d] Processing file:\n", i + 1, num_files);
            printf("    Input:  %s\n", filenames[i]);
            printf("    Output: %s\n", output_file_path);
        }

        if (!file_exists(filenames[i]))
        {
            fprintf(stderr, "    Status: Failed (Input file '%s' not found)\n", filenames[i]);
            overall_op_result = -1;
            continue;
        }

        processed_file_size = process_file(filenames[i], output_file_path, password, iterations, quiet, &original_file_size);
        if (processed_file_size > 0)
        { // process_file returns 0 on failure
            success_count++;
            if (add_entry_to_file_list(output_file_path, original_file_size, processed_file_size, quiet) != 0)
            {
                if (!quiet)
                {
                    fprintf(stderr, "    Warning: Failed to add '%s' to file list '%s'.\n", output_file_path, DEFAULT_FILE_LIST);
                }
            }
        }
        else
        {
            overall_op_result = -1;
        }
    }

    if (!quiet)
    {
        print_section_header("Batch Processing Summary");
        printf("Total files attempted: %d\n", num_files);
        printf("Successful:            %d\n", success_count);
        printf("Failed:                %d\n", num_files - success_count);
        if (overall_op_result == 0)
        {
            printf("\nAll files processed successfully!\n");
        }
        else
        {
            printf("\nSome files failed to process. Check the output above for details.\n");
        }
    }
    return overall_op_result;
}

int main(int argc, char *argv[])
{
    int operation_mode = MODE_HELP;                            // Renamed mode
    char *input_file_arg = NULL, *output_file_arg = NULL;      // Renamed
    char current_password[MAX_PASSWORD];                       // Renamed password
    int key_iterations = DEFAULT_KEY_ITERATIONS;               // Renamed iterations
    int quiet_operation = 0;                                   // Renamed quiet_mode
    char *batch_input_files[MAX_BATCH_FILES];                  // Renamed batch_files
    int num_batch_input_files = 0;                             // Renamed num_batch_files
    char *batch_output_dir = DEFAULT_OUTPUT_DIR;               // Renamed output_dir
    int final_result = 0;                                      // Renamed result
    unsigned long original_op_size = 0, processed_op_size = 0; // Renamed and type changed // Replaced size_t with unsigned long

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

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

    int arg_parse_index = 2; // Renamed file_arg_start_index

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

    for (int i = arg_parse_index; i < argc; i++)
    {
        if (strcmp(argv[i], "-i") == 0)
        {
            if (++i < argc)
            {
                key_iterations = atoi(argv[i]);
                if (key_iterations <= 0)
                {
                    fprintf(stderr, "Error: Invalid number of iterations '%s'. Must be positive.\n", argv[i]);
                    return 1;
                }
            }
            else
            {
                fprintf(stderr, "Error: Missing argument for -i option.\n");
                print_usage(argv[0]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-q") == 0)
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

    if (operation_mode == MODE_BATCH && num_batch_input_files == 0)
    {
        fprintf(stderr, "Error: No input files specified after <outdir> for batch mode '-b'.\n");
        print_usage(argv[0]);
        return 1;
    }

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
            { /* Warned by helper */
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
        { // sizeof(unsigned long) is header size
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
        processed_op_size = encrypt_file(input_file_arg, output_file_arg, current_password, key_iterations, quiet_operation, &original_op_size);
        memset(current_password, 0, sizeof(current_password));
        if (processed_op_size > 0)
        {
            final_result = 0;
            if (add_entry_to_file_list(output_file_arg, original_op_size, processed_op_size, quiet_operation) != 0)
            { /* Warned by helper */
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
        processed_op_size = decrypt_file(input_file_arg, output_file_arg, current_password, key_iterations, quiet_operation, &original_op_size);
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
        processed_op_size = process_file(input_file_arg, output_file_arg, current_password, key_iterations, quiet_operation, &original_op_size);
        memset(current_password, 0, sizeof(current_password));
        if (processed_op_size > 0)
        {
            final_result = 0;
            if (add_entry_to_file_list(output_file_arg, original_op_size, processed_op_size, quiet_operation) != 0)
            { /* Warned by helper */
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
        processed_op_size = extract_file(input_file_arg, output_file_arg, current_password, key_iterations, quiet_operation, &original_op_size);
        memset(current_password, 0, sizeof(current_password));
        if (processed_op_size == 0 && original_op_size > DEFAULT_SALT_SIZE + sizeof(unsigned long))
        { // Salt + huffman header
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
        final_result = batch_process(batch_input_files, num_batch_input_files, batch_output_dir, current_password, key_iterations, quiet_operation);
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
