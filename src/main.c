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
 *   gcc -Wall -Iinclude -o secure_processor src/main.c src/encryption/chacha20.c src/encryption/key_derivation.c src/compression/huffman.c src/utils/file_list.c
 *   
 * For debug build:
 *   gcc -Wall -DDEBUG -Iinclude -o secure_processor src/main.c src/encryption/chacha20.c src/encryption/key_derivation.c src/compression/huffman.c src/utils/file_list.c
 * 
 * This program provides a comprehensive file security solution with:
 * 1. ChaCha20 encryption/decryption (RFC 8439)
 * 2. Run-Length Encoding compression/decompression
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
#include <time.h>
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

/* Program modes */
#define MODE_DEMO        0  /* Run a simple demonstration */
#define MODE_ENCRYPT     1  /* Encrypt a file */
#define MODE_DECRYPT     2  /* Decrypt a file */
#define MODE_COMPRESS    3  /* Compress a file */
#define MODE_DECOMPRESS  4  /* Decompress a file */
#define MODE_PROCESS     5  /* Process (encrypt+compress) a file */
#define MODE_EXTRACT     6  /* Extract (decompress+decrypt) a file */
#define MODE_TEST        7  /* Run tests */
#define MODE_LIST        8  /* List processed files */
#define MODE_FIND        9  /* Find a file in the list */
#define MODE_BATCH       10 /* Batch process multiple files */

/* Default values */
#define DEFAULT_KEY_ITERATIONS  10000   /* Default iterations for key derivation */
#define DEFAULT_SALT_SIZE       16      /* Default salt size in bytes */
#define DEFAULT_FILE_LIST       "file_list.dat" /* Default file list filename */
#define DEFAULT_OUTPUT_DIR      "output"        /* Default output directory */
#define MAX_FILENAME            256     /* Maximum filename length */
#define MAX_PASSWORD            128     /* Maximum password length */
#define MAX_BATCH_FILES         100     /* Maximum number of files in batch mode */
#define BUFFER_SIZE             4096    /* Buffer size for file processing */

/* Function prototypes */
void print_hex(const char *label, const uint8_t *data, size_t len);
void print_usage(const char *program_name);
int run_demo();
int encrypt_file(const char *input_file, const char *output_file, 
                const char *password, int iterations);
int decrypt_file(const char *input_file, const char *output_file, 
                const char *password, int iterations);
int compress_file(const char *input_file, const char *output_file);
int decompress_file(const char *input_file, const char *output_file);
int process_file(const char *input_file, const char *output_file, 
                const char *password, int iterations);
int extract_file(const char *input_file, const char *output_file, 
                const char *password, int iterations);
int handle_file_list(const char *command, const char *filename);
int batch_process(char *filenames[], int num_files, const char *output_dir, 
                  const char *password, int iterations);
int run_tests();

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
 * Print the usage information for the program
 * 
 * @param program_name The name of the program executable
 */
void print_usage(const char *program_name) {
    printf("Secure File Processor - ChaCha20 Encryption and Huffman Compression\n");
    printf("===========================================================\n\n");
    printf("Usage:\n");
    printf("  %s                        Run a simple demonstration\n", program_name);
    printf("  %s -e infile outfile      Encrypt a file (password prompt)\n", program_name);
    printf("  %s -d infile outfile      Decrypt a file (password prompt)\n", program_name);
    printf("  %s -c infile outfile      Compress a file\n", program_name);
    printf("  %s -x infile outfile      Decompress a file\n", program_name);
    printf("  %s -p infile outfile      Process a file (encrypt+compress)\n", program_name);
    printf("  %s -u infile outfile      Extract a file (decompress+decrypt)\n", program_name);
    printf("  %s -t                     Run tests\n", program_name);
    printf("  %s -l                     List processed files\n", program_name);
    printf("  %s -f filename            Find a file in the list\n", program_name);
    printf("  %s -b outdir file1 file2... Batch process multiple files\n", program_name);
    printf("\nOptions:\n");
    printf("  -i iterations            Number of iterations for key derivation (default: %d)\n", DEFAULT_KEY_ITERATIONS);
    printf("  -q                       Quiet mode (minimal output)\n");
    printf("\nWhen using password options, you will be prompted for a password.\n");
}

/**
 * Run a simple demonstration of encryption and compression
 * 
 * @return 0 on success, non-zero on failure
 */
int run_demo() {
    /* Demo text to encrypt/decrypt and compress/decompress */
    const char *demo_text = "This is a demonstration of ChaCha20 encryption and Huffman compression. "
                           "AAAAAABBBBCCCDDDDDDDD is a good test for Huffman compression.";
    size_t demo_len = strlen(demo_text);
    
    /* For demonstration, use a fixed key and nonce */
    uint8_t demo_key[CHACHA20_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t demo_nonce[CHACHA20_NONCE_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    
    /* Buffers for the demonstration */
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *decrypted = NULL;
    uint8_t *compressed = NULL;
    uint8_t *decompressed = NULL;
    size_t compressed_size = 0;
    size_t decompressed_size = 0;
    
    /* ChaCha20 context */
    chacha20_ctx ctx;
    
    int result = 0;
    int i, success = 1;
    
    printf("Secure File Processor Demonstration\n");
    printf("==================================\n\n");
    
    /* Allocate memory for the demonstration */
    plaintext = (uint8_t *)malloc(demo_len);
    ciphertext = (uint8_t *)malloc(demo_len);
    decrypted = (uint8_t *)malloc(demo_len);
    compressed = (uint8_t *)malloc(rle_worst_case_size(demo_len));
    decompressed = (uint8_t *)malloc(demo_len);
    
    if (!plaintext || !ciphertext || !decrypted || !compressed || !decompressed) {
        fprintf(stderr, "Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Copy the demo text to plaintext buffer */
    memcpy(plaintext, demo_text, demo_len);
    
    printf("Original plaintext: %s\n", plaintext);
    PRINT_HEX("Original plaintext (hex)", plaintext, demo_len);
    
    printf("\n--- ChaCha20 Encryption Demonstration ---\n\n");
    
    /* Encrypt the plaintext */
    if (chacha20_init(&ctx, demo_key, demo_nonce, 0) != 0) {
        fprintf(stderr, "Failed to initialize ChaCha20 context for encryption\n");
        result = -1;
        goto cleanup;
    }
    
    if (chacha20_process(&ctx, plaintext, ciphertext, demo_len) != 0) {
        fprintf(stderr, "Encryption failed\n");
        result = -1;
        goto cleanup;
    }
    
    printf("Encrypted ciphertext (hex): ");
    for (i = 0; i < demo_len; i++) {
        printf("%02x", ciphertext[i]);
        if ((i + 1) % 4 == 0) printf(" ");
    }
    printf("\n");
    
    /* Clean up the context before reusing it */
    chacha20_cleanup(&ctx);
    
    /* Decrypt the ciphertext */
    if (chacha20_init(&ctx, demo_key, demo_nonce, 0) != 0) {
        fprintf(stderr, "Failed to initialize ChaCha20 context for decryption\n");
        result = -1;
        goto cleanup;
    }
    
    if (chacha20_process(&ctx, ciphertext, decrypted, demo_len) != 0) {
        fprintf(stderr, "Decryption failed\n");
        result = -1;
        goto cleanup;
    }
    
    printf("Decrypted plaintext: %s\n", decrypted);
    
    /* Verify decryption */
    for (i = 0; i < demo_len; i++) {
        if (plaintext[i] != decrypted[i]) {
            success = 0;
            break;
        }
    }
    
    printf("Encryption/Decryption verification: %s\n", success ? "PASSED" : "FAILED");
    
    printf("\n--- RLE Compression Demonstration ---\n\n");
    
    /* Compress the plaintext */
    if (rle_compress(plaintext, demo_len, compressed, rle_worst_case_size(demo_len), &compressed_size) != 0) {
        fprintf(stderr, "Compression failed\n");
        result = -1;
        goto cleanup;
    }
    
    printf("Compressed data size: %zu bytes (%.2f%% of original)\n", 
           compressed_size, (float)compressed_size * 100 / demo_len);
    
    /* Decompress the compressed data */
    if (rle_decompress(compressed, compressed_size, decompressed, demo_len, &decompressed_size) != 0) {
        fprintf(stderr, "Decompression failed\n");
        result = -1;
        goto cleanup;
    }
    
    printf("Decompressed data size: %zu bytes\n", decompressed_size);
    printf("Decompressed plaintext: %s\n", decompressed);
    
    /* Verify decompression */
    success = 1;
    if (decompressed_size != demo_len) {
        success = 0;
    } else {
        for (i = 0; i < demo_len; i++) {
            if (plaintext[i] != decompressed[i]) {
                success = 0;
                break;
            }
        }
    }
    
    printf("Compression/Decompression verification: %s\n", success ? "PASSED" : "FAILED");
    
    printf("\n--- File List Demonstration ---\n\n");
    
    /* Initialize a file list */
    file_list_t file_list;
    file_list_init(&file_list);
    
    /* Add some example files */
    file_list_add(&file_list, "example1.txt", 1024, 512);
    file_list_add(&file_list, "document.docx", 8192, 4096);
    file_list_add(&file_list, "image.jpg", 65536, 62000);
    
    /* Print the file list */
    file_list_print(&file_list);
    
    /* Find a file */
    printf("\nSearching for 'doc'...\n");
    file_entry_t *found = file_list_find(&file_list, "doc");
    if (found) {
        printf("Found: %s\n", found->filename);
    } else {
        printf("No matching file found\n");
    }
    
    /* Free the file list */
    file_list_free(&file_list);
    
cleanup:
    /* Free allocated memory */
    if (plaintext) free(plaintext);
    if (ciphertext) free(ciphertext);
    if (decrypted) free(decrypted);
    if (compressed) free(compressed);
    if (decompressed) free(decompressed);
    
    /* Clean up the context */
    chacha20_cleanup(&ctx);
    
    return result;
}

/**
 * Encrypt a file using ChaCha20
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param password    Password for encryption
 * @param iterations  Number of iterations for key derivation
 * @return            0 on success, non-zero on failure
 */
int encrypt_file(const char *input_file, const char *output_file, 
                const char *password, int iterations) {
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t salt[DEFAULT_SALT_SIZE];
    size_t read_size, file_size = 0, original_size = 0;
    int result = 0;
    
    printf("Encrypting file '%s' to '%s'\n", input_file, output_file);
    
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        perror("Error opening input file");
        return -1;
    }
    
    /* Get file size */
    fseek(in, 0, SEEK_END);
    original_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        perror("Error opening output file");
        fclose(in);
        return -1;
    }
    
    /* Generate a random salt */
    if (generate_salt(salt, DEFAULT_SALT_SIZE) != 0) {
        fprintf(stderr, "Failed to generate salt\n");
        result = -1;
        goto cleanup;
    }
    
    /* Write the salt to the output file */
    if (fwrite(salt, 1, DEFAULT_SALT_SIZE, out) != DEFAULT_SALT_SIZE) {
        perror("Error writing salt to output file");
        result = -1;
        goto cleanup;
    }
    
    /* Derive key and nonce from password */
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, iterations,
                            key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0) {
        fprintf(stderr, "Failed to derive key and nonce from password\n");
        result = -1;
        goto cleanup;
    }
    
    DEBUG_PRINT("Using %d iterations for key derivation\n", iterations);
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);
    
    /* Initialize ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, 1) != 0) {
        fprintf(stderr, "Failed to initialize ChaCha20 context\n");
        result = -1;
        goto cleanup;
    }
    
    /* Allocate buffers */
    buffer = (uint8_t *)malloc(BUFFER_SIZE);
    output_buffer = (uint8_t *)malloc(BUFFER_SIZE);
    
    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        /* Encrypt the chunk */
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0) {
            fprintf(stderr, "ChaCha20 encryption failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Write the encrypted chunk to the output file */
        if (fwrite(output_buffer, 1, read_size, out) != read_size) {
            perror("Error writing to output file");
            result = -1;
            goto cleanup;
        }
        
        file_size += read_size;
        printf("\rProcessed %zu bytes (%.1f%%)", file_size, 
               (float)file_size * 100 / original_size);
        fflush(stdout);
    }
    
    printf("\nFile encrypted successfully!\n");
    
    /* Add to file list */
    file_list_t file_list;
    file_list_init(&file_list);
    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0) {
        /* File doesn't exist or error loading - just continue with empty list */
        DEBUG_PRINT("Creating new file list\n");
    }
    
    file_list_add(&file_list, output_file, original_size, file_size + DEFAULT_SALT_SIZE);
    if (file_list_save(&file_list, DEFAULT_FILE_LIST) != 0) {
        fprintf(stderr, "Warning: Failed to save file list\n");
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
 * @return            0 on success, non-zero on failure
 */
int decrypt_file(const char *input_file, const char *output_file, 
                const char *password, int iterations) {
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t salt[DEFAULT_SALT_SIZE];
    size_t read_size, file_size = 0, total_size = 0;
    int result = 0;
    
    printf("Decrypting file '%s' to '%s'\n", input_file, output_file);
    
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        perror("Error opening input file");
        return -1;
    }
    
    /* Get file size */
    fseek(in, 0, SEEK_END);
    total_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    if (total_size <= DEFAULT_SALT_SIZE) {
        fprintf(stderr, "Input file is too small to be valid\n");
        fclose(in);
        return -1;
    }
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        perror("Error opening output file");
        fclose(in);
        return -1;
    }
    
    /* Read the salt from the input file */
    if (fread(salt, 1, DEFAULT_SALT_SIZE, in) != DEFAULT_SALT_SIZE) {
        perror("Error reading salt from input file");
        result = -1;
        goto cleanup;
    }
    
    PRINT_HEX("Read salt", salt, DEFAULT_SALT_SIZE);
    
    /* Derive key and nonce from password */
    if (derive_key_and_nonce(password, salt, DEFAULT_SALT_SIZE, iterations,
                            key, CHACHA20_KEY_SIZE, nonce, CHACHA20_NONCE_SIZE) != 0) {
        fprintf(stderr, "Failed to derive key and nonce from password\n");
        result = -1;
        goto cleanup;
    }
    
    DEBUG_PRINT("Using %d iterations for key derivation\n", iterations);
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);
    
    /* Initialize ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, 1) != 0) {
        fprintf(stderr, "Failed to initialize ChaCha20 context\n");
        result = -1;
        goto cleanup;
    }
    
    /* Allocate buffers */
    buffer = (uint8_t *)malloc(BUFFER_SIZE);
    output_buffer = (uint8_t *)malloc(BUFFER_SIZE);
    
    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        /* Decrypt the chunk */
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0) {
            fprintf(stderr, "ChaCha20 decryption failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Write the decrypted chunk to the output file */
        if (fwrite(output_buffer, 1, read_size, out) != read_size) {
            perror("Error writing to output file");
            result = -1;
            goto cleanup;
        }
        
        file_size += read_size;
        printf("\rProcessed %zu bytes (%.1f%%)", file_size, 
               (float)file_size * 100 / (total_size - DEFAULT_SALT_SIZE));
        fflush(stdout);
    }
    
    printf("\nFile decrypted successfully!\n");
    
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
 * Compress a file using RLE
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @return            0 on success, non-zero on failure
 */
int compress_file(const char *input_file, const char *output_file) {
    FILE *in = NULL, *out = NULL;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    size_t read_size, output_size, file_size = 0, total_size = 0;
    int result = 0;
    
    printf("Compressing file '%s' to '%s'\n", input_file, output_file);
    
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        perror("Error opening input file");
        return -1;
    }
    
    /* Get file size */
    fseek(in, 0, SEEK_END);
    total_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        perror("Error opening output file");
        fclose(in);
        return -1;
    }
    
    /* Write the original file size to the output file */
    if (fwrite(&total_size, sizeof(size_t), 1, out) != 1) {
        perror("Error writing file size to output file");
        result = -1;
        goto cleanup;
    }
    
    /* Allocate buffers */
    buffer = (uint8_t *)malloc(BUFFER_SIZE);
    output_buffer = (uint8_t *)malloc(rle_worst_case_size(BUFFER_SIZE));
    
    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    size_t total_output_size = sizeof(size_t); /* Account for the file size header */
    
    while ((read_size = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        /* Compress the chunk */
        if (rle_compress(buffer, read_size, output_buffer, 
                      rle_worst_case_size(BUFFER_SIZE), &output_size) != 0) {
            fprintf(stderr, "RLE compression failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Write the compressed chunk size and data to the output file */
        if (fwrite(&output_size, sizeof(size_t), 1, out) != 1) {
            perror("Error writing chunk size to output file");
            result = -1;
            goto cleanup;
        }
        
        if (fwrite(output_buffer, 1, output_size, out) != output_size) {
            perror("Error writing to output file");
            result = -1;
            goto cleanup;
        }
        
        file_size += read_size;
        total_output_size += output_size + sizeof(size_t);
        
        printf("\rProcessed %zu bytes (%.1f%%) - Compression ratio: %.2f%%", 
               file_size, (float)file_size * 100 / total_size,
               (float)total_output_size * 100 / file_size);
        fflush(stdout);
    }
    
    printf("\nFile compressed successfully! Final size: %zu bytes (%.2f%% of original)\n",
           total_output_size, (float)total_output_size * 100 / total_size);
    
    /* Add to file list */
    file_list_t file_list;
    file_list_init(&file_list);
    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0) {
        /* File doesn't exist or error loading - just continue with empty list */
        DEBUG_PRINT("Creating new file list\n");
    }
    
    file_list_add(&file_list, output_file, total_size, total_output_size);
    if (file_list_save(&file_list, DEFAULT_FILE_LIST) != 0) {
        fprintf(stderr, "Warning: Failed to save file list\n");
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
 * Decompress a file that was compressed using RLE
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @return            0 on success, non-zero on failure
 */
int decompress_file(const char *input_file, const char *output_file) {
    FILE *in = NULL, *out = NULL;
    uint8_t *buffer = NULL, *output_buffer = NULL;
    size_t chunk_size, output_size, file_size = 0, original_size = 0;
    int result = 0;
    
    printf("Decompressing file '%s' to '%s'\n", input_file, output_file);
    
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        perror("Error opening input file");
        return -1;
    }
    
    /* Read the original file size from the input file */
    if (fread(&original_size, sizeof(size_t), 1, in) != 1) {
        perror("Error reading original file size from input file");
        fclose(in);
        return -1;
    }
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        perror("Error opening output file");
        fclose(in);
        return -1;
    }
    
    /* Allocate buffers */
    buffer = (uint8_t *)malloc(rle_worst_case_size(BUFFER_SIZE));
    output_buffer = (uint8_t *)malloc(BUFFER_SIZE);
    
    if (buffer == NULL || output_buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    while (fread(&chunk_size, sizeof(size_t), 1, in) == 1) {
        /* Check if chunk size is reasonable */
        if (chunk_size > rle_worst_case_size(BUFFER_SIZE)) {
            fprintf(stderr, "Invalid chunk size: %zu\n", chunk_size);
            result = -1;
            goto cleanup;
        }
        
        /* Read the compressed chunk */
        if (fread(buffer, 1, chunk_size, in) != chunk_size) {
            perror("Error reading compressed chunk from input file");
            result = -1;
            goto cleanup;
        }
        
        /* Decompress the chunk */
        if (rle_decompress(buffer, chunk_size, output_buffer, BUFFER_SIZE, &output_size) != 0) {
            fprintf(stderr, "RLE decompression failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Write the decompressed chunk to the output file */
        if (fwrite(output_buffer, 1, output_size, out) != output_size) {
            perror("Error writing to output file");
            result = -1;
            goto cleanup;
        }
        
        file_size += output_size;
        printf("\rProcessed %zu bytes (%.1f%%)", file_size, 
               (float)file_size * 100 / original_size);
        fflush(stdout);
    }
    
    printf("\nFile decompressed successfully!\n");
    
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
 * Process a file (encrypt and compress)
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param password    Password for encryption
 * @param iterations  Number of iterations for key derivation
 * @return            0 on success, non-zero on failure
 */
int process_file(const char *input_file, const char *output_file, 
                const char *password, int iterations) {
    char temp_file[MAX_FILENAME];
    int result;
    
    /* Create a temporary filename */
    snprintf(temp_file, MAX_FILENAME, "%s.tmp", output_file);
    
    printf("Processing file '%s' to '%s' (encrypt + compress)\n", input_file, output_file);
    
    /* First encrypt the file */
    result = encrypt_file(input_file, temp_file, password, iterations);
    if (result != 0) {
        fprintf(stderr, "Encryption failed\n");
        remove(temp_file);
        return result;
    }
    
    /* Then compress the encrypted file */
    result = compress_file(temp_file, output_file);
    if (result != 0) {
        fprintf(stderr, "Compression failed\n");
        remove(temp_file);
        return result;
    }
    
    /* Remove the temporary file */
    remove(temp_file);
    
    printf("File processed successfully!\n");
    return 0;
}

/**
 * Extract a file (decompress and decrypt)
 * 
 * @param input_file  Path to the input file
 * @param output_file Path to the output file
 * @param password    Password for decryption
 * @param iterations  Number of iterations for key derivation
 * @return            0 on success, non-zero on failure
 */
int extract_file(const char *input_file, const char *output_file, 
                const char *password, int iterations) {
    char temp_file[MAX_FILENAME];
    int result;
    
    /* Create a temporary filename */
    snprintf(temp_file, MAX_FILENAME, "%s.tmp", output_file);
    
    printf("Extracting file '%s' to '%s' (decompress + decrypt)\n", input_file, output_file);
    
    /* First decompress the file */
    result = decompress_file(input_file, temp_file);
    if (result != 0) {
        fprintf(stderr, "Decompression failed\n");
        remove(temp_file);
        return result;
    }
    
    /* Then decrypt the file */
    result = decrypt_file(temp_file, output_file, password, iterations);
    if (result != 0) {
        fprintf(stderr, "Decryption failed\n");
        remove(temp_file);
        return result;
    }
    
    /* Remove the temporary file */
    remove(temp_file);
    
    printf("File extracted successfully!\n");
    return 0;
}

/**
 * Handle file list operations (list, find)
 * 
 * @param command   Command to execute ("list" or "find")
 * @param filename  Filename to find (only used for "find" command)
 * @return          0 on success, non-zero on failure
 */
int handle_file_list(const char *command, const char *filename) {
    file_list_t file_list;
    file_entry_t *found;
    
    /* Initialize the file list */
    file_list_init(&file_list);
    
    /* Load the file list */
    if (file_list_load(&file_list, DEFAULT_FILE_LIST) != 0) {
        fprintf(stderr, "Failed to load file list or file list doesn't exist\n");
        return -1;
    }
    
    /* Execute the command */
    if (strcmp(command, "list") == 0) {
        /* List all files */
        printf("File list (%zu entries):\n", file_list.count);
        file_list_print(&file_list);
    } else if (strcmp(command, "find") == 0) {
        /* Find a file */
        if (filename == NULL) {
            fprintf(stderr, "No filename specified for find command\n");
            file_list_free(&file_list);
            return -1;
        }
        
        printf("Searching for '%s'...\n", filename);
        found = file_list_find(&file_list, filename);
        
        if (found) {
            printf("Found matching file:\n");
            char time_str[64];
            struct tm *timeinfo = localtime(&found->timestamp);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
            
            printf("  Filename: %s\n", found->filename);
            printf("  Processed on: %s\n", time_str);
            printf("  Original size: %zu bytes\n", found->original_size);
            printf("  Processed size: %zu bytes\n", found->processed_size);
            printf("  Compression ratio: %.2f%%\n",
                  (float)found->processed_size * 100 / found->original_size);
        } else {
            printf("No matching file found\n");
        }
    } else {
        fprintf(stderr, "Unknown file list command: %s\n", command);
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
 * @return            0 on success, non-zero on failure
 */
int batch_process(char *filenames[], int num_files, const char *output_dir, 
                 const char *password, int iterations) {
    char output_file[MAX_FILENAME];
    char *filename_only;
    int result = 0;
    int i;
    
    printf("Batch processing %d files to directory '%s'\n", num_files, output_dir);
    
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
        
        printf("\n[%d/%d] Processing file '%s' to '%s'...\n", 
               i + 1, num_files, filenames[i], output_file);
        
        /* Process the file */
        result = process_file(filenames[i], output_file, password, iterations);
        if (result != 0) {
            fprintf(stderr, "Failed to process file '%s'\n", filenames[i]);
            /* Continue with next file */
        }
    }
    
    printf("\nBatch processing completed!\n");
    return result;
}

/**
 * Run the built-in tests
 * 
 * @return 0 on success, non-zero on failure
 */
int run_tests() {
    /* This is a simplified test function - in a real implementation, 
     * this would run more comprehensive tests */
    printf("Running built-in tests...\n");
    
    /* Test ChaCha20 */
    chacha20_ctx ctx;
    uint8_t key[CHACHA20_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[CHACHA20_NONCE_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    uint8_t plaintext[] = "This is a test message";
    size_t plaintext_len = strlen((char *)plaintext);
    uint8_t ciphertext[64], decrypted[64];
    int success = 1;
    
    /* Initialize ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, 0) != 0) {
        fprintf(stderr, "Failed to initialize ChaCha20 context\n");
        return -1;
    }
    
    /* Encrypt */
    if (chacha20_process(&ctx, plaintext, ciphertext, plaintext_len) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return -1;
    }
    
    /* Reinitialize context */
    chacha20_cleanup(&ctx);
    if (chacha20_init(&ctx, key, nonce, 0) != 0) {
        fprintf(stderr, "Failed to reinitialize ChaCha20 context\n");
        return -1;
    }
    
    /* Decrypt */
    if (chacha20_process(&ctx, ciphertext, decrypted, plaintext_len) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return -1;
    }
    
    /* Check if decryption worked */
    decrypted[plaintext_len] = '\0';
    success = (memcmp(plaintext, decrypted, plaintext_len) == 0);
    printf("ChaCha20 Test: %s\n", success ? "PASSED" : "FAILED");
    
    /* Test RLE compression */
    uint8_t test_data[] = "AAAABBBCCDDDDD";
    size_t test_len = strlen((char *)test_data);
    uint8_t compressed[100], decompressed[100];
    size_t compressed_size, decompressed_size;
    
    /* Compress */
    if (rle_compress(test_data, test_len, compressed, 100, &compressed_size) != 0) {
        fprintf(stderr, "Compression failed\n");
        return -1;
    }
    
    /* Decompress */
    if (rle_decompress(compressed, compressed_size, decompressed, 100, &decompressed_size) != 0) {
        fprintf(stderr, "Decompression failed\n");
        return -1;
    }
    
    /* Check if decompression worked */
    decompressed[decompressed_size] = '\0';
    success = (decompressed_size == test_len && 
              memcmp(test_data, decompressed, test_len) == 0);
    printf("RLE Test: %s\n", success ? "PASSED" : "FAILED");
    printf("Original size: %zu, Compressed size: %zu (%.2f%%)\n",
           test_len, compressed_size, (float)compressed_size * 100 / test_len);
    
    /* Test key derivation */
    uint8_t derived_key[CHACHA20_KEY_SIZE], derived_nonce[CHACHA20_NONCE_SIZE];
    uint8_t salt[DEFAULT_SALT_SIZE];
    
    /* Generate salt */
    if (generate_salt(salt, DEFAULT_SALT_SIZE) != 0) {
        fprintf(stderr, "Failed to generate salt\n");
        return -1;
    }
    
    /* Derive key and nonce */
    if (derive_key_and_nonce("test_password", salt, DEFAULT_SALT_SIZE, 1000,
                           derived_key, CHACHA20_KEY_SIZE, 
                           derived_nonce, CHACHA20_NONCE_SIZE) != 0) {
        fprintf(stderr, "Key derivation failed\n");
        return -1;
    }
    
    printf("Key Derivation Test: PASSED\n");
    
    /* Test file list */
    file_list_t file_list;
    file_list_init(&file_list);
    
    /* Add some test entries */
    file_list_add(&file_list, "test1.txt", 100, 50);
    file_list_add(&file_list, "test2.txt", 200, 150);
    
    /* Find an entry */
    file_entry_t *found = file_list_find(&file_list, "test1");
    success = (found != NULL && strcmp(found->filename, "test1.txt") == 0);
    printf("File List Test: %s\n", success ? "PASSED" : "FAILED");
    
    /* Free the file list */
    file_list_free(&file_list);
    
    printf("All tests completed!\n");
    
    return 0;
}

int main(int argc, char *argv[]) {
    int mode = MODE_DEMO;
    char *input_file = NULL, *output_file = NULL;
    char password[MAX_PASSWORD];
    int iterations = DEFAULT_KEY_ITERATIONS;
    int quiet_mode = 0;
    char *batch_files[MAX_BATCH_FILES];
    int num_batch_files = 0;
    char *output_dir = NULL;
    int result;
    
    /* Check command line arguments */
    if (argc > 1) {
        /* Parse mode */
        if (strcmp(argv[1], "-e") == 0) {
            /* Encrypt mode */
            mode = MODE_ENCRYPT;
            if (argc < 4) {
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2];
            output_file = argv[3];
        } else if (strcmp(argv[1], "-d") == 0) {
            /* Decrypt mode */
            mode = MODE_DECRYPT;
            if (argc < 4) {
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2];
            output_file = argv[3];
        } else if (strcmp(argv[1], "-c") == 0) {
            /* Compress mode */
            mode = MODE_COMPRESS;
            if (argc < 4) {
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2];
            output_file = argv[3];
        } else if (strcmp(argv[1], "-x") == 0) {
            /* Decompress mode */
            mode = MODE_DECOMPRESS;
            if (argc < 4) {
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2];
            output_file = argv[3];
        } else if (strcmp(argv[1], "-p") == 0) {
            /* Process mode (encrypt+compress) */
            mode = MODE_PROCESS;
            if (argc < 4) {
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2];
            output_file = argv[3];
        } else if (strcmp(argv[1], "-u") == 0) {
            /* Extract mode (decompress+decrypt) */
            mode = MODE_EXTRACT;
            if (argc < 4) {
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2];
            output_file = argv[3];
        } else if (strcmp(argv[1], "-t") == 0) {
            /* Test mode */
            mode = MODE_TEST;
        } else if (strcmp(argv[1], "-l") == 0) {
            /* List mode */
            mode = MODE_LIST;
        } else if (strcmp(argv[1], "-f") == 0) {
            /* Find mode */
            mode = MODE_FIND;
            if (argc < 3) {
                print_usage(argv[0]);
                return 1;
            }
            input_file = argv[2]; /* Using input_file to store the filename to find */
        } else if (strcmp(argv[1], "-b") == 0) {
            /* Batch mode */
            mode = MODE_BATCH;
            if (argc < 4) {
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
                        fprintf(stderr, "Unknown option: %s\n", argv[i]);
                        print_usage(argv[0]);
                        return 1;
                    }
                } else {
                    /* Add file to the list */
                    if (num_batch_files < MAX_BATCH_FILES) {
                        batch_files[num_batch_files++] = argv[i];
                    } else {
                        fprintf(stderr, "Too many files specified (maximum: %d)\n", MAX_BATCH_FILES);
                        break;
                    }
                }
            }
            
            if (num_batch_files == 0) {
                fprintf(stderr, "No files specified for batch processing\n");
                print_usage(argv[0]);
                return 1;
            }
        } else {
            /* Unknown mode */
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
                fprintf(stderr, "Unknown option: %s\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
    }
    
    /* Execute the selected mode */
    switch (mode) {
        case MODE_DEMO:
            result = run_demo();
            break;
            
        case MODE_ENCRYPT:
        case MODE_PROCESS:
        case MODE_EXTRACT:
            /* Get password */
            printf("Enter password: ");
            if (fgets(password, MAX_PASSWORD, stdin) == NULL) {
                fprintf(stderr, "Error reading password\n");
                return 1;
            }
            
            /* Remove trailing newline */
            password[strcspn(password, "\n")] = '\0';
            
            /* Check if password is empty */
            if (strlen(password) == 0) {
                fprintf(stderr, "Error: Password cannot be empty\n");
                return 1;
            }
            
            /* Execute the operation */
            if (mode == MODE_ENCRYPT) {
                result = encrypt_file(input_file, output_file, password, iterations);
            } else if (mode == MODE_PROCESS) {
                result = process_file(input_file, output_file, password, iterations);
            } else { /* MODE_EXTRACT */
                result = extract_file(input_file, output_file, password, iterations);
            }
            
            /* Clear the password from memory */
            memset(password, 0, MAX_PASSWORD);
            break;
            
        case MODE_DECRYPT:
            /* Get password */
            printf("Enter password: ");
            if (fgets(password, MAX_PASSWORD, stdin) == NULL) {
                fprintf(stderr, "Error reading password\n");
                return 1;
            }
            
            /* Remove trailing newline */
            password[strcspn(password, "\n")] = '\0';
            
            /* Check if password is empty */
            if (strlen(password) == 0) {
                fprintf(stderr, "Error: Password cannot be empty\n");
                return 1;
            }
            
            /* Decrypt the file */
            result = decrypt_file(input_file, output_file, password, iterations);
            
            /* Clear the password from memory */
            memset(password, 0, MAX_PASSWORD);
            break;
            
        case MODE_COMPRESS:
            result = compress_file(input_file, output_file);
            break;
            
        case MODE_DECOMPRESS:
            result = decompress_file(input_file, output_file);
            break;
            
        case MODE_TEST:
            result = run_tests();
            break;
            
        case MODE_LIST:
            result = handle_file_list("list", NULL);
            break;
            
        case MODE_FIND:
            result = handle_file_list("find", input_file);
            break;
            
        case MODE_BATCH:
            /* Get password */
            printf("Enter password for batch processing: ");
            if (fgets(password, MAX_PASSWORD, stdin) == NULL) {
                fprintf(stderr, "Error reading password\n");
                return 1;
            }
            
            /* Remove trailing newline */
            password[strcspn(password, "\n")] = '\0';
            
            /* Check if password is empty */
            if (strlen(password) == 0) {
                fprintf(stderr, "Error: Password cannot be empty\n");
                return 1;
            }
            
            /* Process the files */
            result = batch_process(batch_files, num_batch_files, output_dir, password, iterations);
            
            /* Clear the password from memory */
            memset(password, 0, MAX_PASSWORD);
            break;
            
        default:
            fprintf(stderr, "Invalid mode\n");
            result = 1;
            break;
    }
    
    return result;
}