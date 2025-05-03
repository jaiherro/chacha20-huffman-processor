/**
 * main.c - ChaCha20 encryption/decryption demonstration program
 * 
 * Group: [Your Group Number]
 * Lab: [Your Lab Number]
 * 
 * Compiling instructions:
 * To compile this program, use the provided makefile with the command:
 *   make
 * 
 * This will produce an executable named 'chacha20_demo'.
 * 
 * For a debug build with verbose output:
 *   make DEBUG=1
 * 
 * Alternatively, compile manually with:
 *   gcc -Wall -o chacha20_demo main.c chacha20.c
 *   
 * For debug build:
 *   gcc -Wall -DCHACHA20_DEBUG -o chacha20_demo main.c chacha20.c
 * 
 * This program demonstrates the ChaCha20 stream cipher implementation
 * according to RFC 8439 (https://datatracker.ietf.org/doc/html/rfc8439)
 * by:
 * 1. Encrypting a text message
 * 2. Decrypting it back to plaintext
 * 3. Optionally performing a file encryption/decryption based on command-line arguments
 * 
 * Only uses the following standard C libraries as required:
 * - stdio.h
 * - stdlib.h
 * - string.h
 * - math.h (not used in this file)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encryption/chacha20.h"

/* Debug mode can be enabled via makefile (make DEBUG=1) */
#ifdef CHACHA20_DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[Main] " fmt, ##__VA_ARGS__)
#define PRINT_HEX(label, data, len) print_hex(label, data, len)
#else
#define DEBUG_PRINT(fmt, ...)
#define PRINT_HEX(label, data, len)
#endif

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
 * Derive a key and nonce from a password
 * Note: This is a simplified implementation for demonstration purposes.
 * In a real application, use a proper key derivation function like PBKDF2.
 * 
 * @param password The password to derive key and nonce from
 * @param key      Output buffer for the key (32 bytes)
 * @param nonce    Output buffer for the nonce (12 bytes)
 * @return         0 on success, -1 on failure
 */
int derive_key_and_nonce(const char *password, uint8_t *key, uint8_t *nonce) {
    size_t password_len;
    size_t i;
    
    if (password == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    
    password_len = strlen(password);
    if (password_len == 0) {
        return -1;
    }
    
    DEBUG_PRINT("Deriving key and nonce from password (%zu chars)\n", password_len);
    
    /* Initialize key and nonce with zeros */
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    
    /* Simple password stretching (not secure, for demonstration only) */
    for (i = 0; i < password_len; i++) {
        key[i % CHACHA20_KEY_SIZE] ^= password[i];
        key[(i + 1) % CHACHA20_KEY_SIZE] ^= (password[i] << 1);
        nonce[i % CHACHA20_NONCE_SIZE] ^= (password[password_len - 1 - i]);
    }
    
    /* Additional mixing */
    for (i = 0; i < 1000; i++) {
        key[i % CHACHA20_KEY_SIZE] ^= key[(i + 7) % CHACHA20_KEY_SIZE];
        nonce[i % CHACHA20_NONCE_SIZE] ^= nonce[(i + 5) % CHACHA20_NONCE_SIZE];
    }
    
    PRINT_HEX("Derived key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Derived nonce", nonce, CHACHA20_NONCE_SIZE);
    
    return 0;
}

/**
 * Convert a hexadecimal string to a byte array
 * 
 * @param hex_str   The hexadecimal string
 * @param byte_array The output byte array
 * @param byte_len   The expected length of the byte array
 * @return          0 on success, -1 on failure
 */
int hex_to_bytes(const char *hex_str, uint8_t *byte_array, size_t byte_len) {
    size_t i;
    size_t hex_len;
    
    if (hex_str == NULL || byte_array == NULL) {
        return -1;
    }
    
    hex_len = strlen(hex_str);
    if (hex_len != byte_len * 2) {
        fprintf(stderr, "Error: Hex string length (%zu) doesn't match expected byte length (%zu)\n", 
                hex_len, byte_len);
        return -1;
    }
    
    for (i = 0; i < byte_len; i++) {
        char high_nibble = hex_str[i * 2];
        char low_nibble = hex_str[i * 2 + 1];
        
        /* Convert high nibble */
        if (high_nibble >= '0' && high_nibble <= '9') {
            byte_array[i] = (high_nibble - '0') << 4;
        } else if (high_nibble >= 'A' && high_nibble <= 'F') {
            byte_array[i] = (high_nibble - 'A' + 10) << 4;
        } else if (high_nibble >= 'a' && high_nibble <= 'f') {
            byte_array[i] = (high_nibble - 'a' + 10) << 4;
        } else {
            fprintf(stderr, "Error: Invalid hex character '%c'\n", high_nibble);
            return -1;
        }
        
        /* Convert low nibble */
        if (low_nibble >= '0' && low_nibble <= '9') {
            byte_array[i] |= (low_nibble - '0');
        } else if (low_nibble >= 'A' && low_nibble <= 'F') {
            byte_array[i] |= (low_nibble - 'A' + 10);
        } else if (low_nibble >= 'a' && low_nibble <= 'f') {
            byte_array[i] |= (low_nibble - 'a' + 10);
        } else {
            fprintf(stderr, "Error: Invalid hex character '%c'\n", low_nibble);
            return -1;
        }
    }
    
    return 0;
}

/**
 * Encrypt or decrypt a file using ChaCha20
 * 
 * @param input_file   Path to the input file
 * @param output_file  Path to the output file
 * @param key          256-bit encryption key (32 bytes)
 * @param nonce        96-bit nonce (12 bytes)
 * @param counter      Initial counter value
 * @return             0 on success, non-zero on failure
 */
int process_file(const char *input_file, const char *output_file, 
                const uint8_t *key, const uint8_t *nonce, uint32_t counter) {
    FILE *in = NULL, *out = NULL;
    chacha20_ctx ctx;
    uint8_t buffer[4096], output_buffer[4096];
    size_t read_size;
    int result = 0;
    
    DEBUG_PRINT("Processing file '%s' -> '%s'\n", input_file, output_file);
    PRINT_HEX("Key", key, CHACHA20_KEY_SIZE);
    PRINT_HEX("Nonce", nonce, CHACHA20_NONCE_SIZE);
    DEBUG_PRINT("Counter: %u\n", counter);
    
    /* Open input file */
    in = fopen(input_file, "rb");
    if (in == NULL) {
        perror("Error opening input file");
        return -1;
    }
    
    /* Open output file */
    out = fopen(output_file, "wb");
    if (out == NULL) {
        perror("Error opening output file");
        fclose(in);
        return -1;
    }
    
    /* Initialize ChaCha20 context */
    if (chacha20_init(&ctx, key, nonce, counter) != 0) {
        fprintf(stderr, "Failed to initialize ChaCha20 context\n");
        result = -1;
        goto cleanup;
    }
    
    /* Process the file in chunks */
    while ((read_size = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (chacha20_process(&ctx, buffer, output_buffer, read_size) != 0) {
            fprintf(stderr, "ChaCha20 processing failed\n");
            result = -1;
            goto cleanup;
        }
        
        if (fwrite(output_buffer, 1, read_size, out) != read_size) {
            perror("Error writing to output file");
            result = -1;
            goto cleanup;
        }
        
        DEBUG_PRINT("Processed %zu bytes\n", read_size);
    }
    
    if (ferror(in)) {
        perror("Error reading from input file");
        result = -1;
    }
    
cleanup:
    /* Close files */
    if (in != NULL) fclose(in);
    if (out != NULL) fclose(out);
    
    /* Clear sensitive data */
    chacha20_cleanup(&ctx);
    memset(buffer, 0, sizeof(buffer));
    memset(output_buffer, 0, sizeof(output_buffer));
    
    return result;
}

/**
 * Print the usage information for the program
 * 
 * @param program_name The name of the program executable
 */
void print_usage(const char *program_name) {
    printf("ChaCha20 Stream Cipher - RFC 8439 Implementation\n");
    printf("==================================================\n\n");
    printf("Usage:\n");
    printf("  %s                       Run a simple demonstration\n", program_name);
    printf("  %s -e infile outfile     Encrypt a file (password prompt)\n", program_name);
    printf("  %s -d infile outfile     Decrypt a file (password prompt)\n", program_name);
    printf("  %s -x key nonce infile outfile\n", program_name);
    printf("                           Process with explicit key/nonce in hex\n");
    printf("\nWhen using -e/-d options, you will be prompted for a password.\n");
    printf("For -x option:\n");
    printf("  key   = 64-character hex string (32 bytes)\n");
    printf("  nonce = 24-character hex string (12 bytes)\n");
}

int main(int argc, char *argv[]) {
    /* Demo text to encrypt/decrypt */
    const char *demo_text = "ChaCha20 is a stream cipher designed by Daniel J. Bernstein.";
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
    
    /* ChaCha20 context */
    chacha20_ctx ctx;
    
    /* For file operations */
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    char password[128];
    
    int result = 0;
    
    /* Check command line arguments */
    if (argc == 1) {
        /* Run the simple demonstration */
        int i, success = 1;
        
        printf("ChaCha20 Stream Cipher Demonstration\n");
        printf("====================================\n\n");
        
        /* Allocate memory for the demonstration */
        plaintext = (uint8_t *)malloc(demo_len);
        ciphertext = (uint8_t *)malloc(demo_len);
        decrypted = (uint8_t *)malloc(demo_len);
        
        if (!plaintext || !ciphertext || !decrypted) {
            fprintf(stderr, "Memory allocation failed\n");
            result = -1;
            goto cleanup;
        }
        
        /* Copy the demo text to plaintext buffer */
        memcpy(plaintext, demo_text, demo_len);
        
        printf("Original plaintext: %s\n", plaintext);
        PRINT_HEX("Original plaintext (hex)", plaintext, demo_len);
        
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
        
        printf("\nEncrypted ciphertext (hex): ");
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
        
        printf("\nDecrypted plaintext: %s\n", decrypted);
        PRINT_HEX("Decrypted plaintext (hex)", decrypted, demo_len);
        
        /* Verify decryption */
        for (i = 0; i < demo_len; i++) {
            if (plaintext[i] != decrypted[i]) {
                success = 0;
                break;
            }
        }
        
        printf("\nVerification: %s\n", success ? "PASSED" : "FAILED");
        
    } else if (argc == 4) {
        /* File encryption/decryption mode with password */
        int encrypt_mode = 0;
        
        if (strcmp(argv[1], "-e") == 0) {
            encrypt_mode = 1;
        } else if (strcmp(argv[1], "-d") == 0) {
            encrypt_mode = 0;
        } else {
            print_usage(argv[0]);
            result = 1;
            goto cleanup;
        }
        
        /* Get password from user */
        printf("Enter password: ");
        if (fgets(password, sizeof(password), stdin) == NULL) {
            fprintf(stderr, "Error reading password\n");
            result = 1;
            goto cleanup;
        }
        
        /* Remove newline character */
        password[strcspn(password, "\n")] = 0;
        
        /* Check if password is empty */
        if (strlen(password) == 0) {
            fprintf(stderr, "Error: Password cannot be empty\n");
            result = 1;
            goto cleanup;
        }
        
        /* Derive key and nonce from password */
        if (derive_key_and_nonce(password, key, nonce) != 0) {
            fprintf(stderr, "Error deriving key and nonce from password\n");
            result = 1;
            goto cleanup;
        }
        
        printf("%s file %s to %s...\n", 
               encrypt_mode ? "Encrypting" : "Decrypting", 
               argv[2], argv[3]);
        
        if (process_file(argv[2], argv[3], key, nonce, 1) == 0) {
            printf("File %s successfully!\n", 
                   encrypt_mode ? "encrypted" : "decrypted");
        } else {
            fprintf(stderr, "File processing failed\n");
            result = 1;
            goto cleanup;
        }
    } else if (argc == 6 && strcmp(argv[1], "-x") == 0) {
        /* File processing with explicit key and nonce */
        const char *key_hex = argv[2];
        const char *nonce_hex = argv[3];
        const char *input_file = argv[4];
        const char *output_file = argv[5];
        
        /* Convert hex strings to bytes */
        if (hex_to_bytes(key_hex, key, CHACHA20_KEY_SIZE) != 0) {
            fprintf(stderr, "Error: Invalid key format\n");
            result = 1;
            goto cleanup;
        }
        
        if (hex_to_bytes(nonce_hex, nonce, CHACHA20_NONCE_SIZE) != 0) {
            fprintf(stderr, "Error: Invalid nonce format\n");
            result = 1;
            goto cleanup;
        }
        
        printf("Processing file %s to %s with explicit key/nonce...\n", 
               input_file, output_file);
        
        if (process_file(input_file, output_file, key, nonce, 1) == 0) {
            printf("File processed successfully!\n");
        } else {
            fprintf(stderr, "File processing failed\n");
            result = 1;
            goto cleanup;
        }
    } else {
        print_usage(argv[0]);
        result = 1;
        goto cleanup;
    }
    
cleanup:
    /* Free allocated memory */
    if (plaintext) {
        memset(plaintext, 0, demo_len);
        free(plaintext);
    }
    if (ciphertext) {
        memset(ciphertext, 0, demo_len);
        free(ciphertext);
    }
    if (decrypted) {
        memset(decrypted, 0, demo_len);
        free(decrypted);
    }
    
    /* Clear sensitive data */
    chacha20_cleanup(&ctx);
    memset(key, 0, CHACHA20_KEY_SIZE);
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    memset(password, 0, sizeof(password));
    
    return result;
}