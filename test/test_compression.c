/**
 * test_compression.c - Test cases for Huffman compression implementation
 * 
 * This file contains test cases to verify the correctness of the Huffman
 * compression implementation.
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
#include "compression/huffman.h"

/* Enable debug output */
#define TEST_DEBUG

#ifdef TEST_DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define PRINT_HEX(label, data, len) print_hex(label, data, len)
#else
#define DEBUG_PRINT(...)
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
 * Test Huffman compression and decompression with a simple string
 * 
 * @return 0 on success, non-zero on failure
 */
int test_simple_compression(void) {
    const char *test_data = "AAAABBBCCDDDDD";
    size_t test_len = strlen(test_data);
    uint8_t compressed[100], decompressed[100];
    size_t compressed_size, decompressed_size;
    int result = 0;
    
    DEBUG_PRINT("Testing Huffman compression with simple string...\n");
    
    /* Compress the data */
    if (huffman_compress((uint8_t *)test_data, test_len, compressed, 100, &compressed_size) != 0) {
        DEBUG_PRINT("Compression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Original size: %zu, Compressed size: %zu (%.2f%%)\n",
               test_len, compressed_size, (float)compressed_size * 100 / test_len);
    
    /* Decompress the data */
    if (huffman_decompress(compressed, compressed_size, decompressed, 100, &decompressed_size) != 0) {
        DEBUG_PRINT("Decompression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Decompressed size: %zu\n", decompressed_size);
    
    /* Check if decompression was successful */
    if (decompressed_size != test_len) {
        DEBUG_PRINT("Size mismatch: expected %zu, got %zu\n", test_len, decompressed_size);
        result = 1;
    } else if (memcmp(test_data, decompressed, test_len) != 0) {
        DEBUG_PRINT("Content mismatch\n");
        PRINT_HEX("Original", (uint8_t *)test_data, test_len);
        PRINT_HEX("Decompressed", decompressed, decompressed_size);
        result = 1;
    } else {
        DEBUG_PRINT("Test passed!\n");
    }
    
    return result;
}

/**
 * Test Huffman compression and decompression with a repeated pattern
 * 
 * @return 0 on success, non-zero on failure
 */
int test_repeated_pattern(void) {
    uint8_t test_data[1000];
    size_t test_len = sizeof(test_data);
    uint8_t compressed[2000], decompressed[1000];
    size_t compressed_size, decompressed_size;
    size_t i;
    int result = 0;
    
    /* Create a pattern with repeating bytes */
    for (i = 0; i < test_len; i++) {
        test_data[i] = i % 10;
    }
    
    DEBUG_PRINT("Testing Huffman compression with repeated pattern...\n");
    
    /* Compress the data */
    if (huffman_compress(test_data, test_len, compressed, 2000, &compressed_size) != 0) {
        DEBUG_PRINT("Compression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Original size: %zu, Compressed size: %zu (%.2f%%)\n",
               test_len, compressed_size, (float)compressed_size * 100 / test_len);
    
    /* Decompress the data */
    if (huffman_decompress(compressed, compressed_size, decompressed, 1000, &decompressed_size) != 0) {
        DEBUG_PRINT("Decompression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Decompressed size: %zu\n", decompressed_size);
    
    /* Check if decompression was successful */
    if (decompressed_size != test_len) {
        DEBUG_PRINT("Size mismatch: expected %zu, got %zu\n", test_len, decompressed_size);
        result = 1;
    } else if (memcmp(test_data, decompressed, test_len) != 0) {
        DEBUG_PRINT("Content mismatch\n");
        result = 1;
    } else {
        DEBUG_PRINT("Test passed!\n");
    }
    
    return result;
}

/**
 * Test Huffman compression and decompression with random data
 * 
 * @return 0 on success, non-zero on failure
 */
int test_random_data(void) {
    uint8_t test_data[1000];
    size_t test_len = sizeof(test_data);
    uint8_t compressed[2000], decompressed[1000];
    size_t compressed_size, decompressed_size;
    size_t i;
    int result = 0;
    
    /* Create random data */
    srand(42);  /* Use fixed seed for reproducibility */
    for (i = 0; i < test_len; i++) {
        test_data[i] = rand() % 256;
    }
    
    DEBUG_PRINT("Testing Huffman compression with random data...\n");
    
    /* Compress the data */
    if (huffman_compress(test_data, test_len, compressed, 2000, &compressed_size) != 0) {
        DEBUG_PRINT("Compression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Original size: %zu, Compressed size: %zu (%.2f%%)\n",
               test_len, compressed_size, (float)compressed_size * 100 / test_len);
    
    /* Decompress the data */
    if (huffman_decompress(compressed, compressed_size, decompressed, 1000, &decompressed_size) != 0) {
        DEBUG_PRINT("Decompression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Decompressed size: %zu\n", decompressed_size);
    
    /* Check if decompression was successful */
    if (decompressed_size != test_len) {
        DEBUG_PRINT("Size mismatch: expected %zu, got %zu\n", test_len, decompressed_size);
        result = 1;
    } else if (memcmp(test_data, decompressed, test_len) != 0) {
        DEBUG_PRINT("Content mismatch\n");
        result = 1;
    } else {
        DEBUG_PRINT("Test passed!\n");
    }
    
    return result;
}

/**
 * Test Huffman compression and decompression with a single byte
 * 
 * @return 0 on success, non-zero on failure
 */
int test_single_byte(void) {
    uint8_t test_data[1] = {42};
    uint8_t compressed[100], decompressed[1];
    size_t compressed_size, decompressed_size;
    int result = 0;
    
    DEBUG_PRINT("Testing Huffman compression with a single byte...\n");
    
    /* Compress the data */
    if (huffman_compress(test_data, 1, compressed, 100, &compressed_size) != 0) {
        DEBUG_PRINT("Compression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Original size: 1, Compressed size: %zu\n", compressed_size);
    
    /* Decompress the data */
    if (huffman_decompress(compressed, compressed_size, decompressed, 1, &decompressed_size) != 0) {
        DEBUG_PRINT("Decompression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Decompressed size: %zu\n", decompressed_size);
    
    /* Check if decompression was successful */
    if (decompressed_size != 1) {
        DEBUG_PRINT("Size mismatch: expected 1, got %zu\n", decompressed_size);
        result = 1;
    } else if (decompressed[0] != 42) {
        DEBUG_PRINT("Content mismatch: expected 42, got %d\n", decompressed[0]);
        result = 1;
    } else {
        DEBUG_PRINT("Test passed!\n");
    }
    
    return result;
}

/**
 * Test Huffman compression and decompression with empty data
 * 
 * @return 0 on success, non-zero on failure
 */
int test_empty_data(void) {
    uint8_t compressed[100], decompressed[1];
    size_t compressed_size, decompressed_size;
    int result = 0;
    
    DEBUG_PRINT("Testing Huffman compression with empty data...\n");
    
    /* Compress the data */
    if (huffman_compress(NULL, 0, compressed, 100, &compressed_size) != 0) {
        DEBUG_PRINT("Compression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Original size: 0, Compressed size: %zu\n", compressed_size);
    
    /* Check if compression was successful */
    if (compressed_size != 0) {
        DEBUG_PRINT("Size mismatch: expected 0, got %zu\n", compressed_size);
        result = 1;
    } else {
        DEBUG_PRINT("Test passed!\n");
    }
    
    /* Decompress the data */
    if (huffman_decompress(NULL, 0, decompressed, 1, &decompressed_size) != 0) {
        DEBUG_PRINT("Decompression failed\n");
        return 1;
    }
    
    DEBUG_PRINT("Decompressed size: %zu\n", decompressed_size);
    
    /* Check if decompression was successful */
    if (decompressed_size != 0) {
        DEBUG_PRINT("Size mismatch: expected 0, got %zu\n", decompressed_size);
        result = 1;
    } else {
        DEBUG_PRINT("Test passed!\n");
    }
    
    return result;
}

int main(void) {
    int failures = 0;
    
    printf("Running Huffman compression tests...\n\n");
    
    /* Run individual tests */
    failures += test_simple_compression();
    failures += test_repeated_pattern();
    failures += test_random_data();
    failures += test_single_byte();
    failures += test_empty_data();
    
    /* Print final results */
    printf("\nTest summary: %d tests failed\n", failures);
    
    return failures ? 1 : 0;
}
