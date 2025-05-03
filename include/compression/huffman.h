#ifndef HUFFMAN_H 
#define HUFFMAN_H 

#include <stddef.h>
#include <stdint.h>

// Huffman compression data structures
typedef struct huffman_node huffman_node;
struct huffman_node {
    unsigned char symbol;
    unsigned long frequency;
    huffman_node *left;
    huffman_node *right;
};

typedef struct {
    unsigned char symbol;
    unsigned char code[256];
    unsigned int code_len;
} huffman_code;

// Function to calculate worst-case size for compressed data
size_t huffman_worst_case_size(size_t input_len);

// Compress data using Huffman coding
int huffman_compress(const uint8_t *input, size_t input_len, 
                    uint8_t *output, size_t output_max_len,
                    size_t *output_len);

// Decompress data using Huffman coding
int huffman_decompress(const uint8_t *input, size_t input_len,
                      uint8_t *output, size_t output_max_len,
                      size_t *output_len);

#endif
