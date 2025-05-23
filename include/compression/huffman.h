#ifndef HUFFMAN_H
#define HUFFMAN_H

// Huffman compression data structures
typedef struct huffman_node huffman_node;
struct huffman_node
{
    unsigned char symbol;
    unsigned long frequency;
    huffman_node *left;
    huffman_node *right;
};

typedef struct
{
    unsigned char symbol;
    unsigned char code[256];
    unsigned int code_len;
} huffman_code;

// Function to calculate worst-case size for compressed data
unsigned long huffman_worst_case_size(unsigned long input_len);

// Compress data using Huffman coding
int huffman_compress(const unsigned char *input, unsigned long input_len,
                     unsigned char *output, unsigned long output_max_len,
                     unsigned long *output_len);

// Decompress data using Huffman coding
int huffman_decompress(const unsigned char *input, unsigned long input_len,
                       unsigned char *output, unsigned long output_max_len,
                       unsigned long *output_len);

#endif
