#ifndef HUFFMAN_H
#define HUFFMAN_H

// Huffman compression data structures
typedef struct huffman_node huffman_node;
struct huffman_node
{
    unsigned char symbol;
    unsigned long frequency; // Replaced size_t with unsigned long for frequency, assuming it represents a count/size
    huffman_node *left;
    huffman_node *right;
};

typedef struct
{
    unsigned char symbol;    // uint8_t equivalent
    unsigned char code[256]; // Assuming codes are represented by bytes
    unsigned int code_len;   // Length of the code
} huffman_code;

// Function to calculate worst-case size for compressed data
// Replaced size_t with unsigned long for lengths/sizes
unsigned long huffman_worst_case_size(unsigned long input_len);

// Compress data using Huffman coding
// Replaced uint8_t with unsigned char for byte data
// Replaced size_t with unsigned long for lengths/sizes
int huffman_compress(const unsigned char *input, unsigned long input_len,
                     unsigned char *output, unsigned long output_max_len,
                     unsigned long *output_len);

// Decompress data using Huffman coding
// Replaced uint8_t with unsigned char for byte data
// Replaced size_t with unsigned long for lengths/sizes
int huffman_decompress(const unsigned char *input, unsigned long input_len,
                       unsigned char *output, unsigned long output_max_len,
                       unsigned long *output_len);

#endif
