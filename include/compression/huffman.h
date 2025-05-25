/*
 * huffman.h - Huffman compression implementation
 */

#ifndef HUFFMAN_H
#define HUFFMAN_H

/* Huffman tree node */
typedef struct huffman_node huffman_node;
struct huffman_node
{
    unsigned char symbol;
    unsigned long frequency;
    huffman_node *left;
    huffman_node *right;
};

/* Huffman code entry */
typedef struct
{
    unsigned char symbol;
    unsigned char code[256];
    unsigned int  code_len;
} huffman_code;

/* Streaming compression context */
typedef struct
{
    huffman_code  codes[256];
    huffman_node *tree;
    unsigned long frequencies[256];
    unsigned long input_size;
    int           pass;
} huffman_stream_context;

/* Calculate worst-case compressed size */
unsigned long huffman_worst_case_size(unsigned long input_len);

/* Initialise streaming compression context */
int huffman_stream_init(huffman_stream_context *ctx);

/* First pass: count frequencies from file */
int huffman_stream_count_frequencies(huffman_stream_context *ctx,
                                     const char             *input_file);

/* Prepare for second pass: build tree and generate codes */
int huffman_stream_prepare_encoding(huffman_stream_context *ctx);

/* Second pass: compress file to output */
int huffman_stream_compress_file(huffman_stream_context *ctx,
                                 const char             *input_file,
                                 const char *output_file, int quiet);

/* Decompress streaming file */
int huffman_stream_decompress_file(const char *input_file,
                                   const char *output_file, int quiet);

/* Clean up streaming context */
void huffman_stream_cleanup(huffman_stream_context *ctx);

/* Convenience function for complete file compression */
int huffman_compress_file(const char *input_file, const char *output_file,
                          int quiet);

#endif
