/**
 * huffman.c - Simplified Huffman compression algorithm
 *
 * Built by: Ethan Hall
 *
 */

#include "compression/huffman.h"
#include "utils/ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SYMBOLS 256
#define MAX_CODE_LEN 256

typedef struct
{
    huffman_node *nodes[MAX_SYMBOLS];
    int count;
} priority_queue;

/* Helper functions */
static huffman_node *build_tree(unsigned long freq[MAX_SYMBOLS]);
static void generate_codes(huffman_node *root, huffman_code codes[MAX_SYMBOLS],
                           unsigned char *code, int len);
static void free_tree(huffman_node *root);
static void pq_insert(priority_queue *pq, huffman_node *node);
static huffman_node *pq_extract_min(priority_queue *pq);
static int write_tree(huffman_node *root, unsigned char *out,
                      unsigned long *pos, int *bit);
static huffman_node *read_tree(const unsigned char *in, unsigned long *pos,
                               int *bit);
static void write_bit(unsigned char *out, unsigned long *pos, int *bit,
                      int val);
static int read_bit(const unsigned char *in, unsigned long *pos, int *bit);

unsigned long huffman_worst_case_size(unsigned long input_len)
{
    return input_len + MAX_SYMBOLS * 10 + sizeof(unsigned long) + 256;
}

static void pq_insert(priority_queue *pq, huffman_node *node)
{
    int i = pq->count;
    pq->nodes[i] = node;

    /* Simple insertion sort to maintain order */
    while (i > 0 && pq->nodes[i]->frequency < pq->nodes[i - 1]->frequency)
        {
            huffman_node *temp = pq->nodes[i];
            pq->nodes[i] = pq->nodes[i - 1];
            pq->nodes[i - 1] = temp;
            i--;
        }
    pq->count++;
}

static huffman_node *pq_extract_min(priority_queue *pq)
{
    if (pq->count == 0)
        return NULL;

    huffman_node *min = pq->nodes[0];
    for (int i = 0; i < pq->count - 1; i++)
        {
            pq->nodes[i] = pq->nodes[i + 1];
        }
    pq->count--;
    return min;
}

static huffman_node *build_tree(unsigned long freq[MAX_SYMBOLS])
{
    priority_queue pq = { 0 };

    /* Create leaf nodes for non-zero frequencies */
    for (int i = 0; i < MAX_SYMBOLS; i++)
        {
            if (freq[i] > 0)
                {
                    huffman_node *node = malloc(sizeof(huffman_node));
                    if (!node)
                        return NULL;

                    node->symbol = i;
                    node->frequency = freq[i];
                    node->left = node->right = NULL;
                    pq_insert(&pq, node);
                }
        }

    if (pq.count == 0)
        return NULL;

    if (pq.count == 1)
        {
            /* Single symbol case: create proper tree structure */
            huffman_node *original_leaf = pq_extract_min(&pq);

            /* Create root node */
            huffman_node *root = malloc(sizeof(huffman_node));
            if (!root)
                {
                    free(original_leaf);
                    return NULL;
                }

            /* Create duplicate leaf node */
            huffman_node *duplicate_leaf = malloc(sizeof(huffman_node));
            if (!duplicate_leaf)
                {
                    free(root);
                    free(original_leaf);
                    return NULL;
                }

            /* Configure duplicate leaf */
            duplicate_leaf->symbol = original_leaf->symbol;
            duplicate_leaf->frequency = original_leaf->frequency;
            duplicate_leaf->left = duplicate_leaf->right = NULL;

            /* Configure root as internal node */
            root->left = original_leaf;
            root->right = duplicate_leaf;
            root->frequency = original_leaf->frequency;
            root->symbol = 0;

            return root;
        }

    /* Build tree by combining nodes */
    while (pq.count > 1)
        {
            huffman_node *left = pq_extract_min(&pq);
            huffman_node *right = pq_extract_min(&pq);

            huffman_node *parent = malloc(sizeof(huffman_node));
            if (!parent)
                return NULL;

            parent->left = left;
            parent->right = right;
            parent->frequency = left->frequency + right->frequency;
            parent->symbol = 0;

            pq_insert(&pq, parent);
        }

    return pq_extract_min(&pq);
}

static void generate_codes(huffman_node *root, huffman_code codes[MAX_SYMBOLS],
                           unsigned char *code, int len)
{
    if (!root)
        return;

    if (!root->left && !root->right)
        {
            /* Leaf node */
            codes[root->symbol].symbol = root->symbol;
            codes[root->symbol].code_len
                = len ? len : 1; /* Handle single symbol case */
            memcpy(codes[root->symbol].code, code, len);
            if (len == 0)
                codes[root->symbol].code[0]
                    = 0; /* Single symbol gets code '0' */
            return;
        }

    if (root->left)
        {
            code[len] = 0;
            generate_codes(root->left, codes, code, len + 1);
        }
    if (root->right)
        {
            code[len] = 1;
            generate_codes(root->right, codes, code, len + 1);
        }
}

static void free_tree(huffman_node *root)
{
    if (!root)
        return;
    free_tree(root->left);
    free_tree(root->right);
    free(root);
}

static void write_bit(unsigned char *out, unsigned long *pos, int *bit, int val)
{
    if (*bit == 0)
        out[*pos] = 0; /* Clear byte on first bit */

    if (val)
        out[*pos] |= (1 << (7 - *bit));

    (*bit)++;
    if (*bit == 8)
        {
            *bit = 0;
            (*pos)++;
        }
}

static int read_bit(const unsigned char *in, unsigned long *pos, int *bit)
{
    int val = (in[*pos] >> (7 - *bit)) & 1;
    (*bit)++;
    if (*bit == 8)
        {
            *bit = 0;
            (*pos)++;
        }
    return val;
}

static int write_tree(huffman_node *root, unsigned char *out,
                      unsigned long *pos, int *bit)
{
    if (!root)
        return 0;

    if (!root->left && !root->right)
        {
            /* Leaf: write 1 + symbol */
            write_bit(out, pos, bit, 1);
            for (int i = 7; i >= 0; i--)
                {
                    write_bit(out, pos, bit, (root->symbol >> i) & 1);
                }
        }
    else
        {
            /* Internal: write 0 + children */
            write_bit(out, pos, bit, 0);
            write_tree(root->left, out, pos, bit);
            write_tree(root->right, out, pos, bit);
        }
    return 0;
}

static huffman_node *read_tree(const unsigned char *in, unsigned long *pos,
                               int *bit)
{
    huffman_node *node = malloc(sizeof(huffman_node));
    if (!node)
        return NULL;

    if (read_bit(in, pos, bit))
        {
            /* Leaf node */
            node->symbol = 0;
            for (int i = 7; i >= 0; i--)
                {
                    node->symbol |= (read_bit(in, pos, bit) << i);
                }
            node->left = node->right = NULL;
        }
    else
        {
            /* Internal node */
            node->left = read_tree(in, pos, bit);
            node->right = read_tree(in, pos, bit);
            if (!node->left || !node->right)
                {
                    free_tree(node);
                    return NULL;
                }
        }
    return node;
}

int huffman_stream_init(huffman_stream_context *ctx)
{
    if (!ctx)
        return -1;

    memset(ctx->frequencies, 0, sizeof(ctx->frequencies));
    memset(ctx->codes, 0, sizeof(ctx->codes));
    ctx->tree = NULL;
    ctx->input_size = 0;
    ctx->pass = 0;

    return 0;
}

int huffman_stream_count_frequencies(huffman_stream_context *ctx,
                                     const char *input_file)
{
    if (!ctx || !input_file)
        return -1;

    FILE *file = fopen(input_file, "rb");
    if (!file)
        return -1;

    unsigned char buffer[8192]; /* 8KB buffer for streaming */
    size_t bytes_read;

    ctx->input_size = 0;

    /* First pass: count frequencies */
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
        {
            for (size_t i = 0; i < bytes_read; i++)
                {
                    ctx->frequencies[buffer[i]]++;
                }
            ctx->input_size += bytes_read;
        }

    fclose(file);
    ctx->pass = 1;

    return 0;
}

int huffman_stream_prepare_encoding(huffman_stream_context *ctx)
{
    if (!ctx || ctx->pass != 1)
        return -1;

    /* Handle empty file case */
    if (ctx->input_size == 0)
        {
            ctx->tree = NULL;
            ctx->pass = 2;
            return 0;
        }

    /* Build tree from frequencies */
    ctx->tree = build_tree(ctx->frequencies);
    if (!ctx->tree)
        return -1;

    /* Generate codes */
    unsigned char code_buffer[MAX_CODE_LEN];
    generate_codes(ctx->tree, ctx->codes, code_buffer, 0);

    ctx->pass = 2;

    return 0;
}

int huffman_stream_compress_file(huffman_stream_context *ctx,
                                 const char *input_file,
                                 const char *output_file, int quiet)
{
    if (!ctx || !input_file || !output_file || ctx->pass != 2)
        return -1;

    FILE *input = fopen(input_file, "rb");
    if (!input)
        return -1;

    FILE *output = fopen(output_file, "wb");
    if (!output)
        {
            fclose(input);
            return -1;
        }

    /* Write header: original file size */
    if (fwrite(&ctx->input_size, sizeof(unsigned long), 1, output) != 1)
        {
            fclose(input);
            fclose(output);
            return -1;
        }

    /* Handle empty file case */
    if (ctx->input_size == 0)
        {
            fclose(input);
            fclose(output);
            return 0;
        }

    /* Write tree to output in a temporary buffer */
    unsigned char tree_buffer[MAX_SYMBOLS * 10]; /* Generous buffer for tree */
    unsigned long tree_pos = 0;
    int tree_bit = 0;

    write_tree(ctx->tree, tree_buffer, &tree_pos, &tree_bit);

    /* Align tree to byte boundary */
    if (tree_bit != 0)
        {
            tree_bit = 0;
            tree_pos++;
        }

    /* Write tree size and tree data */
    if (fwrite(&tree_pos, sizeof(unsigned long), 1, output) != 1
        || fwrite(tree_buffer, 1, tree_pos, output) != tree_pos)
        {
            fclose(input);
            fclose(output);
            return -1;
        }

    /* Second pass: encode data with progress tracking */
    unsigned char input_buffer[4096];
    unsigned char output_buffer[8192];
    unsigned long output_pos = 0;
    int output_bit = 0;
    size_t bytes_read;
    unsigned long processed_bytes = 0;

    /* Initialise progress bar */
    if (!quiet)
        {
            print_progress_bar(0, ctx->input_size, PROGRESS_WIDTH);
        }

    while ((bytes_read = fread(input_buffer, 1, sizeof(input_buffer), input))
           > 0)
        {
            for (size_t i = 0; i < bytes_read; i++)
                {
                    unsigned char symbol = input_buffer[i];

                    /* Write the code for this symbol */
                    for (int j = 0; j < ctx->codes[symbol].code_len; j++)
                        {
                            /* Flush output buffer if needed */
                            if (output_pos >= sizeof(output_buffer) - 1)
                                {
                                    if (fwrite(output_buffer, 1, output_pos,
                                               output)
                                        != output_pos)
                                        {
                                            fclose(input);
                                            fclose(output);
                                            return -1;
                                        }
                                    output_pos = 0;
                                }

                            write_bit(output_buffer, &output_pos, &output_bit,
                                      ctx->codes[symbol].code[j]);
                        }
                }

            /* Update progress */
            processed_bytes += bytes_read;
            if (!quiet)
                {
                    print_progress_bar(processed_bytes, ctx->input_size,
                                       PROGRESS_WIDTH);
                }
        }

    /* Flush remaining bits */
    if (output_bit != 0)
        output_pos++;

    /* Write remaining output buffer */
    if (output_pos > 0)
        {
            if (fwrite(output_buffer, 1, output_pos, output) != output_pos)
                {
                    fclose(input);
                    fclose(output);
                    return -1;
                }
        }

    fclose(input);
    fclose(output);

    return 0;
}

int huffman_stream_decompress_file(const char *input_file,
                                   const char *output_file, int quiet)
{
    if (!input_file || !output_file)
        return -1;

    FILE *input = fopen(input_file, "rb");
    if (!input)
        return -1;

    FILE *output = fopen(output_file, "wb");
    if (!output)
        {
            fclose(input);
            return -1;
        }

    /* Read original file size */
    unsigned long original_size;
    if (fread(&original_size, sizeof(unsigned long), 1, input) != 1)
        {
            fclose(input);
            fclose(output);
            return -1;
        }

    if (original_size == 0)
        {
            fclose(input);
            fclose(output);
            return 0;
        }

    /* Read tree size */
    unsigned long tree_size;
    if (fread(&tree_size, sizeof(unsigned long), 1, input) != 1)
        {
            fclose(input);
            fclose(output);
            return -1;
        }

    /* Read tree data */
    unsigned char *tree_buffer = malloc(tree_size);
    if (!tree_buffer)
        {
            fclose(input);
            fclose(output);
            return -1;
        }

    if (fread(tree_buffer, 1, tree_size, input) != tree_size)
        {
            free(tree_buffer);
            fclose(input);
            fclose(output);
            return -1;
        }

    /* Reconstruct tree */
    unsigned long tree_pos = 0;
    int tree_bit = 0;
    huffman_node *root = read_tree(tree_buffer, &tree_pos, &tree_bit);
    free(tree_buffer);

    if (!root)
        {
            fclose(input);
            fclose(output);
            return -1;
        }

    /* Decompress data in chunks with progress tracking */
    unsigned char input_buffer[8192];
    unsigned char output_buffer[4096];
    unsigned long decoded = 0;
    unsigned long output_count = 0;
    huffman_node *current = root;

    size_t bytes_read;
    unsigned long input_pos = 0;
    int input_bit = 0;

    /* Initialise progress bar */
    if (!quiet)
        {
            print_progress_bar(0, original_size, PROGRESS_WIDTH);
        }

    while (decoded < original_size
           && (bytes_read = fread(input_buffer, 1, sizeof(input_buffer), input))
                  > 0)
        {
            input_pos = 0;
            input_bit = 0;

            while (decoded < original_size && input_pos < bytes_read)
                {
                    /* Read bit from input */
                    if (input_pos < bytes_read)
                        {
                            int b = read_bit(input_buffer, &input_pos,
                                             &input_bit);
                            current = b ? current->right : current->left;

                            if (!current)
                                {
                                    free_tree(root);
                                    fclose(input);
                                    fclose(output);
                                    return -1;
                                }

                            if (!current->left && !current->right)
                                {
                                    /* Leaf node - write to output buffer */
                                    output_buffer[output_count++]
                                        = current->symbol;
                                    decoded++;
                                    current = root;

                                    /* Update progress periodically (every 1024
                                     * bytes decoded) */
                                    if (!quiet
                                        && (decoded % 1024 == 0
                                            || decoded == original_size))
                                        {
                                            print_progress_bar(decoded,
                                                               original_size,
                                                               PROGRESS_WIDTH);
                                        }

                                    /* Flush output buffer if full */
                                    if (output_count >= sizeof(output_buffer))
                                        {
                                            if (fwrite(output_buffer, 1,
                                                       output_count, output)
                                                != output_count)
                                                {
                                                    free_tree(root);
                                                    fclose(input);
                                                    fclose(output);
                                                    return -1;
                                                }
                                            output_count = 0;
                                        }
                                }
                        }
                }
        }

    /* Write remaining output buffer */
    if (output_count > 0)
        {
            if (fwrite(output_buffer, 1, output_count, output) != output_count)
                {
                    free_tree(root);
                    fclose(input);
                    fclose(output);
                    return -1;
                }
        }

    free_tree(root);
    fclose(input);
    fclose(output);

    return (decoded == original_size) ? 0 : -1;
}

void huffman_stream_cleanup(huffman_stream_context *ctx)
{
    if (!ctx)
        return;

    if (ctx->tree)
        {
            free_tree(ctx->tree);
            ctx->tree = NULL;
        }

    memset(ctx, 0, sizeof(huffman_stream_context));
}

/* Convenience function for complete streaming compression */
int huffman_compress_file(const char *input_file, const char *output_file,
                          int quiet)
{
    huffman_stream_context ctx;

    /* Initialise context */
    if (huffman_stream_init(&ctx) != 0)
        return -1;

    /* First pass: count frequencies */
    if (huffman_stream_count_frequencies(&ctx, input_file) != 0)
        {
            huffman_stream_cleanup(&ctx);
            return -1;
        }

    /* Prepare encoding (build tree and codes) */
    if (huffman_stream_prepare_encoding(&ctx) != 0)
        {
            huffman_stream_cleanup(&ctx);
            return -1;
        }

    /* Second pass: compress file */
    int result
        = huffman_stream_compress_file(&ctx, input_file, output_file, quiet);

    /* Clean up */
    huffman_stream_cleanup(&ctx);

    return result;
}