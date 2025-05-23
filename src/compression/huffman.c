/**
 * huffman.c - Simplified Huffman compression algorithm
 * Maintains full functionality with cleaner, more readable code
 */

#include "compression/huffman.h"
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
static void count_frequencies(const unsigned char *input, unsigned long len, unsigned long freq[MAX_SYMBOLS]);
static huffman_node *build_tree(unsigned long freq[MAX_SYMBOLS]);
static void generate_codes(huffman_node *root, huffman_code codes[MAX_SYMBOLS], unsigned char *code, int len);
static void free_tree(huffman_node *root);
static void pq_insert(priority_queue *pq, huffman_node *node);
static huffman_node *pq_extract_min(priority_queue *pq);
static int write_tree(huffman_node *root, unsigned char *out, unsigned long *pos, int *bit);
static huffman_node *read_tree(const unsigned char *in, unsigned long *pos, int *bit);
static void write_bit(unsigned char *out, unsigned long *pos, int *bit, int val);
static int read_bit(const unsigned char *in, unsigned long *pos, int *bit);

unsigned long huffman_worst_case_size(unsigned long input_len)
{
    return input_len + MAX_SYMBOLS * 10 + sizeof(unsigned long) + 256;
}

static void count_frequencies(const unsigned char *input, unsigned long len, unsigned long freq[MAX_SYMBOLS])
{
    memset(freq, 0, MAX_SYMBOLS * sizeof(unsigned long));
    for (unsigned long i = 0; i < len; i++)
    {
        freq[input[i]]++;
    }
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
    priority_queue pq = {0};

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

static void generate_codes(huffman_node *root, huffman_code codes[MAX_SYMBOLS], unsigned char *code, int len)
{
    if (!root)
        return;

    if (!root->left && !root->right)
    {
        /* Leaf node */
        codes[root->symbol].symbol = root->symbol;
        codes[root->symbol].code_len = len ? len : 1; /* Handle single symbol case */
        memcpy(codes[root->symbol].code, code, len);
        if (len == 0)
            codes[root->symbol].code[0] = 0; /* Single symbol gets code '0' */
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

static int write_tree(huffman_node *root, unsigned char *out, unsigned long *pos, int *bit)
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

static huffman_node *read_tree(const unsigned char *in, unsigned long *pos, int *bit)
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

int huffman_compress(const unsigned char *input, unsigned long input_len,
                     unsigned char *output, unsigned long output_max_len,
                     unsigned long *output_len)
{
    if (!input || !output || !output_len)
        return -1;
    if (input_len == 0)
    {
        *output_len = 0;
        return 0;
    }

    unsigned long freq[MAX_SYMBOLS];
    count_frequencies(input, input_len, freq);

    huffman_node *root = build_tree(freq);
    if (!root)
        return -1;

    huffman_code codes[MAX_SYMBOLS] = {0};
    unsigned char code_buffer[MAX_CODE_LEN];
    generate_codes(root, codes, code_buffer, 0);

    /* Write header: original size */
    unsigned long pos = 0;
    int bit = 0;

    if (pos + sizeof(unsigned long) > output_max_len)
    {
        free_tree(root);
        return -1;
    }

    memcpy(output + pos, &input_len, sizeof(unsigned long));
    pos += sizeof(unsigned long);

    /* Write tree */
    write_tree(root, output, &pos, &bit);

    /* Align to byte boundary */
    if (bit != 0)
    {
        bit = 0;
        pos++;
    }

    /* Write compressed data */
    for (unsigned long i = 0; i < input_len; i++)
    {
        unsigned char symbol = input[i];
        for (int j = 0; j < codes[symbol].code_len; j++)
        {
            if (pos >= output_max_len)
            {
                free_tree(root);
                return -1;
            }
            write_bit(output, &pos, &bit, codes[symbol].code[j]);
        }
    }

    if (bit != 0)
        pos++;
    *output_len = pos;

    free_tree(root);
    return 0;
}

int huffman_decompress(const unsigned char *input, unsigned long input_len,
                       unsigned char *output, unsigned long output_max_len,
                       unsigned long *output_len)
{
    if (!input || !output || !output_len)
        return -1;
    if (input_len == 0)
    {
        *output_len = 0;
        return 0;
    }

    unsigned long pos = 0;
    int bit = 0;

    /* Read original size */
    if (pos + sizeof(unsigned long) > input_len)
        return -1;

    unsigned long original_size;
    memcpy(&original_size, input + pos, sizeof(unsigned long));
    pos += sizeof(unsigned long);

    if (original_size == 0)
    {
        *output_len = 0;
        return 0;
    }

    if (output_max_len < original_size)
        return -1;

    /* Read tree */
    huffman_node *root = read_tree(input, &pos, &bit);
    if (!root)
        return -1;

    /* Align to byte boundary */
    if (bit != 0)
    {
        bit = 0;
        pos++;
    }

    /* Decompress data */
    unsigned long decoded = 0;
    huffman_node *current = root;

    while (decoded < original_size && pos < input_len)
    {
        int b = read_bit(input, &pos, &bit);
        current = b ? current->right : current->left;

        if (!current)
        {
            free_tree(root);
            return -1;
        }

        if (!current->left && !current->right)
        {
            /* Leaf node */
            output[decoded++] = current->symbol;
            current = root;
        }
    }

    *output_len = decoded;
    free_tree(root);

    return (decoded == original_size) ? 0 : -1;
}