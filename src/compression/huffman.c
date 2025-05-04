/**
 * huffman.c - Implementation of Huffman compression algorithm
 * 
 * This file implements the Huffman coding algorithm for data compression
 * and decompression.
 * 
 * Only uses the following standard C libraries as required:
 * - stdio.h (for file I/O and printing)
 * - stdlib.h (for memory allocation)
 * - string.h (for string operations)
 * - math.h (not used in this file)
 */

#include "compression/huffman.h"
#include <stdio.h>   /* For file I/O and printing */
#include <stdlib.h>  /* For memory allocation */
#include <string.h>  /* For string operations */

/* Debug printing support */
#ifdef HUFFMAN_DEBUG
#define DEBUG_PRINT(...) printf("[Huffman] " __VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

#define MAX_SYMBOLS 256  /* Maximum number of symbols (bytes) */
#define MAX_TREE_NODES (MAX_SYMBOLS * 2 - 1)  /* Maximum nodes in Huffman tree */

/* Helper structure for building the Huffman tree */
typedef struct {
    huffman_node *nodes[MAX_TREE_NODES];
    size_t count;
} huffman_node_pool;

/* Helper structure for priority queue */
typedef struct {
    huffman_node *nodes[MAX_SYMBOLS];
    size_t count;
} priority_queue;

/* Forward declarations of helper functions */
static void count_frequencies(const uint8_t *input, size_t input_len, unsigned long frequencies[MAX_SYMBOLS]);
static huffman_node *build_huffman_tree(unsigned long frequencies[MAX_SYMBOLS]);
static void generate_huffman_codes(huffman_node *root, huffman_code codes[MAX_SYMBOLS], unsigned char code_buffer[256], int code_len);
static void priority_queue_insert(priority_queue *queue, huffman_node *node);
static huffman_node *priority_queue_extract_min(priority_queue *queue);
static void free_huffman_tree(huffman_node *root);
static int write_bit(uint8_t *output, size_t *byte_pos, size_t *bit_pos, int bit);
static int read_bit(const uint8_t *input, size_t *byte_pos, size_t *bit_pos);
static int write_tree(huffman_node *root, uint8_t *output, size_t *byte_pos, size_t *bit_pos);
static huffman_node *read_tree(const uint8_t *input, size_t *byte_pos, size_t *bit_pos, huffman_node_pool *pool);

size_t huffman_worst_case_size(size_t input_len) {
    /* Worst case for Huffman is when all symbols have equal frequency,
     * resulting in fixed-length codes. In this case, we need:
     * - Header with Huffman tree (at most 2*256 - 1 nodes, or ~512 bytes)
     * - Each symbol encoded using approximately log2(256) = 8 bits
     * Plus additional overhead for storing the original size.
     */
    return input_len + 1024;  /* Conservative estimate */
}

/**
 * Count frequencies of each byte in the input data
 * 
 * @param input Input data
 * @param input_len Length of input data
 * @param frequencies Array to store frequencies
 */
static void count_frequencies(const uint8_t *input, size_t input_len, unsigned long frequencies[MAX_SYMBOLS]) {
    size_t i;
    
    /* Initialize frequencies to 0 */
    memset(frequencies, 0, MAX_SYMBOLS * sizeof(unsigned long));
    
    /* Count occurrences of each byte */
    for (i = 0; i < input_len; i++) {
        frequencies[input[i]]++;
    }
    
    DEBUG_PRINT("Counted frequencies of %zu bytes\n", input_len);
}

/**
 * Insert a node into the priority queue
 * 
 * @param queue Priority queue
 * @param node Node to insert
 */
static void priority_queue_insert(priority_queue *queue, huffman_node *node) {
    size_t i, j;
    
    /* Insert at the end */
    queue->nodes[queue->count] = node;
    queue->count++;
    
    /* Sift up to maintain heap property */
    i = queue->count - 1;
    while (i > 0) {
        j = (i - 1) / 2;  /* Parent index */
        if (queue->nodes[j]->frequency <= queue->nodes[i]->frequency) {
            break;  /* Heap property satisfied */
        }
        
        /* Swap with parent */
        huffman_node *temp = queue->nodes[j];
        queue->nodes[j] = queue->nodes[i];
        queue->nodes[i] = temp;
        
        i = j;
    }
}

/**
 * Extract the minimum frequency node from the priority queue
 * 
 * @param queue Priority queue
 * @return Node with minimum frequency
 */
static huffman_node *priority_queue_extract_min(priority_queue *queue) {
    huffman_node *min_node;
    size_t i, j, k;
    
    if (queue->count == 0) {
        return NULL;
    }
    
    /* Get the minimum (root) node */
    min_node = queue->nodes[0];
    
    /* Replace root with last element */
    queue->nodes[0] = queue->nodes[queue->count - 1];
    queue->count--;
    
    /* Sift down to maintain heap property */
    i = 0;
    while (1) {
        j = 2 * i + 1;  /* Left child */
        k = 2 * i + 2;  /* Right child */
        
        if (j >= queue->count) {
            break;  /* No children */
        }
        
        /* Find the smaller child */
        if (k < queue->count && queue->nodes[k]->frequency < queue->nodes[j]->frequency) {
            j = k;
        }
        
        /* Check if heap property is satisfied */
        if (queue->nodes[i]->frequency <= queue->nodes[j]->frequency) {
            break;
        }
        
        /* Swap with the smaller child */
        huffman_node *temp = queue->nodes[i];
        queue->nodes[i] = queue->nodes[j];
        queue->nodes[j] = temp;
        
        i = j;
    }
    
    return min_node;
}

/**
 * Build a Huffman tree from frequency data
 * 
 * @param frequencies Array of byte frequencies
 * @return Root node of the Huffman tree
 */
static huffman_node *build_huffman_tree(unsigned long frequencies[MAX_SYMBOLS]) {
    priority_queue queue;
    huffman_node *nodes[MAX_SYMBOLS * 2 - 1];  /* Pool for all nodes */
    huffman_node *left, *right, *parent;
    size_t node_count = 0;
    int i;
    
    /* Initialize the priority queue */
    queue.count = 0;
    
    /* Create a leaf node for each symbol with non-zero frequency */
    for (i = 0; i < MAX_SYMBOLS; i++) {
        if (frequencies[i] > 0) {
            nodes[node_count] = (huffman_node *)malloc(sizeof(huffman_node));
            if (nodes[node_count] == NULL) {
                /* Clean up previously allocated nodes */
                while (node_count > 0) {
                    free(nodes[--node_count]);
                }
                return NULL;
            }
            
            nodes[node_count]->symbol = (unsigned char)i;
            nodes[node_count]->frequency = frequencies[i];
            nodes[node_count]->left = NULL;
            nodes[node_count]->right = NULL;
            
            priority_queue_insert(&queue, nodes[node_count]);
            node_count++;
        }
    }
    
    /* Special case: empty input or single symbol */
    if (queue.count == 0) {
        return NULL;
    } else if (queue.count == 1) {
        /* Create a second leaf node with the same symbol */
        huffman_node *right_child = (huffman_node *)malloc(sizeof(huffman_node));
        if (right_child == NULL) {
            free(nodes[0]);
            return NULL;
        }
        right_child->symbol = nodes[0]->symbol;
        right_child->frequency = 0;
        right_child->left = NULL;
        right_child->right = NULL;
        
        /* Create a parent node with both left and right children */
        parent = (huffman_node *)malloc(sizeof(huffman_node));
        if (parent == NULL) {
            free(nodes[0]);
            free(right_child);
            return NULL;
        }
        
        parent->symbol = 0;  /* Not used for internal nodes */
        parent->frequency = nodes[0]->frequency;
        parent->left = nodes[0];
        parent->right = right_child;
        
        /* Add nodes to the pool for cleanup */
        nodes[node_count++] = right_child;
        nodes[node_count++] = parent;
        
        return parent;
    }
    
    /* Build the Huffman tree by repeatedly combining the two nodes 
     * with the lowest frequencies */
    while (queue.count > 1) {
        /* Extract the two nodes with minimum frequency */
        left = priority_queue_extract_min(&queue);
        right = priority_queue_extract_min(&queue);
        
        /* Create a new internal node with these two nodes as children */
        parent = (huffman_node *)malloc(sizeof(huffman_node));
        if (parent == NULL) {
            /* Clean up all allocated nodes */
            for (i = 0; i < node_count; i++) {
                free(nodes[i]);
            }
            return NULL;
        }
        
        parent->symbol = 0;  /* Not used for internal nodes */
        parent->frequency = left->frequency + right->frequency;
        parent->left = left;
        parent->right = right;
        
        nodes[node_count] = parent;
        node_count++;
        
        /* Add the new node back to the priority queue */
        priority_queue_insert(&queue, parent);
    }
    
    /* The remaining node is the root of the Huffman tree */
    return priority_queue_extract_min(&queue);
}

/**
 * Generate Huffman codes for all symbols in the tree
 * 
 * @param root Root of the Huffman tree
 * @param codes Array to store generated codes
 * @param code_buffer Buffer to build codes during traversal
 * @param code_len Current code length during traversal
 */
static void generate_huffman_codes(huffman_node *root, huffman_code codes[MAX_SYMBOLS], 
                                  unsigned char code_buffer[256], int code_len) {
    if (root == NULL) {
        return;
    }
    
    /* If this is a leaf node, store the code */
    if (root->left == NULL && root->right == NULL) {
        codes[root->symbol].symbol = root->symbol;
        memcpy(codes[root->symbol].code, code_buffer, code_len);
        codes[root->symbol].code_len = code_len;
        
        DEBUG_PRINT("Symbol %d (ASCII '%c') -> Code length: %d\n", 
                   root->symbol, 
                   (root->symbol >= 32 && root->symbol <= 126) ? root->symbol : '?', 
                   code_len);
        return;
    }
    
    /* Traverse left (add 0 to code) */
    if (root->left != NULL) {
        code_buffer[code_len] = 0;
        generate_huffman_codes(root->left, codes, code_buffer, code_len + 1);
    }
    
    /* Traverse right (add 1 to code) */
    if (root->right != NULL) {
        code_buffer[code_len] = 1;
        generate_huffman_codes(root->right, codes, code_buffer, code_len + 1);
    }
}

/**
 * Free memory used by Huffman tree
 * 
 * @param root Root of the Huffman tree
 */
static void free_huffman_tree(huffman_node *root) {
    if (root == NULL) {
        return;
    }
    
    /* Recursively free children */
    free_huffman_tree(root->left);
    free_huffman_tree(root->right);
    
    /* Free this node */
    free(root);
}

/**
 * Write a single bit to the output buffer
 * 
 * @param output Output buffer
 * @param byte_pos Current byte position
 * @param bit_pos Current bit position within the byte
 * @param bit Bit to write (0 or 1)
 * @return 0 on success, -1 on failure
 */
static int write_bit(uint8_t *output, size_t *byte_pos, size_t *bit_pos, int bit) {
    /* Set or clear the bit */
    if (bit) {
        output[*byte_pos] |= (1 << (7 - *bit_pos));
    } else {
        output[*byte_pos] &= ~(1 << (7 - *bit_pos));
    }
    
    /* Move to the next bit */
    (*bit_pos)++;
    if (*bit_pos == 8) {
        *bit_pos = 0;
        (*byte_pos)++;
    }
    
    return 0;
}

/**
 * Read a single bit from the input buffer
 * 
 * @param input Input buffer
 * @param byte_pos Current byte position
 * @param bit_pos Current bit position within the byte
 * @return 0 or 1 (the bit value)
 */
static int read_bit(const uint8_t *input, size_t *byte_pos, size_t *bit_pos) {
    int bit;
    
    /* Get the bit */
    bit = (input[*byte_pos] >> (7 - *bit_pos)) & 1;
    
    /* Move to the next bit */
    (*bit_pos)++;
    if (*bit_pos == 8) {
        *bit_pos = 0;
        (*byte_pos)++;
    }
    
    return bit;
}

/**
 * Write a Huffman tree to the output buffer
 * 
 * @param root Root of the Huffman tree
 * @param output Output buffer
 * @param byte_pos Current byte position
 * @param bit_pos Current bit position within the byte
 * @return 0 on success, -1 on failure
 */
static int write_tree(huffman_node *root, uint8_t *output, size_t *byte_pos, size_t *bit_pos) {
    if (root == NULL) {
        return 0;
    }
    
    /* If this is a leaf node, write 1 followed by the symbol */
    if (root->left == NULL && root->right == NULL) {
        write_bit(output, byte_pos, bit_pos, 1);
        
        /* Write the symbol (8 bits) */
        int i;
        for (i = 7; i >= 0; i--) {
            write_bit(output, byte_pos, bit_pos, (root->symbol >> i) & 1);
        }
        
        return 0;
    }
    
    /* If this is an internal node, write 0 and then write the left and right subtrees */
    write_bit(output, byte_pos, bit_pos, 0);
    
    write_tree(root->left, output, byte_pos, bit_pos);
    write_tree(root->right, output, byte_pos, bit_pos);
    
    return 0;
}

/**
 * Read a Huffman tree from the input buffer
 * 
 * @param input Input buffer
 * @param byte_pos Current byte position
 * @param bit_pos Current bit position within the byte
 * @param pool Pool of nodes for memory management
 * @return Root of the Huffman tree, or NULL on failure
 */
static huffman_node *read_tree(const uint8_t *input, size_t *byte_pos, size_t *bit_pos, huffman_node_pool *pool) {
    int bit, i;
    unsigned char symbol = 0;
    huffman_node *node;
    
    /* Check if we have space for a new node */
    if (pool->count >= MAX_TREE_NODES) {
        return NULL;
    }
    
    /* Read a bit to determine if this is a leaf or internal node */
    bit = read_bit(input, byte_pos, bit_pos);
    
    /* Allocate a new node */
    node = (huffman_node *)malloc(sizeof(huffman_node));
    if (node == NULL) {
        return NULL;
    }
    
    /* Add to the pool for later cleanup */
    pool->nodes[pool->count++] = node;
    
    if (bit == 1) {
        /* Leaf node - read the symbol */
        for (i = 7; i >= 0; i--) {
            bit = read_bit(input, byte_pos, bit_pos);
            symbol |= bit << i;
        }
        
        node->symbol = symbol;
        node->frequency = 0;  /* Not needed for decompression */
        node->left = NULL;
        node->right = NULL;
    } else {
        /* Internal node - read left and right subtrees */
        node->symbol = 0;  /* Not used for internal nodes */
        node->frequency = 0;  /* Not needed for decompression */
        node->left = read_tree(input, byte_pos, bit_pos, pool);
        node->right = read_tree(input, byte_pos, bit_pos, pool);
        
        if (node->left == NULL || node->right == NULL) {
            return NULL;
        }
    }
    
    return node;
}

/**
 * Compress data using Huffman coding
 * 
 * @param input Input data
 * @param input_len Length of input data
 * @param output Output buffer
 * @param output_max_len Maximum length of output buffer
 * @param output_len Actual length of compressed data
 * @return 0 on success, -1 on failure
 */
int huffman_compress(const uint8_t *input, size_t input_len, 
                    uint8_t *output, size_t output_max_len,
                    size_t *output_len) {
    unsigned long frequencies[MAX_SYMBOLS];
    huffman_node *root = NULL;
    huffman_code codes[MAX_SYMBOLS];
    unsigned char code_buffer[256];
    size_t byte_pos = 0, bit_pos = 0;
    size_t i, j;
    
    /* Check parameters */
    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }
    
    if (input_len == 0) {
        *output_len = 0;
        return 0;
    }
    
    /* Make sure output buffer is large enough */
    if (output_max_len < huffman_worst_case_size(input_len)) {
        return -1;
    }
    
    /* Count frequencies of each byte */
    count_frequencies(input, input_len, frequencies);
    
    /* Build the Huffman tree */
    root = build_huffman_tree(frequencies);
    if (root == NULL) {
        return -1;
    }
    
    /* Initialize code array */
    for (i = 0; i < MAX_SYMBOLS; i++) {
        codes[i].code_len = 0;
    }
    
    /* Generate codes for each symbol */
    generate_huffman_codes(root, codes, code_buffer, 0);
    
    /* Write the original data size */
    for (i = 0; i < sizeof(size_t); i++) {
        output[byte_pos++] = (input_len >> (i * 8)) & 0xFF;
    }
    
    /* Write the Huffman tree */
    bit_pos = 0;
    write_tree(root, output, &byte_pos, &bit_pos);
    
    /* If there are any unused bits in the last byte, make sure they're 0 */
    if (bit_pos > 0) {
        for (i = bit_pos; i < 8; i++) {
            write_bit(output, &byte_pos, &bit_pos, 0);
        }
    }
    
    /* Write the compressed data */
    bit_pos = 0;
    for (i = 0; i < input_len; i++) {
        unsigned char symbol = input[i];
        for (j = 0; j < codes[symbol].code_len; j++) {
            write_bit(output, &byte_pos, &bit_pos, codes[symbol].code[j]);
        }
    }
    
    /* If there are any unused bits in the last byte, make sure they're 0 */
    if (bit_pos > 0) {
        for (i = bit_pos; i < 8; i++) {
            write_bit(output, &byte_pos, &bit_pos, 0);
        }
    }
    
    /* Set the actual output length */
    *output_len = byte_pos;
    
    /* Clean up */
    free_huffman_tree(root);
    
    DEBUG_PRINT("Compressed %zu bytes to %zu bytes (%.2f%%)\n", 
               input_len, *output_len, (float)*output_len * 100 / input_len);
    
    return 0;
}

/**
 * Decompress data using Huffman coding
 * 
 * @param input Input data (compressed)
 * @param input_len Length of input data
 * @param output Output buffer
 * @param output_max_len Maximum length of output buffer
 * @param output_len Actual length of decompressed data
 * @return 0 on success, -1 on failure
 */
int huffman_decompress(const uint8_t *input, size_t input_len,
                      uint8_t *output, size_t output_max_len,
                      size_t *output_len) {
    huffman_node_pool pool;
    huffman_node *root, *node;
    size_t original_size = 0;
    size_t byte_pos = 0, bit_pos = 0;
    size_t i, output_pos = 0;
    
    /* Check parameters */
    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }
    
    if (input_len == 0) {
        *output_len = 0;
        return 0;
    }
    
    /* Read the original data size */
    for (i = 0; i < sizeof(size_t); i++) {
        original_size |= (size_t)input[byte_pos++] << (i * 8);
    }
    
    /* Check if output buffer is large enough */
    if (output_max_len < original_size) {
        return -1;
    }
    
    /* Initialize node pool */
    pool.count = 0;
    
    /* Read the Huffman tree */
    bit_pos = 0;
    root = read_tree(input, &byte_pos, &bit_pos, &pool);
    if (root == NULL) {
        /* Clean up the node pool */
        for (i = 0; i < pool.count; i++) {
            free(pool.nodes[i]);
        }
        return -1;
    }
    
    /* If there are any unused bits in the last byte, skip them */
    if (bit_pos > 0) {
        bit_pos = 0;
        byte_pos++;
    }
    
    /* Decode the data */
    node = root;
    for (i = 0; i < original_size; ) {
        if (byte_pos >= input_len) {
            /* Clean up the node pool */
            for (i = 0; i < pool.count; i++) {
                free(pool.nodes[i]);
            }
            return -1;
        }
        
        int bit = read_bit(input, &byte_pos, &bit_pos);
        
        if (bit == 0) {
            node = node->left;
        } else {
            node = node->right;
        }
        
        if (node->left == NULL && node->right == NULL) {
            /* Leaf node - output the symbol */
            output[output_pos++] = node->symbol;
            i++;
            
            /* Reset to the root for the next symbol */
            node = root;
        }
    }
    
    /* Set the actual output length */
    *output_len = output_pos;
    
    /* Clean up the node pool */
    for (i = 0; i < pool.count; i++) {
        free(pool.nodes[i]);
    }
    
    DEBUG_PRINT("Decompressed %zu bytes to %zu bytes\n", input_len, *output_len);
    
    return 0;
}
