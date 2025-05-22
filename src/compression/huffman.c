/**
 * huffman.c - Implementation of Huffman compression algorithm
 * * This file implements the Huffman coding algorithm for data compression
 * and decompression.
 * * Only uses the following standard C libraries as required:
 * - stdio.h (for file I/O and printing)
 * - stdlib.h (for memory allocation)
 * - string.h (for string operations)
 * - math.h (not used in this file)
 */

#include "compression/huffman.h"
#include <stdio.h>  /* For file I/O and printing */
#include <stdlib.h> /* For memory allocation */
#include <string.h> /* For string operations */

/* Debug printing support */
#ifdef HUFFMAN_DEBUG
#define DEBUG_PRINT(...) printf("[Huffman] " __VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

#define MAX_SYMBOLS 256                      /* Maximum number of symbols (bytes) */
#define MAX_TREE_NODES (MAX_SYMBOLS * 2 - 1) /* Maximum nodes in Huffman tree */

/* Helper structure for building the Huffman tree */
typedef struct
{
    huffman_node *nodes[MAX_TREE_NODES];
    unsigned long count; // Replaced size_t with unsigned long
} huffman_node_pool;

/* Helper structure for priority queue */
typedef struct
{
    huffman_node *nodes[MAX_SYMBOLS];
    unsigned long count; // Replaced size_t with unsigned long
} priority_queue;

/* Forward declarations of helper functions */
static void count_frequencies(const unsigned char *input, unsigned long input_len, unsigned long frequencies[MAX_SYMBOLS]); // Replaced uint8_t with unsigned char, size_t with unsigned long
static huffman_node *build_huffman_tree(unsigned long frequencies[MAX_SYMBOLS]);
static void generate_huffman_codes(huffman_node *root, huffman_code codes[MAX_SYMBOLS], unsigned char code_buffer[256], int code_len);
static void priority_queue_insert(priority_queue *queue, huffman_node *node);
static huffman_node *priority_queue_extract_min(priority_queue *queue);
static void free_huffman_tree(huffman_node *root);
static int write_bit(unsigned char *output, unsigned long *byte_pos, unsigned long *bit_pos, int bit);                                // Replaced uint8_t with unsigned char, size_t with unsigned long
static int read_bit(const unsigned char *input, unsigned long *byte_pos, unsigned long *bit_pos);                                     // Replaced uint8_t with unsigned char, size_t with unsigned long
static int write_tree(huffman_node *root, unsigned char *output, unsigned long *byte_pos, unsigned long *bit_pos);                    // Replaced uint8_t with unsigned char, size_t with unsigned long
static huffman_node *read_tree(const unsigned char *input, unsigned long *byte_pos, unsigned long *bit_pos, huffman_node_pool *pool); // Replaced uint8_t with unsigned char, size_t with unsigned long

// Replaced size_t with unsigned long
unsigned long huffman_worst_case_size(unsigned long input_len)
{
    /* Worst case for Huffman is when all symbols have equal frequency,
     * resulting in fixed-length codes. In this case, we need:
     * - Header with Huffman tree (at most 2*256 - 1 nodes, or ~512 bytes for a naive representation)
     * - Each symbol encoded using approximately log2(256) = 8 bits (so no compression benefit)
     * Plus additional overhead for storing the original size and tree structure.
     * A simple estimate is input_len + tree_size + original_size_storage.
     * Tree size can be up to (2 * MAX_SYMBOLS - 1) * (1 bit for node type + 8 bits for symbol if leaf).
     * This is roughly 511 * 9 bits ~ 575 bytes in a compact form.
     * Storing original size (unsigned long) is sizeof(unsigned long).
     */
    // A conservative estimate: input length + space for tree + original length storage + some padding
    return input_len + (MAX_TREE_NODES) + sizeof(unsigned long) + 256; // Increased padding for safety
}

/**
 * Count frequencies of each byte in the input data
 * * @param input Input data - Replaced uint8_t with unsigned char
 * @param input_len Length of input data - Replaced size_t with unsigned long
 * @param frequencies Array to store frequencies
 */
// Replaced uint8_t with unsigned char, size_t with unsigned long
static void count_frequencies(const unsigned char *input, unsigned long input_len, unsigned long frequencies[MAX_SYMBOLS])
{
    unsigned long i; // Replaced size_t with unsigned long

    /* Initialize frequencies to 0 */
    memset(frequencies, 0, MAX_SYMBOLS * sizeof(unsigned long));

    /* Count occurrences of each byte */
    for (i = 0; i < input_len; i++)
    {
        frequencies[input[i]]++;
    }

    DEBUG_PRINT("Counted frequencies of %lu bytes\n", input_len); // Use %lu for unsigned long
}

/**
 * Insert a node into the priority queue
 * * @param queue Priority queue
 * @param node Node to insert
 */
static void priority_queue_insert(priority_queue *queue, huffman_node *node)
{
    unsigned long i, j; // Replaced size_t with unsigned long

    if (queue->count >= MAX_SYMBOLS)
    {
        // This should ideally not happen if MAX_SYMBOLS is handled correctly
        DEBUG_PRINT("Error: Priority queue full, cannot insert.\n");
        return;
    }

    /* Insert at the end */
    queue->nodes[queue->count] = node;
    queue->count++;

    /* Sift up to maintain heap property (min-heap) */
    i = queue->count - 1;
    while (i > 0)
    {
        j = (i - 1) / 2; /* Parent index */
        if (queue->nodes[j]->frequency <= queue->nodes[i]->frequency)
        {
            break; /* Heap property satisfied */
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
 * * @param queue Priority queue
 * @return Node with minimum frequency
 */
static huffman_node *priority_queue_extract_min(priority_queue *queue)
{
    huffman_node *min_node;
    unsigned long i, j, k; // Replaced size_t with unsigned long

    if (queue->count == 0)
    {
        return NULL;
    }

    /* Get the minimum (root) node */
    min_node = queue->nodes[0];

    /* Replace root with last element */
    queue->nodes[0] = queue->nodes[queue->count - 1];
    queue->count--;

    /* Sift down to maintain heap property (min-heap) */
    i = 0;
    while (1)
    {
        j = 2 * i + 1;              /* Left child */
        k = 2 * i + 2;              /* Right child */
        unsigned long smallest = i; // Index of the smallest among i, j, k

        if (j < queue->count && queue->nodes[j]->frequency < queue->nodes[smallest]->frequency)
        {
            smallest = j;
        }
        if (k < queue->count && queue->nodes[k]->frequency < queue->nodes[smallest]->frequency)
        {
            smallest = k;
        }

        if (smallest == i)
        {
            break; // Heap property satisfied
        }

        /* Swap with the smallest child */
        huffman_node *temp = queue->nodes[i];
        queue->nodes[i] = queue->nodes[smallest];
        queue->nodes[smallest] = temp;

        i = smallest; // Move down to the swapped child
    }

    return min_node;
}

/**
 * Build a Huffman tree from frequency data
 * * @param frequencies Array of byte frequencies
 * @return Root node of the Huffman tree
 */
static huffman_node *build_huffman_tree(unsigned long frequencies[MAX_SYMBOLS])
{
    priority_queue queue;
    // Node pool is managed by freeing the tree later.
    // For dynamic allocation within this function, ensure all paths free memory on error.
    huffman_node *left, *right, *parent;
    int i;
    unsigned long nodes_created = 0; // Keep track of allocated nodes for potential cleanup
    huffman_node *allocated_nodes[MAX_TREE_NODES];

    /* Initialize the priority queue */
    queue.count = 0;

    /* Create a leaf node for each symbol with non-zero frequency */
    for (i = 0; i < MAX_SYMBOLS; i++)
    {
        if (frequencies[i] > 0)
        {
            huffman_node *new_node = (huffman_node *)malloc(sizeof(huffman_node));
            if (new_node == NULL)
            {
                DEBUG_PRINT("Error: malloc failed for leaf node.\n");
                // Free previously allocated nodes in this loop
                for (unsigned long k = 0; k < nodes_created; ++k)
                    free(allocated_nodes[k]);
                return NULL;
            }
            allocated_nodes[nodes_created++] = new_node;

            new_node->symbol = (unsigned char)i;
            new_node->frequency = frequencies[i];
            new_node->left = NULL;
            new_node->right = NULL;

            priority_queue_insert(&queue, new_node);
        }
    }

    /* Special case: empty input (no symbols with frequency > 0) */
    if (queue.count == 0)
    {
        DEBUG_PRINT("No symbols with frequency > 0. Cannot build Huffman tree.\n");
        return NULL; // Or handle as per specification for empty input
    }

    /* Special case: only one unique symbol */
    if (queue.count == 1)
    {
        huffman_node *single_leaf = priority_queue_extract_min(&queue); // This is from allocated_nodes

        // Create a dummy parent node. The standard Huffman algorithm needs at least two nodes to combine.
        // One way is to make the single leaf the left child and have no right child,
        // or create a dummy right child. For decompression to work, the tree structure must be consistent.
        // A common approach is to make the single symbol's code '0'.
        // To represent this with the tree structure, we can have a parent with this leaf as left, and a null right.
        // Or, create a parent, make the leaf its left child, and a dummy node as its right child.
        // Let's use a parent with the single leaf as left, and a dummy right child for standard tree traversal.

        parent = (huffman_node *)malloc(sizeof(huffman_node));
        if (parent == NULL)
        {
            DEBUG_PRINT("Error: malloc failed for parent of single symbol.\n");
            // `single_leaf` is already in `allocated_nodes`. We need to free it if we return.
            // However, since it was extracted, it's not in the queue.
            // The `allocated_nodes` array should be used to free all nodes created so far.
            for (unsigned long k = 0; k < nodes_created; ++k)
                free(allocated_nodes[k]);
            return NULL;
        }
        allocated_nodes[nodes_created++] = parent;

        // It's often simpler to ensure the tree building loop runs by adding a dummy node if queue.count == 1
        // Or, handle the single symbol case specifically in encoding/decoding.
        // For this implementation, let's assume the tree building loop will create a valid structure.
        // If only one symbol, its code is effectively '0' or '1'.
        // The loop below will create a parent.
        // Re-insert the single_leaf to ensure the loop runs at least once if it's the only one.
        priority_queue_insert(&queue, single_leaf);
    }

    /* Build the Huffman tree by repeatedly combining the two nodes
     * with the lowest frequencies */
    while (queue.count > 1)
    {
        /* Extract the two nodes with minimum frequency */
        left = priority_queue_extract_min(&queue);
        right = priority_queue_extract_min(&queue);

        if (left == NULL || right == NULL)
        { // Should not happen if queue.count > 1
            DEBUG_PRINT("Error: Extracted NULL node from priority queue.\n");
            // Free all nodes created so far
            for (unsigned long k = 0; k < nodes_created; ++k)
                free(allocated_nodes[k]);
            // Also, if left or right is not NULL but the other is, free the non-NULL one if it's not in allocated_nodes
            // However, they should be from allocated_nodes if logic is correct.
            return NULL;
        }

        /* Create a new internal node with these two nodes as children */
        parent = (huffman_node *)malloc(sizeof(huffman_node));
        if (parent == NULL)
        {
            DEBUG_PRINT("Error: malloc failed for internal node.\n");
            // Free all nodes created so far, including left and right if they were just extracted
            for (unsigned long k = 0; k < nodes_created; ++k)
                free(allocated_nodes[k]);
            // Left and right were extracted, so they are part of `allocated_nodes`
            return NULL;
        }
        allocated_nodes[nodes_created++] = parent;

        parent->symbol = 0; /* Not used for internal nodes, can be any value */
        parent->frequency = left->frequency + right->frequency;
        parent->left = left;
        parent->right = right;

        priority_queue_insert(&queue, parent);
    }

    /* The remaining node is the root of the Huffman tree */
    huffman_node *root_node = priority_queue_extract_min(&queue);
    if (root_node == NULL && nodes_created > 0 && queue.count == 0)
    {
        // This implies the tree was built, but extract_min failed, or queue was empty.
        // If nodes_created > 0, it means we had symbols.
        // If root_node is NULL after the loop, it's an issue.
        DEBUG_PRINT("Warning: Huffman tree root is NULL but nodes were processed.\n");
        // Fall through, will likely be caught by subsequent checks.
    }
    // If root_node is NULL and nodes_created == 0, it means empty input, handled earlier.

    return root_node;
}

/**
 * Generate Huffman codes for all symbols in the tree
 * * @param root Root of the Huffman tree
 * @param codes Array to store generated codes
 * @param code_buffer Buffer to build codes during traversal
 * @param code_len Current code length during traversal
 */
static void generate_huffman_codes(huffman_node *root, huffman_code codes[MAX_SYMBOLS],
                                   unsigned char code_buffer[256], int code_len)
{
    if (root == NULL)
    {
        return;
    }

    /* If this is a leaf node, store the code */
    if (root->left == NULL && root->right == NULL)
    {
        if (code_len > 255)
        { // Code length exceeds buffer for huffman_code.code
            DEBUG_PRINT("Error: Huffman code length %d for symbol %d exceeds max (255).\n", code_len, root->symbol);
            // This scenario is highly unlikely with MAX_SYMBOLS = 256
            return;
        }
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
    if (root->left != NULL)
    {
        if (code_len < 256)
        { // Prevent buffer overflow on code_buffer
            code_buffer[code_len] = 0;
            generate_huffman_codes(root->left, codes, code_buffer, code_len + 1);
        }
        else
        {
            DEBUG_PRINT("Error: Code buffer overflow during left traversal.\n");
        }
    }

    /* Traverse right (add 1 to code) */
    if (root->right != NULL)
    {
        if (code_len < 256)
        { // Prevent buffer overflow on code_buffer
            code_buffer[code_len] = 1;
            generate_huffman_codes(root->right, codes, code_buffer, code_len + 1);
        }
        else
        {
            DEBUG_PRINT("Error: Code buffer overflow during right traversal.\n");
        }
    }
}

/**
 * Free memory used by Huffman tree
 * * @param root Root of the Huffman tree
 */
static void free_huffman_tree(huffman_node *root)
{
    if (root == NULL)
    {
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
 * * @param output Output buffer - Replaced uint8_t with unsigned char
 * @param byte_pos Current byte position - Replaced size_t with unsigned long
 * @param bit_pos Current bit position within the byte - Replaced size_t with unsigned long
 * @param bit Bit to write (0 or 1)
 * @return 0 on success, -1 on failure (e.g. if output buffer is too small, though not checked here)
 */
// Replaced uint8_t with unsigned char, size_t with unsigned long
static int write_bit(unsigned char *output, unsigned long *byte_pos, unsigned long *bit_pos, int bit)
{
    /* Set or clear the bit */
    if (bit)
    {                                                 // if bit is 1
        output[*byte_pos] |= (1 << (7 - (*bit_pos))); // MSB first
    }
    else
    {                                                  // if bit is 0
        output[*byte_pos] &= ~(1 << (7 - (*bit_pos))); // MSB first
    }

    /* Move to the next bit */
    (*bit_pos)++;
    if (*bit_pos == 8)
    {
        *bit_pos = 0;
        (*byte_pos)++;
    }

    return 0;
}

/**
 * Read a single bit from the input buffer
 * * @param input Input buffer - Replaced uint8_t with unsigned char
 * @param byte_pos Current byte position - Replaced size_t with unsigned long
 * @param bit_pos Current bit position within the byte - Replaced size_t with unsigned long
 * @return 0 or 1 (the bit value), or -1 on error (e.g. end of buffer, though not checked here)
 */
// Replaced uint8_t with unsigned char, size_t with unsigned long
static int read_bit(const unsigned char *input, unsigned long *byte_pos, unsigned long *bit_pos)
{
    int bit_val;

    /* Get the bit */
    bit_val = (input[*byte_pos] >> (7 - (*bit_pos))) & 1; // MSB first

    /* Move to the next bit */
    (*bit_pos)++;
    if (*bit_pos == 8)
    {
        *bit_pos = 0;
        (*byte_pos)++;
    }

    return bit_val;
}

/**
 * Write a Huffman tree to the output buffer (canonical representation)
 * Format: 0 for internal node, 1 for leaf node followed by 8-bit symbol.
 * * @param root Root of the Huffman tree
 * @param output Output buffer - Replaced uint8_t with unsigned char
 * @param byte_pos Current byte position - Replaced size_t with unsigned long
 * @param bit_pos Current bit position within the byte - Replaced size_t with unsigned long
 * @return 0 on success, -1 on failure
 */
// Replaced uint8_t with unsigned char, size_t with unsigned long
static int write_tree(huffman_node *root, unsigned char *output, unsigned long *byte_pos, unsigned long *bit_pos)
{
    if (root == NULL)
    {
        // This case should ideally be handled by the caller or tree construction
        // If we must write something, it depends on the agreed format for NULL subtrees.
        // For this canonical representation, a NULL child in a valid tree means its parent was a leaf,
        // or it's an error in tree structure.
        // Let's assume valid trees are passed.
        return 0;
    }

    /* If this is a leaf node, write 1 followed by the symbol */
    if (root->left == NULL && root->right == NULL)
    {
        if (write_bit(output, byte_pos, bit_pos, 1) != 0)
            return -1; // Write '1' for leaf

        /* Write the symbol (8 bits) */
        int i;
        for (i = 7; i >= 0; i--)
        { // MSB of symbol first
            if (write_bit(output, byte_pos, bit_pos, (root->symbol >> i) & 1) != 0)
                return -1;
        }
        return 0;
    }

    /* If this is an internal node, write 0 and then write the left and right subtrees */
    if (write_bit(output, byte_pos, bit_pos, 0) != 0)
        return -1; // Write '0' for internal node

    if (write_tree(root->left, output, byte_pos, bit_pos) != 0)
        return -1;
    if (write_tree(root->right, output, byte_pos, bit_pos) != 0)
        return -1;

    return 0;
}

/**
 * Read a Huffman tree from the input buffer
 * * @param input Input buffer - Replaced uint8_t with unsigned char
 * @param byte_pos Current byte position - Replaced size_t with unsigned long
 * @param bit_pos Current bit position within the byte - Replaced size_t with unsigned long
 * @param pool Pool of nodes for memory management (caller responsible for freeing nodes in pool on error)
 * @return Root of the Huffman tree, or NULL on failure
 */
// Replaced uint8_t with unsigned char, size_t with unsigned long
static huffman_node *read_tree(const unsigned char *input, unsigned long *byte_pos, unsigned long *bit_pos, huffman_node_pool *pool)
{
    int bit_val, i;
    unsigned char symbol_val = 0;
    huffman_node *new_node;

    /* Check if we have space for a new node in the pool (for cleanup tracking) */
    if (pool->count >= MAX_TREE_NODES)
    {
        DEBUG_PRINT("Error: Node pool full during tree read.\n");
        return NULL;
    }

    /* Read a bit to determine if this is a leaf or internal node */
    bit_val = read_bit(input, byte_pos, bit_pos);
    if (bit_val < 0)
    { /* Assuming read_bit could return -1 on EOF, though current one doesn't */
        DEBUG_PRINT("Error: Failed to read bit for node type.\n");
        return NULL;
    }

    /* Allocate a new node */
    new_node = (huffman_node *)malloc(sizeof(huffman_node));
    if (new_node == NULL)
    {
        DEBUG_PRINT("Error: malloc failed for tree node during read.\n");
        return NULL;
    }

    /* Add to the pool for later cleanup if function succeeds or for caller cleanup on failure */
    pool->nodes[pool->count++] = new_node;

    if (bit_val == 1)
    { // Leaf node
        /* Leaf node - read the symbol (8 bits) */
        for (i = 7; i >= 0; i--)
        { // MSB of symbol first
            bit_val = read_bit(input, byte_pos, bit_pos);
            if (bit_val < 0)
            {
                DEBUG_PRINT("Error: Failed to read symbol bit.\n");
                // new_node is in pool, caller should handle freeing it
                return NULL;
            }
            symbol_val |= (bit_val << i);
        }

        new_node->symbol = symbol_val;
        new_node->frequency = 0; /* Not needed for decompression, can be set to 0 */
        new_node->left = NULL;
        new_node->right = NULL;
    }
    else
    {                            // Internal node (bit_val == 0)
        new_node->symbol = 0;    /* Not used for internal nodes */
        new_node->frequency = 0; /* Not needed for decompression */

        new_node->left = read_tree(input, byte_pos, bit_pos, pool);
        if (new_node->left == NULL)
        {
            // Error reading left child. new_node is in pool.
            // Right child not yet read.
            return NULL;
        }

        new_node->right = read_tree(input, byte_pos, bit_pos, pool);
        if (new_node->right == NULL)
        {
            // Error reading right child. new_node and its left child are in pool.
            return NULL;
        }
    }

    return new_node;
}

/**
 * Compress data using Huffman coding
 * * @param input Input data - Replaced uint8_t with unsigned char
 * @param input_len Length of input data - Replaced size_t with unsigned long
 * @param output Output buffer - Replaced uint8_t with unsigned char
 * @param output_max_len Maximum length of output buffer - Replaced size_t with unsigned long
 * @param output_len Actual length of compressed data - Replaced size_t with unsigned long
 * @return 0 on success, -1 on failure
 */
// Replaced uint8_t with unsigned char, size_t with unsigned long
int huffman_compress(const unsigned char *input, unsigned long input_len,
                     unsigned char *output, unsigned long output_max_len,
                     unsigned long *output_len)
{
    unsigned long frequencies[MAX_SYMBOLS];
    huffman_node *root = NULL;
    huffman_code codes[MAX_SYMBOLS];    // To store generated codes
    unsigned char code_buffer[256];     // Temporary buffer for generating codes
    unsigned long current_byte_pos = 0; // Current byte position in output buffer
    unsigned long current_bit_pos = 0;  // Current bit position in the current_byte_pos
    unsigned long i, j;

    /* Check parameters */
    if (input == NULL || output == NULL || output_len == NULL)
    {
        DEBUG_PRINT("Error: NULL parameter in huffman_compress.\n");
        return -1;
    }

    if (input_len == 0)
    {
        *output_len = 0; // No data to compress
        DEBUG_PRINT("Input length is 0, compressed length is 0.\n");
        return 0; // Success for empty input
    }

    // Check if output buffer is potentially too small even for header.
    // Header: original_size (sizeof unsigned long) + tree (worst case)
    // A very rough check, huffman_worst_case_size is more accurate.
    if (output_max_len < sizeof(unsigned long) + 10)
    { // 10 is arbitrary small number for tree
        DEBUG_PRINT("Error: Output buffer too small for header.\n");
        return -1;
    }

    /* Count frequencies of each byte */
    count_frequencies(input, input_len, frequencies);

    /* Build the Huffman tree */
    root = build_huffman_tree(frequencies);
    if (root == NULL)
    {
        DEBUG_PRINT("Error: Failed to build Huffman tree.\n");
        return -1; // Failure in tree building
    }

    /* Initialize code array (especially code_len) */
    for (i = 0; i < MAX_SYMBOLS; i++)
    {
        codes[i].code_len = 0; // Mark all as not yet generated
    }

    /* Generate codes for each symbol */
    generate_huffman_codes(root, codes, code_buffer, 0);

    /* --- Start writing to output buffer --- */
    // 1. Write the original data size (unsigned long)
    if (current_byte_pos + sizeof(unsigned long) > output_max_len)
    {
        DEBUG_PRINT("Error: Output buffer too small for original size.\n");
        free_huffman_tree(root);
        return -1;
    }
    // Manual serialization of unsigned long (assuming little-endian for this example, can be platform dependent)
    // Or, more portably, memcpy. For fixed size types, direct copy is fine if endianness matches or is handled.
    // Let's use memcpy for safety and clarity.
    memcpy(output + current_byte_pos, &input_len, sizeof(unsigned long));
    current_byte_pos += sizeof(unsigned long);
    current_bit_pos = 0; // Reset bit position as we are byte-aligned now

    DEBUG_PRINT("Wrote original size: %lu bytes.\n", input_len);

    // 2. Write the Huffman tree
    // Before writing tree, ensure output buffer has space.
    // This is tricky as tree size is variable. huffman_worst_case_size should cover this.
    if (write_tree(root, output, &current_byte_pos, &current_bit_pos) != 0)
    {
        DEBUG_PRINT("Error: Failed to write Huffman tree to output.\n");
        free_huffman_tree(root);
        return -1;
    }
    // If write_tree wrote partial byte, align to next byte for data
    if (current_bit_pos != 0)
    {
        current_bit_pos = 0;
        current_byte_pos++;
    }
    DEBUG_PRINT("Wrote Huffman tree. Current byte_pos: %lu\n", current_byte_pos);

    // 3. Write the compressed data
    for (i = 0; i < input_len; i++)
    {
        unsigned char symbol = input[i];
        if (codes[symbol].code_len == 0 && input_len > 0)
        {
            // This can happen if a symbol was in input but not in frequencies (e.g. single symbol file)
            // or if generate_huffman_codes had an issue.
            // build_huffman_tree should handle single symbol case correctly.
            DEBUG_PRINT("Error: No Huffman code for symbol %d (ASCII '%c').\n", symbol, symbol);
            free_huffman_tree(root);
            return -1;
        }
        for (j = 0; j < codes[symbol].code_len; j++)
        {
            if (current_byte_pos >= output_max_len)
            {
                DEBUG_PRINT("Error: Output buffer overflow while writing data bits.\n");
                free_huffman_tree(root);
                return -1;
            }
            if (write_bit(output, &current_byte_pos, &current_bit_pos, codes[symbol].code[j]) != 0)
            {
                DEBUG_PRINT("Error: Failed to write data bit.\n");
                free_huffman_tree(root);
                return -1;
            }
        }
    }

    /* Finalize output length */
    // If the last byte is partially filled, current_byte_pos needs to be incremented.
    if (current_bit_pos != 0)
    {
        current_byte_pos++;
    }
    *output_len = current_byte_pos;

    if (*output_len > output_max_len)
    {
        DEBUG_PRINT("Error: Calculated output_len (%lu) exceeds output_max_len (%lu).\n", *output_len, output_max_len);
        // This indicates a logic error or insufficient worst_case_size.
        free_huffman_tree(root);
        return -1;
    }

    /* Clean up */
    free_huffman_tree(root);

    DEBUG_PRINT("Compressed %lu bytes to %lu bytes (%.2f%% of original)\n",
                input_len, *output_len,
                (input_len > 0) ? (float)(*output_len) * 100.0f / input_len : 0.0f);

    return 0; // Success
}

/**
 * Decompress data using Huffman coding
 * * @param input Input data (compressed) - Replaced uint8_t with unsigned char
 * @param input_len Length of input data - Replaced size_t with unsigned long
 * @param output Output buffer - Replaced uint8_t with unsigned char
 * @param output_max_len Maximum length of output buffer - Replaced size_t with unsigned long
 * @param output_len Actual length of decompressed data - Replaced size_t with unsigned long
 * @return 0 on success, -1 on failure
 */
// Replaced uint8_t with unsigned char, size_t with unsigned long
int huffman_decompress(const unsigned char *input, unsigned long input_len,
                       unsigned char *output, unsigned long output_max_len,
                       unsigned long *output_len)
{
    huffman_node_pool node_pool; // For managing nodes read from input
    huffman_node *root = NULL, *current_node = NULL;
    unsigned long original_data_size = 0;
    unsigned long current_byte_pos = 0; // Current byte position in input buffer
    unsigned long current_bit_pos = 0;  // Current bit position in the current_byte_pos
    unsigned long decompressed_bytes_count = 0;
    int bit_val;
    unsigned long i; // Loop variable

    /* Check parameters */
    if (input == NULL || output == NULL || output_len == NULL)
    {
        DEBUG_PRINT("Error: NULL parameter in huffman_decompress.\n");
        return -1;
    }

    if (input_len == 0)
    {
        *output_len = 0; // No data to decompress
        DEBUG_PRINT("Input length is 0, decompressed length is 0.\n");
        return 0; // Success for empty input
    }

    /* Initialize node pool for cleanup */
    node_pool.count = 0;

    /* --- Read from input buffer --- */
    // 1. Read the original data size (unsigned long)
    if (current_byte_pos + sizeof(unsigned long) > input_len)
    {
        DEBUG_PRINT("Error: Input buffer too small to read original size.\n");
        return -1;
    }
    memcpy(&original_data_size, input + current_byte_pos, sizeof(unsigned long));
    current_byte_pos += sizeof(unsigned long);
    current_bit_pos = 0; // Reset bit position

    DEBUG_PRINT("Read original data size: %lu bytes.\n", original_data_size);

    // Check if output buffer is sufficient for decompressed data
    if (output_max_len < original_data_size)
    {
        DEBUG_PRINT("Error: Output buffer (max %lu) too small for decompressed data (%lu).\n", output_max_len, original_data_size);
        return -1;
    }

    // If original data size is 0, we are done.
    if (original_data_size == 0)
    {
        *output_len = 0;
        DEBUG_PRINT("Original data size is 0, decompression complete.\n");
        return 0;
    }

    // 2. Read the Huffman tree
    root = read_tree(input, &current_byte_pos, &current_bit_pos, &node_pool);
    if (root == NULL)
    {
        DEBUG_PRINT("Error: Failed to read Huffman tree from input.\n");
        for (i = 0; i < node_pool.count; i++)
            free(node_pool.nodes[i]); // Cleanup nodes allocated by read_tree
        return -1;
    }
    // Align to next byte if tree reading left us mid-byte
    if (current_bit_pos != 0)
    {
        current_bit_pos = 0;
        current_byte_pos++;
    }
    DEBUG_PRINT("Read Huffman tree. Current byte_pos: %lu\n", current_byte_pos);

    // 3. Decode the data
    current_node = root;
    while (decompressed_bytes_count < original_data_size)
    {
        if (current_byte_pos >= input_len && !(current_byte_pos == input_len - 1 && current_bit_pos < 8))
        {
            // Reached end of input prematurely or exactly at the end but expecting more bits
            DEBUG_PRINT("Error: End of input reached prematurely during decompression. Expected %lu bytes, got %lu.\n", original_data_size, decompressed_bytes_count);
            free_huffman_tree(root); // read_tree uses malloc, so free_huffman_tree is appropriate
            return -1;
        }

        bit_val = read_bit(input, &current_byte_pos, &current_bit_pos);
        if (bit_val < 0)
        { // Should not happen with current read_bit
            DEBUG_PRINT("Error: Failed to read data bit during decompression.\n");
            free_huffman_tree(root);
            return -1;
        }

        if (bit_val == 0)
        {
            current_node = current_node->left;
        }
        else
        {
            current_node = current_node->right;
        }

        if (current_node == NULL)
        {
            // This indicates a corrupted tree or data stream
            DEBUG_PRINT("Error: Traversed to NULL node in Huffman tree during decompression.\n");
            free_huffman_tree(root);
            return -1;
        }

        if (current_node->left == NULL && current_node->right == NULL)
        { // Leaf node
            if (decompressed_bytes_count >= output_max_len)
            {
                DEBUG_PRINT("Error: Output buffer overflow during decompression.\n");
                free_huffman_tree(root);
                return -1;
            }
            output[decompressed_bytes_count++] = current_node->symbol;
            current_node = root; // Reset to root for next symbol
        }
    }

    *output_len = decompressed_bytes_count;

    if (decompressed_bytes_count != original_data_size)
    {
        DEBUG_PRINT("Error: Decompressed size (%lu) does not match expected original size (%lu).\n", decompressed_bytes_count, original_data_size);
        free_huffman_tree(root);
        return -1;
    }

    /* Clean up */
    free_huffman_tree(root); // This will free all nodes allocated by read_tree

    DEBUG_PRINT("Decompressed %lu bytes to %lu bytes\n", input_len, *output_len);

    return 0; // Success
}
