/**
 * chacha20.c - Implementation of the ChaCha20 stream cipher
 * * This file implements the ChaCha20 stream cipher as defined in RFC 8439.
 * https://datatracker.ietf.org/doc/html/rfc8439
 * * Only uses the following standard C libraries as required:
 * - stdio.h (only used in debug mode)
 * - stdlib.h (not used in this file)
 * - string.h (for memcpy, memset)
 * - math.h (not used in this file)
 */

#include "encryption/chacha20.h"
#include <string.h> /* For memcpy, memset */

/* Debug printing support */
#ifdef CHACHA20_DEBUG
#include <stdio.h> /* For printf in debug mode */
#define DEBUG_PRINT(...) printf("[ChaCha20] " __VA_ARGS__)
#define DEBUG_PRINT_STATE(label, state) debug_print_state(label, state)
#define DEBUG_PRINT_BYTES(label, bytes, len) debug_print_bytes(label, bytes, len)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINT_STATE(label, state)
#define DEBUG_PRINT_BYTES(label, bytes, len)
#endif

/* Helper macros for ChaCha20 */
#define ROTL32(v, c) (((v) << (c)) | ((v) >> (32 - (c)))) // Assumes unsigned int is 32-bit
#define U32TO8_LITTLE(p, v)              \
    (p)[0] = (unsigned char)((v));       \
    (p)[1] = (unsigned char)((v) >> 8);  \
    (p)[2] = (unsigned char)((v) >> 16); \
    (p)[3] = (unsigned char)((v) >> 24);

#define U8TO32_LITTLE(p)              \
    (((unsigned int)((p)[0])) |       \
     ((unsigned int)((p)[1]) << 8) |  \
     ((unsigned int)((p)[2]) << 16) | \
     ((unsigned int)((p)[3]) << 24))

/* ChaCha20 constants - "expand 32-byte k" in ASCII */
static const unsigned int CHACHA20_CONSTANTS[4] = { // Replaced uint32_t with unsigned int
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

#ifdef CHACHA20_DEBUG
/* Debug helper function to print state matrix */
static void debug_print_state(const char *label, const unsigned int *state)
{ // Replaced uint32_t with unsigned int
    printf("[ChaCha20] %s:\n", label);
    for (int i = 0; i < 4; i++)
    {
        printf("[ChaCha20]   ");
        for (int j = 0; j < 4; j++)
        {
            printf("0x%08x ", state[i * 4 + j]);
        }
        printf("\n");
    }
}

/* Debug helper function to print byte array */
static void debug_print_bytes(const char *label, const unsigned char *bytes, unsigned long len)
{ // Replaced uint8_t with unsigned char, size_t with unsigned long
    printf("[ChaCha20] %s: ", label);
    for (unsigned long i = 0; i < len && i < 32; i++)
    { /* Limit to first 32 bytes */ // Replaced size_t with unsigned long
        printf("%02x", bytes[i]);
        if ((i + 1) % 4 == 0)
            printf(" ");
    }
    if (len > 32)
        printf("... (%lu bytes total)", len); // Use %lu for unsigned long
    printf("\n");
}
#endif

void chacha20_quarterround(int a, int b, int c, int d, unsigned int *state)
{ // Replaced uint32_t with unsigned int
    /* Implements the ChaCha20 quarter round function */
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32(state[d], 16);
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32(state[b], 12);
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32(state[d], 8);
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32(state[b], 7);
}

int chacha20_block(chacha20_ctx *ctx)
{
    unsigned int x[16]; // Replaced uint32_t with unsigned int
    int i;

    if (ctx == NULL)
    {
        return -1;
    }

    DEBUG_PRINT("Generating block for counter: %u\n", ctx->state[12]);
    DEBUG_PRINT_STATE("Initial state", ctx->state);

    /* Create a copy of the current state */
    memcpy(x, ctx->state, sizeof(ctx->state)); // sizeof(ctx->state) is 16 * sizeof(unsigned int)

    /* Apply 20 rounds of ChaCha20 (10 column rounds + 10 diagonal rounds) */
    for (i = 0; i < 10; i++)
    { // RFC specifies 20 rounds, which is 10 pairs of column/diagonal rounds
        /* Column rounds */
        chacha20_quarterround(0, 4, 8, 12, x);
        chacha20_quarterround(1, 5, 9, 13, x);
        chacha20_quarterround(2, 6, 10, 14, x);
        chacha20_quarterround(3, 7, 11, 15, x);

        /* Diagonal rounds */
        chacha20_quarterround(0, 5, 10, 15, x);
        chacha20_quarterround(1, 6, 11, 12, x);
        chacha20_quarterround(2, 7, 8, 13, x);
        chacha20_quarterround(3, 4, 9, 14, x);

        DEBUG_PRINT("After round %d\n", (i * 2) + 2); // Each loop iteration is 2 rounds
    }

    DEBUG_PRINT_STATE("After 20 rounds", x);

    /* Add the original state to the result */
    for (i = 0; i < 16; i++)
    {
        x[i] += ctx->state[i];
    }

    DEBUG_PRINT_STATE("After final addition", x);

    /* Convert to little-endian bytes and store in keystream */
    for (i = 0; i < 16; i++)
    {
        U32TO8_LITTLE(ctx->keystream + (i * 4), x[i]);
    }

    DEBUG_PRINT_BYTES("Generated keystream", ctx->keystream, CHACHA20_BLOCK_SIZE);

    /* Increment counter for next block and handle overflow */
    ctx->state[12]++;
    if (ctx->state[12] == 0)
    {
        /* Counter overflow - increment the next word */
        ctx->state[13]++;
        DEBUG_PRINT("WARNING: Counter overflow, incrementing next word\n");
        // Note: RFC 8439 does not specify behavior for 96-bit nonce if state[13] overflows.
        // This implementation follows the common practice for 64-bit block counter.
    }

    /* Reset position in keystream */
    ctx->position = 0;

    /* Clear sensitive data from the stack */
    memset(x, 0, sizeof(x));

    return 0;
}

int chacha20_init(chacha20_ctx *ctx, const unsigned char *key, const unsigned char *nonce, unsigned int counter)
{ // Replaced uint8_t with unsigned char, uint32_t with unsigned int
    int i;

    if (ctx == NULL || key == NULL || nonce == NULL)
    {
        return -1;
    }

    DEBUG_PRINT("Initializing ChaCha20 with counter=%u\n", counter);
    DEBUG_PRINT_BYTES("Key", key, CHACHA20_KEY_SIZE);
    DEBUG_PRINT_BYTES("Nonce", nonce, CHACHA20_NONCE_SIZE);

    /* Set up the initial state (4x4 matrix of 32-bit words) */

    /* First row: ChaCha20 constants */
    ctx->state[0] = CHACHA20_CONSTANTS[0];
    ctx->state[1] = CHACHA20_CONSTANTS[1];
    ctx->state[2] = CHACHA20_CONSTANTS[2];
    ctx->state[3] = CHACHA20_CONSTANTS[3];

    /* Second and third rows: 256-bit key */
    for (i = 0; i < 8; i++)
    {
        ctx->state[4 + i] = U8TO32_LITTLE(key + (i * 4));
    }

    /* Fourth row: Counter and nonce */
    ctx->state[12] = counter;
    ctx->state[13] = U8TO32_LITTLE(nonce + 0); // Nonce word 0
    ctx->state[14] = U8TO32_LITTLE(nonce + 4); // Nonce word 1
    ctx->state[15] = U8TO32_LITTLE(nonce + 8); // Nonce word 2

    DEBUG_PRINT_STATE("Initial state", ctx->state);

    /* Initialize position to force generation of first block */
    ctx->position = CHACHA20_BLOCK_SIZE;

    return 0;
}

int chacha20_process(chacha20_ctx *ctx, const unsigned char *input, unsigned char *output, unsigned long input_len)
{                    // Replaced uint8_t with unsigned char, size_t with unsigned long
    unsigned long i; // Replaced size_t with unsigned long

    if (ctx == NULL || (input == NULL && input_len > 0) || output == NULL)
    {
        return -1;
    }

    DEBUG_PRINT("Processing %lu bytes of data\n", input_len); // Use %lu for unsigned long
    DEBUG_PRINT_BYTES("Input data (first bytes)", input, input_len > 32 ? 32 : input_len);

    for (i = 0; i < input_len; i++)
    {
        /* Generate new block if needed */
        if (ctx->position >= CHACHA20_BLOCK_SIZE)
        { // Use >= for safety
            if (chacha20_block(ctx) != 0)
            {
                return -1; // Error generating block
            }
        }

        /* XOR input with keystream to produce output */
        output[i] = input[i] ^ ctx->keystream[ctx->position++];
    }

    DEBUG_PRINT_BYTES("Output data (first bytes)", output, input_len > 32 ? 32 : input_len);
    DEBUG_PRINT("Processing complete\n");

    return 0;
}

void chacha20_cleanup(chacha20_ctx *ctx)
{
    if (ctx != NULL)
    {
        /* Zero out the entire context to prevent sensitive data leakage */
        memset(ctx->state, 0, sizeof(ctx->state));
        memset(ctx->keystream, 0, sizeof(ctx->keystream));
        ctx->position = 0;

        DEBUG_PRINT("Context cleared\n");
    }
}
