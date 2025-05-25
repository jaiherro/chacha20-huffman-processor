/**
 * chacha20.c - ChaCha20 stream cipher implementation (RFC 8439)
 *
 * Built by: Jai Herro
 *
 */

#include "encryption/chacha20.h"
#include <string.h>

#define ROTL32(v, c) (((v) << (c)) | ((v) >> (32 - (c))))

#define U32TO8_LITTLE(p, v)                                                    \
    (p)[0] = (unsigned char)((v));                                             \
    (p)[1] = (unsigned char)((v) >> 8);                                        \
    (p)[2] = (unsigned char)((v) >> 16);                                       \
    (p)[3] = (unsigned char)((v) >> 24);

#define U8TO32_LITTLE(p)                                                       \
    (((unsigned int)((p)[0])) | ((unsigned int)((p)[1]) << 8)                  \
     | ((unsigned int)((p)[2]) << 16) | ((unsigned int)((p)[3]) << 24))

/* ChaCha20 constants: "expand 32-byte k" */
static const unsigned int CONSTANTS[4]
    = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

static void
quarterround (int a, int b, int c, int d, unsigned int *state)
{
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32 (state[d], 16);
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32 (state[b], 12);
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32 (state[d], 8);
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32 (state[b], 7);
}

static int
generate_block (chacha20_ctx *ctx)
{
    unsigned int x[16];
    int i;

    if (!ctx)
        return -1;

    memcpy (x, ctx->state, sizeof (ctx->state));

    /* 20 rounds (10 pairs of column/diagonal rounds) */
    for (i = 0; i < 10; i++)
        {
            /* Column rounds */
            quarterround (0, 4, 8, 12, x);
            quarterround (1, 5, 9, 13, x);
            quarterround (2, 6, 10, 14, x);
            quarterround (3, 7, 11, 15, x);

            /* Diagonal rounds */
            quarterround (0, 5, 10, 15, x);
            quarterround (1, 6, 11, 12, x);
            quarterround (2, 7, 8, 13, x);
            quarterround (3, 4, 9, 14, x);
        }

    /* Add original state */
    for (i = 0; i < 16; i++)
        {
            x[i] += ctx->state[i];
        }

    /* Convert to little-endian bytes */
    for (i = 0; i < 16; i++)
        {
            U32TO8_LITTLE (ctx->keystream + (i * 4), x[i]);
        }

    /* Increment counter */
    if (++ctx->state[12] == 0)
        {
            ctx->state[13]++;
        }

    ctx->position = 0;
    memset (x, 0, sizeof (x));
    return 0;
}

int
chacha20_init (chacha20_ctx *ctx, const unsigned char *key,
               const unsigned char *nonce, unsigned int counter)
{
    int i;

    if (!ctx || !key || !nonce)
        return -1;

    /* Constants */
    for (i = 0; i < 4; i++)
        {
            ctx->state[i] = CONSTANTS[i];
        }

    /* Key (256 bits) */
    for (i = 0; i < 8; i++)
        {
            ctx->state[4 + i] = U8TO32_LITTLE (key + (i * 4));
        }

    /* Counter and nonce */
    ctx->state[12] = counter;
    ctx->state[13] = U8TO32_LITTLE (nonce);
    ctx->state[14] = U8TO32_LITTLE (nonce + 4);
    ctx->state[15] = U8TO32_LITTLE (nonce + 8);

    ctx->position = CHACHA20_BLOCK_SIZE; /* Force block generation */
    return 0;
}

int
chacha20_process (chacha20_ctx *ctx, const unsigned char *input,
                  unsigned char *output, unsigned long len)
{
    unsigned long i;

    if (!ctx || (!input && len > 0) || !output)
        return -1;

    for (i = 0; i < len; i++)
        {
            if (ctx->position >= CHACHA20_BLOCK_SIZE)
                {
                    if (generate_block (ctx) != 0)
                        return -1;
                }
            output[i] = input[i] ^ ctx->keystream[ctx->position++];
        }

    return 0;
}

void
chacha20_cleanup (chacha20_ctx *ctx)
{
    if (ctx)
        {
            memset (ctx, 0, sizeof (*ctx));
        }
}
