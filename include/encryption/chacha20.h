/*
 * chacha20.h - ChaCha20 stream cipher implementation (RFC 8439)
 */

#ifndef CHACHA20_H
#define CHACHA20_H

/* ChaCha20 constants */
#define CHACHA20_KEY_SIZE 32   /* 256-bit key */
#define CHACHA20_NONCE_SIZE 12 /* 96-bit nonce */
#define CHACHA20_BLOCK_SIZE 64 /* 512-bit block */
#define CHACHA20_ROUNDS 20     /* Number of rounds */

/* ChaCha20 context structure */
typedef struct
{
    unsigned int  state[16];                      /* 4x4 state matrix */
    unsigned char keystream[CHACHA20_BLOCK_SIZE]; /* Keystream buffer */
    unsigned long position;                       /* Current position */
} chacha20_ctx;

/* Initialise ChaCha20 context with key, nonce, and counter */
int chacha20_init(chacha20_ctx *ctx, const unsigned char *key,
                  const unsigned char *nonce, unsigned int counter);

/* Process data (encrypt/decrypt - same operation) */
int chacha20_process(chacha20_ctx *ctx, const unsigned char *input,
                     unsigned char *output, unsigned long input_len);

/* Generate new keystream block (internal function) */
int chacha20_block(chacha20_ctx *ctx);

/* Perform ChaCha20 quarter round operation */
void chacha20_quarterround(int a, int b, int c, int d, unsigned int *state);

/* Clear sensitive data from memory */
void chacha20_cleanup(chacha20_ctx *ctx);

#endif
