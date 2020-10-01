#ifndef HMAC_H
#define HMAC_H

/** Includes */
#include "sha1.h"

/** Defines */
/** Inner Chunk xor constant as defined by the HMAC algorithm */
#define INNER_PAD_XOR_CONST 0x36363636
/** Outer Chunk xor constant as defined by the HMAC algorithm */
#define OUTER_PAD_XOR_CONST 0x5C5C5C5C

/**
 * Definition of the structure hmac_ctx_t, containing:
 *
 *  - sha1_ctx_text:        a struct containing all the variables needed in order to execute the sha1 algorithm on Text,
 *                          as defined in the HMAC algorithm ( HMAC(Key, Text) ).
 *
 *  - sha1_ctx_key:         a struct containing all the variables needed in order to execute the sha1 algorithm on Key,
 *                          as defined in the HMAC algorithm ( HMAC(Key, Text) ).
 *
 *  - outer_pad:            single chunk needed in order to xor with the outer pad constant.
 *
 *  - inner_pad:            single chunk needed in order to xor with the inner pad constant.
 *
 *  - digest:               array of [WORDS_IN_HASH] words needed to represent the Hashed Message Authentication Code,
 *                          the output hash of the HMAC algorithm.
 */
typedef struct {
    sha1_ctx_t sha1_ctx_text;
    sha1_ctx_t sha1_ctx_key;
    chunk_t outer_pad;
    chunk_t inner_pad;
    uint32_t digest[WORDS_IN_HASH];
} hmac_ctx_t;

/** Function declarations */
void hmac_append_bit_key(hmac_ctx_t *ctx, bit_t value);

void hmac_append_bit_text(hmac_ctx_t *ctx, bit_t value);

void hmac_append_char_key(hmac_ctx_t *ctx, unsigned char value);

void hmac_append_char_text(hmac_ctx_t *ctx, unsigned char value);

void hmac_append_str_key(hmac_ctx_t *ctx, unsigned char *value, uint32_t strlen);

void hmac_append_str_text(hmac_ctx_t *ctx, unsigned char *value, uint32_t strlen);

void hmac_append_int_key(hmac_ctx_t *ctx, uint32_t value);

void hmac_append_int_text(hmac_ctx_t *ctx, uint32_t value);

void hmac_append_long_key(hmac_ctx_t *ctx, uint64_t value);

void hmac_append_long_text(hmac_ctx_t *ctx, uint64_t value);

void hmac_ctx_init(hmac_ctx_t *ctx, uint32_t bits_to_be_written_in_key, uint32_t bits_to_be_written_in_text);

void hmac_ctx_dispose(hmac_ctx_t *ctx);

void hmac(hmac_ctx_t *ctx);

#endif /* HMAC_H */
