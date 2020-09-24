#ifndef HMAC_H
#define HMAC_H

#include "sha1.h"

#define INNER_PAD_XOR_CONST 0x36363636
#define OUTER_PAD_XOR_CONST 0x5C5C5C5C

typedef struct
{
    sha1_ctx_t sha1_ctx_text;
    sha1_ctx_t sha1_ctx_key;
    chunk_t outer_pad;
    chunk_t inner_pad;
    uint32_t digest[WORDS_IN_HASH];

} hmac_ctx_t;

void hmac_append_bit_key(hmac_ctx_t* ctx, bit_t value);
void hmac_append_bit_text(hmac_ctx_t* ctx, bit_t value);
void hmac_append_char_key(hmac_ctx_t* ctx, unsigned char value);
void hmac_append_char_text(hmac_ctx_t* ctx, unsigned char value);
void hmac_append_str_key(hmac_ctx_t* ctx, unsigned char* value, uint64_t strlen);
void hmac_append_str_text(hmac_ctx_t* ctx, unsigned char* value, uint64_t strlen);
void hmac_append_int_key(hmac_ctx_t* ctx, uint32_t value);
void hmac_append_int_text(hmac_ctx_t* ctx, uint32_t value);
void hmac_append_long_key(hmac_ctx_t* ctx, uint64_t value);
void hmac_append_long_text(hmac_ctx_t* ctx, uint64_t value);


void hmac_ctx_init(hmac_ctx_t* ctx, uint64_t bits_to_be_written_in_key, uint64_t bits_to_be_written_in_text);
void hmac_ctx_dispose(hmac_ctx_t* ctx);
void hmac(hmac_ctx_t* ctx);

#endif /* HMAC_H */
