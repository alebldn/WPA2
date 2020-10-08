#ifndef WPA2_SPECIFIC_HMAC_H
#define WPA2_SPECIFIC_HMAC_H

/** Includes */
#include "types/hmac_types.h"
#include "wpa2_specific_sha1.h"

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
    wpa2_specific_sha1_ctx_t sha1_ctx_text;
    wpa2_specific_sha1_ctx_t sha1_ctx_key;
    chunk_t outer_pad;
    chunk_t inner_pad;
    uint32_t digest[WORDS_IN_HASH];
} wpa2_specific_hmac_ctx_t;

/** Function declarations */
void ws_hmac_append_bit_key(wpa2_specific_hmac_ctx_t *ctx, bit_t value);

void ws_hmac_append_bit_text(wpa2_specific_hmac_ctx_t *ctx, bit_t value);

void ws_hmac_append_char_key(wpa2_specific_hmac_ctx_t *ctx, unsigned char value);

void ws_hmac_append_char_text(wpa2_specific_hmac_ctx_t *ctx, unsigned char value);

void ws_hmac_append_str_key(wpa2_specific_hmac_ctx_t *ctx, unsigned char *value, uint32_t strlen);

void ws_hmac_append_str_text(wpa2_specific_hmac_ctx_t *ctx, unsigned char *value, uint32_t strlen);

void ws_hmac_append_int_key(wpa2_specific_hmac_ctx_t *ctx, uint32_t value);

void ws_hmac_append_int_text(wpa2_specific_hmac_ctx_t *ctx, uint32_t value);

void ws_hmac_append_long_key(wpa2_specific_hmac_ctx_t *ctx, uint64_t value);

void ws_hmac_append_long_text(wpa2_specific_hmac_ctx_t *ctx, uint64_t value);

void ws_hmac_ctx_init(wpa2_specific_hmac_ctx_t *ctx, uint32_t bits_to_be_written_in_key,
                      uint32_t bits_to_be_written_in_text);

void ws_hmac(wpa2_specific_hmac_ctx_t *ctx);

#endif /* WPA2_SPECIFIC_HMAC_H */
