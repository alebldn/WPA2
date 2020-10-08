#ifndef WPA2_SPECIFIC_SHA1_H
#define WPA2_SPECIFIC_SHA1_H

/** Includes */
#include "types/sha1_types.h"

/** Defines */
/** Chunks necessary for WPA2-HMAC */
#define WPA2_CHUNKS                 6

/**
 * Definition of the structure sha1_ctx_t: containing
 *
 *  - chunks:               A pointer to a possible list of chunks (dynamically allocated)
 *
 *  - digest:               A statically defined array of [WORDS_IN_HASH] words representing the output hash digest.
 *
 *  - num_of_chunks:        Number of chunks dynamically allocated.
 *
 *  - chunk_counter:        Counter variable that, during the sha1 execution, counts the amount of chunks already completed.
 *
 *  - word_counter:         Counter variable that, during the sha1 execution, counts the amount of words already completed
 *                          (within a single chunk, not globally).
 *
 *  - counter:              Counter variable that, during the sha1 execution, counts the amount of bits already written
 *                          within a single word, not globally.
 */
typedef struct {
    chunk_t chunks[WPA2_CHUNKS];
    uint32_t digest[WORDS_IN_HASH];
    uint64_t num_of_chunks;
    uint64_t chunk_counter;
    uint8_t word_counter;
    uint8_t counter;
} wpa2_specific_sha1_ctx_t;

/** Function declarations */
void ws_sha1_append_bit(wpa2_specific_sha1_ctx_t *ctx, bit_t bit);

void ws_sha1_append_char(wpa2_specific_sha1_ctx_t *ctx, unsigned char value);

void ws_sha1_append_int(wpa2_specific_sha1_ctx_t *ctx, uint32_t value);

void ws_sha1_append_long(wpa2_specific_sha1_ctx_t *ctx, uint64_t value);

void ws_sha1_append_str(wpa2_specific_sha1_ctx_t *ctx, unsigned char *str, uint32_t strlen);

uint32_t ws_rotate_left(uint32_t value, uint32_t shift);

uint32_t ws_rotate_right(uint32_t value, uint32_t shift);

void ws_sha1(wpa2_specific_sha1_ctx_t *ctx);

void ws_sha1_ctx_init(wpa2_specific_sha1_ctx_t *ctx, uint32_t num_of_chunks);

void ws_sha1_ctx_finalize(wpa2_specific_sha1_ctx_t *ctx);

void ws_sha1_ctx_reset_counters(wpa2_specific_sha1_ctx_t *ctx);

#endif /* WPA2_SPECIFIC_SHA1_H */
