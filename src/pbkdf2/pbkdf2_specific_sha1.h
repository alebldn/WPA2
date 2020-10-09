#ifndef PBKDF2_SPECIFIC_SHA1_H
#define PBKDF2_SPECIFIC_SHA1_H

/** Includes */
#include "../types/sha1_types.h"

/** Defines */
/** Chunks necessary for WPA2-PBKDF2 */
#define PBKDF2_CHUNKS                       2

/**
 * Definition of the structure ps_specific_sha1_ctx_t: containing
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
    chunk_t chunks[PBKDF2_CHUNKS];
    uint32_t digest[WORDS_IN_HASH];
    uint64_t num_of_chunks;
    uint64_t chunk_counter;
    uint8_t word_counter;
    uint8_t counter;
} pbkdf2_specific_sha1_ctx_t;

/** Function declarations */
void ps_sha1_append_bit(pbkdf2_specific_sha1_ctx_t *ctx, bit_t bit);

void ps_sha1_append_char(pbkdf2_specific_sha1_ctx_t *ctx, unsigned char value);

void ps_sha1_append_int(pbkdf2_specific_sha1_ctx_t *ctx, uint32_t value);

void ps_sha1_append_long(pbkdf2_specific_sha1_ctx_t *ctx, uint64_t value);

void ps_sha1_append_str(pbkdf2_specific_sha1_ctx_t *ctx, unsigned char *str, uint32_t strlen);

uint32_t ps_rotate_left(uint32_t value, uint32_t shift);

uint32_t ps_rotate_right(uint32_t value, uint32_t shift);

void ps_sha1(pbkdf2_specific_sha1_ctx_t *ctx);

void ps_sha1_ctx_init(pbkdf2_specific_sha1_ctx_t *ctx, uint32_t num_of_chunks);

void ps_sha1_ctx_finalize(pbkdf2_specific_sha1_ctx_t *ctx);

void ps_sha1_ctx_reset_counters(pbkdf2_specific_sha1_ctx_t *ctx);

#endif /* SHA1_H */
