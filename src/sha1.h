#ifndef SHA1_H
#define SHA1_H

/** Includes */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

/** Defines */
/** Sha1 bit counter value on context initialization */
#define SHA1_BIT_COUNTER_INIT           32

/** Sha1 word counter value on context initialization */
#define SHA1_WORD_COUNTER_INIT          0

/** Sha1 chunk counter value on context initialization */
#define SHA1_CHUNK_COUNTER_INIT         0

/** Number of bits within a single word */
#define BITS_IN_WORD                    32

/** Number of bits within a single chunk */
#define BITS_IN_CHUNK                   512

/** Number of words within a single chunk */
#define WORDS_IN_CHUNK                  16

/** Number of bits in sha1 hash digest */
#define BITS_IN_HASH                    160

/** Number of words in sha1 hash digest */
#define WORDS_IN_HASH                   5

/** Definition of the boolean type bit_t */
typedef enum {
    false,
    true
} bit_t;

/** Definition of the struct chunk_t: contains a static array of [WORDS_IN_CHUNK] words */
typedef struct {
    uint32_t words[WORDS_IN_CHUNK];
} chunk_t;

/** Definition of the structure sha1_ctx_t: containing
 *  - chunks: A pointer to a possible list of chunks (dynamically allocated)
 *  - digest: A statically defined array of [WORDS_IN_HASH] words representing the output hash digest.
 *  - num_of_chunks: Number of chunks dynamically allocated.
 *  - chunk_counter: counter variable that, during the sha1 execution, counts the amount of chunks
 *    already completed.
 *  - word_counter: counter variable that, during the sha1 execution, counts the amount of words
 *    already completed (within a single chunk, not globally).
 *  - counter: counter variable that, during the sha1 execution, counts the amount of bits already
 *    written within a single word, not globally.
 */
typedef struct {
    chunk_t *chunks;
    uint32_t digest[WORDS_IN_HASH];
    uint64_t num_of_chunks;
    uint64_t chunk_counter;
    uint8_t word_counter;
    uint8_t counter;
} sha1_ctx_t;

/** Function declarations */
void sha1_append_bit(sha1_ctx_t *ctx, bit_t bit);

void sha1_append_char(sha1_ctx_t *ctx, unsigned char value);

void sha1_append_int(sha1_ctx_t *ctx, uint32_t value);

void sha1_append_long(sha1_ctx_t *ctx, uint64_t value);

void sha1_append_str(sha1_ctx_t *ctx, unsigned char *str, uint64_t strlen);

uint32_t rotate_left(uint32_t value, int32_t shift);

uint32_t rotate_right(uint32_t value, int32_t shift);

void sha1(sha1_ctx_t *ctx);

void sha1_ctx_init(sha1_ctx_t *ctx, uint64_t num_of_chunks);

void sha1_ctx_finalize(sha1_ctx_t *ctx);

void sha1_ctx_dispose(sha1_ctx_t *ctx);

void sha1_pad(sha1_ctx_t *ctx);

void sha1_ctx_reset_counters(sha1_ctx_t *ctx);

#endif /* SHA1_H */
