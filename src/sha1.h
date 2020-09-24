#ifndef SHA1_H
#define SHA1_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#define SHA1_BIT_COUNTER_INIT 	    32
#define SHA1_WORD_COUNTER_INIT	    0
#define SHA1_CHUNK_COUNTER_INIT 	0

#define BITS_IN_CHUNK		        512
#define BITS_IN_WORD		        32
#define BITS_IN_HASH                160
#define WORDS_IN_CHUNK 		        16
#define WORDS_IN_HASH			    5

typedef enum
{
    false,
    true
} bit_t;

typedef struct
{
    uint32_t words[WORDS_IN_CHUNK];
} chunk_t;

typedef struct
{
    chunk_t* 	chunks;
    uint32_t 	digest[WORDS_IN_HASH];
    uint64_t 	num_of_chunks;
    uint64_t 	chunk_counter;
    uint8_t 	word_counter;
    uint8_t 	counter;
} sha1_ctx_t;

void sha1_append_bit(sha1_ctx_t* ctx, bit_t bit);
void sha1_append_char(sha1_ctx_t* ctx, unsigned char value);
void sha1_append_int(sha1_ctx_t* ctx, uint32_t value);
void sha1_append_long(sha1_ctx_t* ctx, uint64_t value);
void sha1_append_str(sha1_ctx_t* ctx, unsigned char* str, uint64_t strlen);
uint32_t rotate_left(uint32_t value, int32_t shift);
uint32_t rotate_right(uint32_t value, int32_t shift);

void sha1(sha1_ctx_t* ctx);
void sha1_ctx_init(sha1_ctx_t* ctx, uint64_t num_of_chunks);
void sha1_ctx_finalize(sha1_ctx_t* ctx);
void sha1_ctx_dispose(sha1_ctx_t* ctx);
void sha1_pad(sha1_ctx_t* ctx);
void sha1_ctx_reset_counters(sha1_ctx_t* ctx);

#endif /* SHA1_H */
