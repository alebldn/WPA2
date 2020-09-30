#include "sha1.h"

/** Constant words defined as dictated in SHA1 algorithm */
const uint32_t _h0 = 0x67452301;
const uint32_t _h1 = 0xEFCDAB89;
const uint32_t _h2 = 0x98BADCFE;
const uint32_t _h3 = 0x10325476;
const uint32_t _h4 = 0xC3D2E1F0;


/**                                 sha1_append_bit
 * Utility function needed to correctly insert a single bit in the current word of the
 * current chunk. The MSB (Most Significant Bit) has to be evaluated first since the
 * background architecture has to be Big Endian.
 *
 * @param ctx: struct type that holds both chunks and counters needed in order to
 *             correctly append the bit.
 * @param bit: bit that has to be appended in the current word of the current chunk.
 */
void sha1_append_bit(sha1_ctx_t *ctx, bit_t bit) {
    ctx->counter--;
    ctx->chunks[ctx->chunk_counter].words[ctx->word_counter] += (bit << ctx->counter);

    if (ctx->counter == 0) {
        ctx->counter = SHA1_BIT_COUNTER_INIT;
        ctx->word_counter += 1;

        if (ctx->word_counter == WORDS_IN_CHUNK) {
            ctx->word_counter = SHA1_WORD_COUNTER_INIT;
            ctx->chunk_counter += 1;
        }
    }
}


/**                                 sha1_append_char:
 * Utility function that uses sha1_append_bit in order to properly store a whole byte (char)
 * inside the current word(s) of the current chunk(s).
 *
 * @param ctx: struct type that holds both chunks and counters needed in order to
  *            correctly append the byte.
 * @param value: char byte that has to be appended in the current word of the current chunk
 */
void sha1_append_char(sha1_ctx_t *ctx, unsigned char value) {
    for (int8_t i = 7; i >= 0; i--) {
        sha1_append_bit(ctx, (value >> i) & 1);
    }
}


/**                                 sha1_append_str:
 * Utility function that uses sha1_append_char in order to store a full string of length strlen
 * within the current word(s) of the current chunk(s).
 *
 * @param ctx: struct type that holds both chunks and counters needed in order to
 *             correctly append the string in the current word(s) of the current chunk(s)
 * @param str: string that has to be appended inside the chunk(s)
 * @param strlen: length of the string passed as previous argument.
 */
void sha1_append_str(sha1_ctx_t *ctx, unsigned char *str, uint64_t strlen) {
    for (uint64_t i = 0; i < strlen; i++) {
        sha1_append_char(ctx, str[i]);
    }
}


/**                                 sha1_append_int:
 * Utility function that uses sha1_append_bit in order to store a 32 bit unsigned integer within the
 * current word(s) of the current chunk(s)
 *
 * @param ctx: struct type that holds both chunks and counters needed in order to
 *             correctly append the unsigned integer in the current word(s) of the current chunk(s)
 * @param value: 32 bit unsigned integer that has to be appended in the chunks.
 */
void sha1_append_int(sha1_ctx_t *ctx, uint32_t value) {
    for (int8_t i = 31; i >= 0; i--) {
        sha1_append_bit(ctx, (value >> i) & 1);
    }
}


/**                                 sha1_append_long:
 * Utility function that uses sha1_append_bit in order to store a 64 bit unsigned integer within the
 * current word(s) of the current chunk(s)
 *
 * @param ctx: struct type that holds both chunks and counters needed in order to
 *             correctly append the unsigned integer in the current word(s) of the current chunk(s)
 * @param value: 64 bit unsigned integer that has to be appended in the chunks.
 */
void sha1_append_long(sha1_ctx_t *ctx, uint64_t value) {
    for (int8_t i = 63; i >= 0; i--) {
        sha1_append_bit(ctx, (value >> i) & 1);
    }
}


/**                                 rotate_left:
 * Utility function that shifts to the left all the bits inside a uint32_t word and inserts the overflowed ones to the
 * right side of the word. Example with an 8 bit word:
 *          rotate_left(|1|0|0|0|0|1|0|0|, 1) = |0|0|0|0|1|0|0|1|
 *          rotate_left(|1|0|0|0|0|1|0|0|, 2) = |0|0|0|1|0|0|1|0|
 *          rotate_left(|1|0|0|0|0|1|0|0|, 3) = |0|0|1|0|0|1|0|0|
 *
 * @param value: uint32_t word that has to be rotated.
 * @param shift: value of the rotation (max should be 31 bit)
 * @return: rotated uint32_t word.
 */
uint32_t rotate_left(const uint32_t value, int32_t shift) {
    if ((shift &= sizeof(value) * 8 - 1) == 0)
        return value;
    return (value << shift) | (value >> (sizeof(value) * 8 - shift));
}


/**                                 rotate_right:
 * Utility function that shifts to the right all the bits inside a uint32_t word and inserts the overflowed ones to the
 * left side of the word exactly as rotate_left function but differs for the direction.
 *
 * @param value: uint32_t word that has to be rotated.
 * @param shift: value of the right shift rotation (max should be 31 bit)
 * @return: rotated uint32_t word.
 */
uint32_t rotate_right(const uint32_t value, int32_t shift) {
    if ((shift &= sizeof(value) * 8 - 1) == 0)
        return value;
    return (value >> shift) | (value << (sizeof(value) * 8 - shift));
}


/**                                 sha1_pad:
 * Utility function that pads the remaining unwritten words of the last chunk with the correct amount of zeroes
 * as specified in the sha1 algorithm.
 *
 * @param ctx: struct type that holds both chunks and counters needed in order to
 *             correctly find the correct amount of zeroes that need to be appended in order to pad the last chunk
 */
void sha1_pad(sha1_ctx_t *ctx) {
    uint64_t cap = BITS_IN_CHUNK*(ctx->num_of_chunks - ctx->chunk_counter) -
                   ctx->word_counter * BITS_IN_WORD - BITS_IN_WORD + ctx->counter - 64;

    for (uint64_t i = 0; i < cap; i++) {
        sha1_append_bit(ctx, 0);
    }
}


/**                                 sha1_ctx_reset_counters:
 * Utility function that resets all (bit counter, word counter and chunk counter)  sha1 counter within the context passed as pointer.
 *
 * @param ctx: struct type that holds all counter variables that need to be set to initial values.
 */
void sha1_ctx_reset_counters(sha1_ctx_t *ctx) {
    ctx->word_counter = SHA1_WORD_COUNTER_INIT;
    ctx->chunk_counter = SHA1_CHUNK_COUNTER_INIT;
    ctx->counter = SHA1_BIT_COUNTER_INIT;
}


/**                                 sha1_ctx_init:
 * Utility function that initializes the sha1_ctx passed as argument with the correct amount of chunks.
 * This function sets to 0 all words in chunks and digest and calls sha1_ctx_reset_counters in order to correctly
 * initialize all (bit, word and chunk) counters
 *
 * @param ctx: struct type that holds both chunk pointer and counters needed to correctly initialize the sha1_ctx struct
 * @param num_of_chunks: number of chunks needed in order to store all the information on which the sha1 algorithm has to
 *                       be applied
 */
void sha1_ctx_init(sha1_ctx_t *ctx, uint64_t num_of_chunks) {
    uint32_t i, j;

    ctx->num_of_chunks = num_of_chunks;
    ctx->chunks = (chunk_t *) malloc(ctx->num_of_chunks * sizeof(chunk_t));

    for (i = 0; i < ctx->num_of_chunks; i++)
        for (j = 0; j < WORDS_IN_CHUNK; j++)
            ctx->chunks[i].words[j] = 0;

    for (i = 0; i < WORDS_IN_HASH; i++)
        ctx->digest[i] = 0;

    sha1_ctx_reset_counters(ctx);
}


/**                                 sha1_ctx_finalize:
 * Utility function that has to be called after all data that needs to be hashed has been written to the sha1_ctx structure
 * chunks and before the very execution of the function sha1.
 * As defined by the SHA1 algorithm, it appends the final bit (1) to the last written chunk, pads with zeroes the
 * remaining words and appends a 64 bit integer representing the length in bit of the data previously written.
 *
 * @param ctx: structure that holds every parameter needed in order to finalize the data and finally execute the sha1 algorithm
 */
void sha1_ctx_finalize(sha1_ctx_t *ctx) {
    uint32_t len = ctx->chunk_counter * BITS_IN_CHUNK + ctx->word_counter * BITS_IN_WORD +
                   (SHA1_BIT_COUNTER_INIT - ctx->counter);

    sha1_append_bit(ctx, 1);
    sha1_pad(ctx);
    sha1_append_long(ctx, len);
}


/**                                 sha1_ctx_dispose:
 * Utility function that disposes the dynamically allocated chunk array via the free() function.
 *
 * @param ctx: structure that holds the chunk array that needs to be disposed.
 */
void sha1_ctx_dispose(sha1_ctx_t *ctx) {
    free(ctx->chunks);
    ctx->chunks = NULL;
}


/**                                 sha1:
 * Actual sha1 algorithm. Processes the data in the chunks and generates the sha1 hash digest.
 *
 * @param ctx: finalized sha1_ctx_t structure that holds all the data needed in order to evaluate the hash.
 */
void sha1(sha1_ctx_t *ctx) {
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    uint32_t h0, h1, h2, h3, h4;
    uint32_t f, k, temp;
    int32_t word_index, chunk_index;

    /**
     * Pre-processing: append the bit '1' to the message.
     * append 0 <= k < 512 bits '0', such that the resulting message length in bits is congruent to 448 (mod 512).
     * append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512.
     *
     * for each chunk
     * break chunk into sixteen 32-bit big-endian words w[i], 0 <= i <= 15
     *
     * Process the message in successive 512-bit chunks:
     * break message into 512-bit chunks
     */

    h0 = _h0;
    h1 = _h1;
    h2 = _h2;
    h3 = _h3;
    h4 = _h4;

    for (chunk_index = 0; chunk_index < ctx->num_of_chunks; chunk_index++) {
        for (word_index = 0; word_index < WORDS_IN_CHUNK; word_index++)
            w[word_index] = ctx->chunks[chunk_index].words[word_index];

        for (; word_index < 80; word_index++)
            w[word_index] = rotate_left(w[word_index - 3] ^ w[word_index - 8] ^ w[word_index - 14] ^ w[word_index - 16],
                                        1);

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;

        /*
         * Main loop:
         * for i from 0 to 79
         *   if 0 <= i <= 19 then
         *      f = (b and c) xor ((not b) and d)
         *      k = 0x5A827999
         *  else if 20 <= i <= 39
         *      f = b xor c xor d
         *      k = 0x6ED9EBA1
         *  else if 40 <= i <= 59
         *      f = (b and c) xor (b and d) xor (c and d)
         *      k = 0x8F1BBCDC
         *  else if 60 <= i <= 79
         *      f = b xor c xor d
         *      k = 0xCA62C1D6
         */

        for (word_index = 0; word_index < 80; word_index++) {
            if (word_index < 20) {
                f = ((b & c) ^ ((~b) & d));
                k = 0x5A827999;
            } else if (word_index >= 20 && word_index < 40) {
                f = (b ^ c ^ d);
                k = 0x6ED9EBA1;
            } else if (word_index >= 40 && word_index < 60) {
                f = ((b & c) ^ (b & d) ^ (c & d));
                k = 0x8F1BBCDC;
            } else if (word_index >= 60 && word_index < 80) {
                f = (b ^ c ^ d);
                k = 0xCA62C1D6;
            }

            /*
             * temp = (a leftrotate 5) + f + e + k + w[i]
                *  e = d
                *  d = c
                *  c = b leftrotate 30
                *  b = a
                *  a = temp
                */

            temp = rotate_left(a, 5) + e + k + f + w[word_index];

            e = d;
            d = c;
            c = rotate_left(b, 30);
            b = a;
            a = temp;
        }

        /**
         * Add this chunk's hash to result so far:
         * h0 = h0 + a
         * h1 = h1 + b
         * h2 = h2 + c
         * h3 = h3 + d
         * h4 = h4 + e
         */

        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
    }

    ctx->digest[0] = h0;
    ctx->digest[1] = h1;
    ctx->digest[2] = h2;
    ctx->digest[3] = h3;
    ctx->digest[4] = h4;
}
