#include "pbkdf2_specific_sha1.h"


/**                         sha1_append_bit(pbkdf2_specific_sha1_ctx_t*, bit_t);
 *
 *  Requires:               - sha1_ctx_init(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Allows:                 []
 *
 *  Description:            Utility function needed to correctly insert a single bit in the current word of the current
 *                          chunk. The MSB (Most Significant Bit) has to be evaluated first since the background
 *                          architecture has to be Big Endian.
 *
 *  @param ctx:             struct type that holds both chunks and counters needed in order to correctly append the bit.
 *  @param bit:             bit that has to be appended in the current word of the current chunk.
 */
void ps_sha1_append_bit(pbkdf2_specific_sha1_ctx_t *ctx, bit_t bit) {
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


/**                         sha1_append_char(pbkdf2_specific_sha1_ctx_t*, unsigned_char value);
 *
 *  Requires:               - sha1_ctx_init(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Allows:                 []
 *
 *  Description:            Utility function that uses sha1_append_bit in order to properly store a whole byte (char)
 *                          inside the current word(s) of the current chunk(s).
 *
 *  @param ctx:             struct type that holds both chunks and counters needed in order to correctly append the byte.
 *  @param value:           char byte that has to be appended in the current word of the current chunk
 */
void ps_sha1_append_char(pbkdf2_specific_sha1_ctx_t *ctx, unsigned char value) {
    for (int8_t i = 7; i >= 0; i--) {
        ps_sha1_append_bit(ctx, (value >> i) & 1);
    }
}


/**                         sha1_append_str(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Requires:               - sha1_ctx_init(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Allows                  []
 *
 *  Description:            Utility function that uses sha1_append_char in order to store a full string of length strlen
 *                          within the current word(s) of the current chunk(s).
 *
 *  @param ctx:             struct type that holds both chunks and counters needed in order to
 *                          correctly append the string in the current word(s) of the current chunk(s)
 *  @param str:             string that has to be appended inside the chunk(s)
 *  @param strlen:          length of the string passed as previous argument.
 */
void ps_sha1_append_str(pbkdf2_specific_sha1_ctx_t *ctx, unsigned char *str, uint16_t strlen) {
    for (uint8_t i = 0; i < strlen; i++) {
        ps_sha1_append_char(ctx, str[i]);
    }
}


/**                         sha1_append_int(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Requires:               - sha1_ctx_init(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Allows:                 []
 *
 *  Description:            Utility function that uses sha1_append_bit in order to store a 32 bit unsigned integer within
 *                          the current word(s) of the current chunk(s).
 *
 *  @param ctx:             struct type that holds both chunks and counters needed in order to correctly append the
 *                          unsigned integer in the current word(s) of the current chunk(s).
 *  @param value:           32 bit unsigned integer that has to be appended in the chunks.
 */
void ps_sha1_append_int(pbkdf2_specific_sha1_ctx_t *ctx, uint32_t value) {
    for (int8_t i = 31; i >= 0; i--) {
        ps_sha1_append_bit(ctx, (value >> i) & 1);
    }
}


/**                         sha1_append_long(pbkdf2_specific_sha1_ctx_t*, uint64_t);
 *
 *  Requires:               - sha1_ctx_init(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Allows:                 []
 *
 *  Description:            Utility function that uses sha1_append_bit in order to store a 64 bit unsigned integer within
 *                          the current word(s) of the current chunk(s).
 *
 *  @param ctx:             struct type that holds both chunks and counters needed in order to correctly append the
 *                          unsigned integer in the current word(s) of the current chunk(s).
 *  @param value:           64 bit unsigned integer that has to be appended in the chunks.
 */
void ps_sha1_append_long(pbkdf2_specific_sha1_ctx_t *ctx, uint64_t value) {
    for (int8_t i = 63; i >= 0; i--) {
        ps_sha1_append_bit(ctx, (value >> i) & 1);
    }
}


/**                         rotate_left(uint32_t, uint32_t);
 *
 *  Requires:               []
 *  Allows:                 []
 *
 *  Description:            Utility function that shifts to the left all the bits inside a uint32_t word and inserts the
 *                          overflowed ones to the right side of the word. Example with an 8 bit word:
 *
 *                              rotate_left(|1|0|0|0|0|1|0|0|, 1) = |0|0|0|0|1|0|0|1|
 *                              rotate_left(|1|0|0|0|0|1|0|0|, 2) = |0|0|0|1|0|0|1|0|
 *                              rotate_left(|1|0|0|0|0|1|0|0|, 3) = |0|0|1|0|0|1|0|0|
 *
 *  @param value:           uint32_t word that has to be rotated.
 *  @param shift:           value of the rotation (max should be 31 bit).
 *  @return:                rotated uint32_t word.
 */
 /** TODO: Delete if check */
uint32_t ps_rotate_left(const uint32_t value, uint32_t shift) {
    return (value << shift) | (value >> (32 - shift));
}


/**                         rotate_right(uint32_t, uint32_t);
 *
 *  Requires:               []
 *
 *  Allows:                 []
 *
 *  Description:            Utility function that shifts to the right all the bits inside a uint32_t word and inserts the
 *                          overflowed ones to the left side of the word exactly as rotate_left function but differs for
 *                          the direction.
 *
 *  @param value:           uint32_t word that has to be rotated.
 *  @param shift:           value of the right shift rotation (max should be 31 bit)
 *  @return:                rotated uint32_t word.
 */
uint32_t ps_rotate_right(const uint32_t value, uint32_t shift) {
    return (value >> shift) | (value << (32 - shift));
}


/**                         [Private] sha1_pad(pbkdf2_specific_sha1_ctx_t*);
 *
 *  Requires:               - sha1_ctx_init(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Allows:                 []
 *
 *  Description:            Utility function that pads the remaining unwritten words of the last chunk with the correct
 *                          amount of zeroes as specified in the sha1 algorithm.
 *
 *  @param ctx:             struct type that holds both chunks and counters needed in order to correctly find the correct
 *                          amount of zeroes that need to be appended in order to pad the last chunk
 */
void ps_sha1_pad(pbkdf2_specific_sha1_ctx_t *ctx) {
    uint16_t cap = BITS_IN_CHUNK * (ctx->num_of_chunks - ctx->chunk_counter) -
                   ctx->word_counter * BITS_IN_WORD - BITS_IN_WORD + ctx->counter - 64;

    for (uint16_t i = 0; i < cap; i++) {
        ps_sha1_append_bit(ctx, 0);
    }
}


/**                         sha1_ctx_reset_counters(pbkdf2_specific_sha1_ctx_t*);
 *
 *  Requires:               []
 *
 *  Allows:                 []
 *
 *  Description:            Utility function that resets all (bit counter, word counter and chunk counter)  sha1 counter
 *                          within the context passed as pointer.
 *
 *  @param ctx:             struct type that holds all counter variables that need to be set to initial values.
 */
void ps_sha1_ctx_reset_counters(pbkdf2_specific_sha1_ctx_t *ctx) {
    ctx->word_counter = SHA1_WORD_COUNTER_INIT;
    ctx->chunk_counter = SHA1_CHUNK_COUNTER_INIT;
    ctx->counter = SHA1_BIT_COUNTER_INIT;
}


/**                         sha1_ctx_init(pbkdf2_specific_sha1_ctx_t*, uint32_t);
 *
 *  Requires:               []
 *
 *  Allows:                 [All append functions.]
 *                          - sha1_finalize(pbkdf2_specific_sha1_ctx_t*);
 *
 *  Description:            Utility function that initializes the sha1_ctx passed as argument with the correct amount
 *                          of chunks. This function sets to 0 all words in chunks and digest and calls.
 *                          sha1_ctx_reset_counters in order to correctly initialize all (bit, word and chunk) counters.
 *
 *  @param ctx:             struct type that holds both chunk pointer and counters needed to correctly initialize the
 *                          sha1_ctx struct.
 *  @param num_of_chunks:   number of chunks needed in order to store all the information on which the sha1 algorithm
 *                          has to be applied.
 */
void ps_sha1_ctx_init(pbkdf2_specific_sha1_ctx_t *ctx, uint8_t num_of_chunks) {

    ctx->num_of_chunks = num_of_chunks;

    ctx->chunks[0].words[0] = 0;
    ctx->chunks[0].words[1] = 0;
    ctx->chunks[0].words[2] = 0;
    ctx->chunks[0].words[3] = 0;
    ctx->chunks[0].words[4] = 0;
    ctx->chunks[0].words[5] = 0;
    ctx->chunks[0].words[6] = 0;
    ctx->chunks[0].words[7] = 0;
    ctx->chunks[0].words[8] = 0;
    ctx->chunks[0].words[9] = 0;
    ctx->chunks[0].words[10] = 0;
    ctx->chunks[0].words[11] = 0;
    ctx->chunks[0].words[12] = 0;
    ctx->chunks[0].words[13] = 0;
    ctx->chunks[0].words[14] = 0;
    ctx->chunks[0].words[15] = 0;

    if(ctx->num_of_chunks == 2)
    {
        ctx->chunks[1].words[0] = 0;
        ctx->chunks[1].words[1] = 0;
        ctx->chunks[1].words[2] = 0;
        ctx->chunks[1].words[3] = 0;
        ctx->chunks[1].words[4] = 0;
        ctx->chunks[1].words[5] = 0;
        ctx->chunks[1].words[6] = 0;
        ctx->chunks[1].words[7] = 0;
        ctx->chunks[1].words[8] = 0;
        ctx->chunks[1].words[9] = 0;
        ctx->chunks[1].words[10] = 0;
        ctx->chunks[1].words[11] = 0;
        ctx->chunks[1].words[12] = 0;
        ctx->chunks[1].words[13] = 0;
        ctx->chunks[1].words[14] = 0;
        ctx->chunks[1].words[15] = 0;

    }

    ctx->digest[0] = 0;
    ctx->digest[1] = 0;
    ctx->digest[2] = 0;
    ctx->digest[3] = 0;
    ctx->digest[4] = 0;

    ps_sha1_ctx_reset_counters(ctx);
}


/**                         sha1_ctx_finalize(pbkdf2_specific_sha1_ctx_t*);
 *
 *  Requires:               sha1_ctx_init(pbkdf2_specific_sha1_ctx_t*);
 *                          [Ended the 'appending to chunks' phase.]
 *
 *  Allows:                 sha1(pbkdf2_specific_sha1_ctx_t*);
 *
 *  Description:            Utility function that has to be called after all data that needs to be hashed has been
 *                          written to the sha1_ctx structure chunks and before the very execution of the function sha1.
 *                          As defined by the SHA1 algorithm, it appends the final bit (1) to the last written chunk,
 *                          pads with zeroes the remaining words and appends a 64 bit integer representing the length in
 *                          bit of the data previously written.
 *
 *  @param ctx:             structure that holds every parameter needed in order to finalize the data and finally execute the sha1 algorithm
 */
void ps_sha1_ctx_finalize(pbkdf2_specific_sha1_ctx_t *ctx) {
    uint16_t len = ctx->chunk_counter * BITS_IN_CHUNK + ctx->word_counter * BITS_IN_WORD +
                   (SHA1_BIT_COUNTER_INIT - ctx->counter);

    ps_sha1_append_bit(ctx, 1);
    ps_sha1_pad(ctx);
    ps_sha1_append_long(ctx, len);
}

/**                         sha1(pbkdf2_specific_sha1_ctx_t*);
 *
 *  Requires:               - sha1_ctx_finalize(pbkdf2_specific_sha1_ctx_t*);
 *
 *  Allows:                 []
 *
 *  Description:            Actual sha1 algorithm. Processes the data in the chunks and generates the sha1 hash digest.
 *
 * @param ctx:              finalized pbkdf2_specific_sha1_ctx_t structure that holds all the data needed in order to evaluate the hash.
 */
void ps_sha1(pbkdf2_specific_sha1_ctx_t *ctx) {
    uint32_t w[WORDS_IN_CHUNK];
    uint32_t a, b, c, d, e, temp;
    uint8_t word_index, chunk_index, word_index_mod_16;

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

    ctx->digest[0] = H0;
    ctx->digest[1] = H1;
    ctx->digest[2] = H2;
    ctx->digest[3] = H3;
    ctx->digest[4] = H4;

    for (chunk_index = 0; chunk_index < ctx->num_of_chunks; chunk_index++) {

        w[0] = ctx->chunks[chunk_index].words[0];
        w[1] = ctx->chunks[chunk_index].words[1];
        w[2] = ctx->chunks[chunk_index].words[2];
        w[3] = ctx->chunks[chunk_index].words[3];
        w[4] = ctx->chunks[chunk_index].words[4];
        w[5] = ctx->chunks[chunk_index].words[5];
        w[6] = ctx->chunks[chunk_index].words[6];
        w[7] = ctx->chunks[chunk_index].words[7];
        w[8] = ctx->chunks[chunk_index].words[8];
        w[9] = ctx->chunks[chunk_index].words[9];
        w[10] = ctx->chunks[chunk_index].words[10];
        w[11] = ctx->chunks[chunk_index].words[11];
        w[12] = ctx->chunks[chunk_index].words[12];
        w[13] = ctx->chunks[chunk_index].words[13];
        w[14] = ctx->chunks[chunk_index].words[14];
        w[15] = ctx->chunks[chunk_index].words[15];

        a = ctx->digest[0];
        b = ctx->digest[1];
        c = ctx->digest[2];
        d = ctx->digest[3];
        e = ctx->digest[4];

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

            word_index_mod_16 = word_index & MASK;

            if(word_index > MASK) {
                w[word_index_mod_16] = ps_rotate_left(
                        w[(word_index_mod_16 + 13) & MASK] ^ w[(word_index_mod_16 + 8) & MASK] ^
                        w[(word_index_mod_16 + 2) & MASK] ^ w[word_index_mod_16], 1);
            }

            if (word_index < 20) {
                temp = ps_rotate_left(a, 5) + e + 0x5A827999 + ((b & c) ^ ((~b) & d)) + w[word_index_mod_16];
            } else if (word_index >= 20 && word_index < 40) {
                temp = ps_rotate_left(a, 5) + e + 0x6ED9EBA1 + (b ^ c ^ d) + w[word_index_mod_16];
            } else if (word_index >= 40 && word_index < 60) {
                temp = ps_rotate_left(a, 5) + e + 0x8F1BBCDC + ((b & c) ^ (b & d) ^ (c & d)) + w[word_index_mod_16];
            } else if (word_index >= 60 && word_index < 80) {
                temp = ps_rotate_left(a, 5) + e + 0xCA62C1D6 + (b ^ c ^ d) + w[word_index_mod_16];
            }

            /*
             * temp = (a leftrotate 5) + f + e + k + w[i]
                *  e = d
                *  d = c
                *  c = b leftrotate 30
                *  b = a
                *  a = temp
                */

            e = d;
            d = c;
            c = ps_rotate_left(b, 30);
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

        ctx->digest[0] = ctx->digest[0] + a;
        ctx->digest[1] = ctx->digest[1] + b;
        ctx->digest[2] = ctx->digest[2] + c;
        ctx->digest[3] = ctx->digest[3] + d;
        ctx->digest[4] = ctx->digest[4] + e;
    }
}
