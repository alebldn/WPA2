#include "hmac.h"

/**                                 hmac_append_bit_key:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a single bit to
 * key chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: bit_t type containing the value that needs to be appended in text chunks.
 */
void hmac_append_bit_key(hmac_ctx_t *ctx, bit_t value) {
    sha1_append_bit(&ctx->sha1_ctx_key, value);
}


/**                                 hmac_append_bit_text:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a single bit to
 * text chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: bit_t type containing the value that needs to be appended in text chunks.
 */
void hmac_append_bit_text(hmac_ctx_t *ctx, bit_t value) {
    sha1_append_bit(&ctx->sha1_ctx_text, value);
}


/**                                 hmac_append_char_key:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a single char (byte)
 * to key chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: byte type containing the value that needs to be appended in key chunks.
 */
void hmac_append_char_key(hmac_ctx_t *ctx, unsigned char value) {
    sha1_append_char(&ctx->sha1_ctx_key, value);
}


/**                                 hmac_append_char_text:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a single char (byte)
 * to text chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: byte type containing the value that needs to be appended in text chunks.
 */
void hmac_append_char_text(hmac_ctx_t *ctx, unsigned char value) {
    sha1_append_char(&ctx->sha1_ctx_text, value);
}


/**                                 hmac_append_str_key:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a full string
 * to key chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: string that needs to be appended in key chunks.
 * @param strlen: length of the string passed as previous argument.
 */
void hmac_append_str_key(hmac_ctx_t *ctx, unsigned char *value, uint64_t strlen) {
    sha1_append_str(&ctx->sha1_ctx_key, value, strlen);
}


/**                                 hmac_append_str_text:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a full string
 * to text chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: string that needs to be appended in text chunks.
 * @param strlen: length of the string passed as previous argument.
 */
void hmac_append_str_text(hmac_ctx_t *ctx, unsigned char *value, uint64_t strlen) {
    sha1_append_str(&ctx->sha1_ctx_text, value, strlen);
}


/**                                 hmac_append_int_key:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a 32 bit usigned
 * integer to key chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: 32 bit integer value that needs to be appended in key chunks.
 */
void hmac_append_int_key(hmac_ctx_t *ctx, uint32_t value) {
    sha1_append_int(&ctx->sha1_ctx_key, value);
}


/**                                 hmac_append_int_text:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a 32 bit usigned
 * integer to text chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: 32 bit integer value that needs to be appended in text chunks.
 */
void hmac_append_int_text(hmac_ctx_t *ctx, uint32_t value) {
    sha1_append_int(&ctx->sha1_ctx_text, value);
}


/**                                 hmac_append_int_key:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a 64 bit usigned
 * integer to key chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: 64 bit integer value that needs to be appended in key chunks.
 */
void hmac_append_long_key(hmac_ctx_t *ctx, uint64_t value) {
    sha1_append_long(&ctx->sha1_ctx_key, value);
}


/**                                 hmac_append_int_text:
 * Wrapper utility function that calls the underlying sha1_append_bit in order to append a 64 bit usigned
 * integer to text chunks.
 *
 * @param ctx:  structure containing chunks and counters of both Text and Key variables needed to perform
 *              HMAC.
 * @param value: 64 bit integer value that needs to be appended in text chunks.
 */
void hmac_append_long_text(hmac_ctx_t *ctx, uint64_t value) {
    sha1_append_long(&ctx->sha1_ctx_text, value);
}
/**                                 hmac_pad:
 * Utility function that pads with zeroes the given sha1_ctx_t context's chunk. It does not wrap
 * sha1_pad for they have different behaviours.
 *
 * @param ctx: sha1_ctx_t struct whose chunks need to be padded according to the HMAC algorithm.
 */
void hmac_pad(sha1_ctx_t *ctx) {
    uint64_t cap = BITS_IN_CHUNK - (ctx->word_counter * SHA1_BIT_COUNTER_INIT + (32 - ctx->counter));

    for (uint32_t i = 0; i < cap; i++) {
        sha1_append_bit(ctx, 0);
    }
}

/**                                 hmac_ctx_key_init:
 * Utility function that initializes sha1_ctx_key with the correct amount of chunks based on how
 * many bits we need to write in it.
 *
 * @param ctx:  hmac_ctx_t struct that wraps the sha1_ctx_key struct passed to the wrapped function
 *              sha1_ctx_init.
 * @param bits_to_be_written_in_key: number of bits that have to be written in key chunks (meaning
 *                                   the number of bits that you need to encode the key parameter).
 */
void hmac_ctx_key_init(hmac_ctx_t *ctx, uint64_t bits_to_be_written_in_key) {
    sha1_ctx_init(&ctx->sha1_ctx_key, (bits_to_be_written_in_key + 1 + 64) / BITS_IN_CHUNK + 1);
}


/**                                 hmac_ctx_text_init:
 * Utility function that initializes sha1_ctx_text with the correct amount of chunks based on how
 * many bits we need to write in it.
 *
 * @param ctx:  hmac_ctx_t struct that wraps the sha1_ctx_text struct passed to the wrapped function
 *              sha1_ctx_init.
 * @param bits_to_be_written_in_text: number of bits that have to be written in text chunks (meaning
 *                                   the number of bits that you need to encode the text parameter).
 */
void hmac_ctx_text_init(hmac_ctx_t *ctx, uint64_t bits_to_be_written_in_text) {
    sha1_ctx_init(&ctx->sha1_ctx_text, (bits_to_be_written_in_text + 1 + 64) / BITS_IN_CHUNK + 1 + 1);
    ctx->sha1_ctx_text.chunk_counter += 1;
}

/**                                 hmac_ctx_reset_pad_words:
 * Utility function that (re-)initializes all of the inner_pad and outer_pad words to 0.
 *
 * @param ctx: hmac context struct that wraps inner_pad and outer_pad.
 */
void hmac_ctx_reset_pad_words(hmac_ctx_t *ctx) {
    ctx->inner_pad.words[0] = 0;
    ctx->inner_pad.words[1] = 0;
    ctx->inner_pad.words[2] = 0;
    ctx->inner_pad.words[3] = 0;
    ctx->inner_pad.words[4] = 0;
    ctx->inner_pad.words[5] = 0;
    ctx->inner_pad.words[6] = 0;
    ctx->inner_pad.words[7] = 0;
    ctx->inner_pad.words[8] = 0;
    ctx->inner_pad.words[9] = 0;
    ctx->inner_pad.words[10] = 0;
    ctx->inner_pad.words[11] = 0;
    ctx->inner_pad.words[12] = 0;
    ctx->inner_pad.words[13] = 0;
    ctx->inner_pad.words[14] = 0;
    ctx->inner_pad.words[15] = 0;

    ctx->outer_pad.words[0] = 0;
    ctx->outer_pad.words[1] = 0;
    ctx->outer_pad.words[2] = 0;
    ctx->outer_pad.words[3] = 0;
    ctx->outer_pad.words[4] = 0;
    ctx->outer_pad.words[5] = 0;
    ctx->outer_pad.words[6] = 0;
    ctx->outer_pad.words[7] = 0;
    ctx->outer_pad.words[8] = 0;
    ctx->outer_pad.words[9] = 0;
    ctx->outer_pad.words[10] = 0;
    ctx->outer_pad.words[11] = 0;
    ctx->outer_pad.words[12] = 0;
    ctx->outer_pad.words[13] = 0;
    ctx->outer_pad.words[14] = 0;
    ctx->outer_pad.words[15] = 0;
}

/**                             hmac_ctx_init:
 * Wrapper function that correctly initializes the whole hmac context's key and text chunks.
 *
 * @param ctx: hmac context wrapping the sha1 contexts that need to be initialized.
 * @param bits_to_be_written_in_key: number of bits that have to be written in key chunks (meaning
 *                                   the number of bits that you need to encode the key parameter).
 * @param bits_to_be_written_in_text: number of bits that have to be written in text chunks (meaning
 *                                    the number of bits that you need to encode the text parameter).
 */
void hmac_ctx_init(hmac_ctx_t *ctx, uint64_t bits_to_be_written_in_key, uint64_t bits_to_be_written_in_text) {
    hmac_ctx_key_init(ctx, bits_to_be_written_in_key);
    hmac_ctx_text_init(ctx, bits_to_be_written_in_text);
    hmac_ctx_reset_pad_words(ctx);
}


/**                                 hmac_ctx_key_dispose:
 * Wrapper utility function that calls sha1_ctx_dispose in order to dispose key context's chunks.
 *
 * @param ctx: hmac context that holds sha1_ctx_t structure that holds, itself, the chunks that need to be
 *             disposed
 */
void hmac_ctx_key_dispose(hmac_ctx_t *ctx) {
    sha1_ctx_dispose(&ctx->sha1_ctx_key);
}


/**                                 hmac_ctx_text_dispose:
 * Wrapper utility function that calls sha1_ctx_dispose in order to dispose text context's chunks.
 *
 * @param ctx: hmac context that holds sha1_ctx_t structure that holds, itself, the chunks that need to be
 *             disposed
 */
void hmac_ctx_text_dispose(hmac_ctx_t *ctx) {
    sha1_ctx_dispose(&ctx->sha1_ctx_text);
}


/**                                 hmac_ctx_dispose:
 * Wrapping function that disposes both key and text chunks.
 *
 * @param ctx:  hmac context that holds both sha1_ctx_t structures, the key one and the text one, that hold,
 *              themselves, the chunks that need to be disposed.
 */
void hmac_ctx_dispose(hmac_ctx_t *ctx) {
    hmac_ctx_text_dispose(ctx);
    hmac_ctx_key_dispose(ctx);
}


/**                                 hmac:
 * Main function that, once the function is finalized, executes the HMAC algorithm in order to produce the
 * Message Authentication Code. Comments inside the function define each step the algorithm needs to go through.
 *
 * @param ctx: hmac_ctx_t structure that holds every variable needed for the execution as seen in hmac.h
 */
void hmac(hmac_ctx_t *ctx) {
    uint8_t temp_counter, temp_word_counter;
    uint64_t temp_chunk_counter;
    uint64_t bits_written_in_key, bits_written_in_text;

    bits_written_in_key = ctx->sha1_ctx_key.chunk_counter * BITS_IN_CHUNK
                          + ctx->sha1_ctx_key.word_counter * BITS_IN_WORD
                          + 32 - ctx->sha1_ctx_key.counter;

    bits_written_in_text = ctx->sha1_ctx_text.chunk_counter * BITS_IN_CHUNK
                           + ctx->sha1_ctx_text.word_counter * BITS_IN_WORD
                           + 32 - ctx->sha1_ctx_text.counter;

    /*
     * Step 1       If the length of K = B: set K0 = K. Go to step 4.
     * Step 2       If the length of K > B: hash K to obtain an L byte string, then append (B-L)
     *              zeros to create a B-byte string K0 (i.e., K0 = H(K) || 00...00). Go to step 4.
     */

    if (bits_written_in_key > BITS_IN_CHUNK) {
        sha1(&ctx->sha1_ctx_key);

        sha1_ctx_dispose(&ctx->sha1_ctx_key);
        sha1_ctx_init(&ctx->sha1_ctx_key, 1);

        sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[0]);
        sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[1]);
        sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[2]);
        sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[3]);
        sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[4]);
    }

    /*
     * Step 3       If the length of K < B: append zeros to the end of K to create a B-byte string K0
     *              (e.g., if K is 20 bytes in length and B = 64, then K will be appended with 44
     *              zero bytes x’00’).
     */

    hmac_pad(&ctx->sha1_ctx_key);

    /*
     * Step 4       Exclusive-Or K0 with ipad to produce a B-byte string: K0 xor ipad.
     * Step 7       Exclusive-Or K0 with opad: K0 xor opad.
     */

    ctx->inner_pad.words[0] = ctx->sha1_ctx_key.chunks[0].words[0] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[1] = ctx->sha1_ctx_key.chunks[0].words[1] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[2] = ctx->sha1_ctx_key.chunks[0].words[2] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[3] = ctx->sha1_ctx_key.chunks[0].words[3] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[4] = ctx->sha1_ctx_key.chunks[0].words[4] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[5] = ctx->sha1_ctx_key.chunks[0].words[5] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[6] = ctx->sha1_ctx_key.chunks[0].words[6] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[7] = ctx->sha1_ctx_key.chunks[0].words[7] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[8] = ctx->sha1_ctx_key.chunks[0].words[8] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[9] = ctx->sha1_ctx_key.chunks[0].words[9] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[10] = ctx->sha1_ctx_key.chunks[0].words[10] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[11] = ctx->sha1_ctx_key.chunks[0].words[11] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[12] = ctx->sha1_ctx_key.chunks[0].words[12] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[13] = ctx->sha1_ctx_key.chunks[0].words[13] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[14] = ctx->sha1_ctx_key.chunks[0].words[14] ^ INNER_PAD_XOR_CONST;
    ctx->inner_pad.words[15] = ctx->sha1_ctx_key.chunks[0].words[15] ^ INNER_PAD_XOR_CONST;

    ctx->outer_pad.words[0] = ctx->sha1_ctx_key.chunks[0].words[0] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[1] = ctx->sha1_ctx_key.chunks[0].words[1] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[2] = ctx->sha1_ctx_key.chunks[0].words[2] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[3] = ctx->sha1_ctx_key.chunks[0].words[3] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[4] = ctx->sha1_ctx_key.chunks[0].words[4] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[5] = ctx->sha1_ctx_key.chunks[0].words[5] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[6] = ctx->sha1_ctx_key.chunks[0].words[6] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[7] = ctx->sha1_ctx_key.chunks[0].words[7] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[8] = ctx->sha1_ctx_key.chunks[0].words[8] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[9] = ctx->sha1_ctx_key.chunks[0].words[9] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[10] = ctx->sha1_ctx_key.chunks[0].words[10] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[11] = ctx->sha1_ctx_key.chunks[0].words[11] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[12] = ctx->sha1_ctx_key.chunks[0].words[12] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[13] = ctx->sha1_ctx_key.chunks[0].words[13] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[14] = ctx->sha1_ctx_key.chunks[0].words[14] ^ OUTER_PAD_XOR_CONST;
    ctx->outer_pad.words[15] = ctx->sha1_ctx_key.chunks[0].words[15] ^ OUTER_PAD_XOR_CONST;

    /*
     * Step 5       Append the stream of data 'text' to the string resulting from step 4:
     *              (K0 xor ipad) || text.
     */

    temp_counter = ctx->sha1_ctx_text.counter;
    temp_word_counter = ctx->sha1_ctx_text.word_counter;
    temp_chunk_counter = ctx->sha1_ctx_text.chunk_counter;

    sha1_ctx_reset_counters(&ctx->sha1_ctx_text);

    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[0]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[1]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[2]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[3]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[4]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[5]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[6]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[7]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[8]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[9]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[10]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[11]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[12]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[13]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[14]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[15]);

    ctx->sha1_ctx_text.num_of_chunks = bits_written_in_text / BITS_IN_CHUNK + 1;
    ctx->sha1_ctx_text.counter = temp_counter;
    ctx->sha1_ctx_text.word_counter = temp_word_counter;
    ctx->sha1_ctx_text.chunk_counter = temp_chunk_counter;

    sha1_ctx_finalize(&ctx->sha1_ctx_text);

    /*
     * Step 6       Apply H to the stream generated in step 5: H((K0 xor ipad) || text).
     */

    sha1(&ctx->sha1_ctx_text);

    ctx->digest[0] = ctx->sha1_ctx_text.digest[0];
    ctx->digest[1] = ctx->sha1_ctx_text.digest[1];
    ctx->digest[2] = ctx->sha1_ctx_text.digest[2];
    ctx->digest[3] = ctx->sha1_ctx_text.digest[3];
    ctx->digest[4] = ctx->sha1_ctx_text.digest[4];

    sha1_ctx_dispose(&ctx->sha1_ctx_text);
    sha1_ctx_init(&ctx->sha1_ctx_text, 2);

    /*
     * Step 8       Append the result from step 6 to step 7:
     *              (K0 xor opad) || H((K0 xor ipad) || text).
     */

    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[0]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[1]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[2]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[3]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[4]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[5]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[6]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[7]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[8]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[9]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[10]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[11]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[12]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[13]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[14]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[15]);

    sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[0]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[1]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[2]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[3]);
    sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[4]);

    sha1_ctx_finalize(&ctx->sha1_ctx_text);

    /*
     * Step 9       Apply H to the result from step 8:
     *              H((K0 xor opad )|| H((K0 xor ipad) || text))
     */

    sha1(&ctx->sha1_ctx_text);

    ctx->digest[0] = ctx->sha1_ctx_text.digest[0];
    ctx->digest[1] = ctx->sha1_ctx_text.digest[1];
    ctx->digest[2] = ctx->sha1_ctx_text.digest[2];
    ctx->digest[3] = ctx->sha1_ctx_text.digest[3];
    ctx->digest[4] = ctx->sha1_ctx_text.digest[4];
}
