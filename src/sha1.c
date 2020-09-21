#include "sha1.h"

const uint32_t _h0 = 0x67452301;
const uint32_t _h1 = 0xEFCDAB89;
const uint32_t _h2 = 0x98BADCFE;
const uint32_t _h3 = 0x10325476;
const uint32_t _h4 = 0xC3D2E1F0;

/**
 * La funzione append_bit prende in ingresso un array di words, un counter c per contare quante word sono state usate
 * finora ed appende un bit.
 * Bit piu' significativi devono essere passati per primi in modo da essere posizionati in celle piu' alte (Big Endian).
 */
void sha1_append_bit(sha1_ctx_t* ctx, bit_t bit)
{
    ctx->counter--;
    ctx->chunks[ctx->chunk_counter].words[ctx->word_counter] += (bit << ctx->counter);

    if(ctx->counter == 0)
    {
        ctx->counter = SHA1_BIT_COUNTER_INIT;
        ctx->word_counter += 1;

        if(ctx->word_counter == WORDS_IN_CHUNK)
        {
            ctx->word_counter = SHA1_WORD_COUNTER_INIT;
            ctx->chunk_counter += 1;
        }
    }
}

void sha1_append_char(sha1_ctx_t* ctx, char value)
{
    for(int8_t i = 7; i >= 0; i--)
    {
        sha1_append_bit(ctx, (value >> i) & 1);
    }
}

void sha1_append_str(sha1_ctx_t* ctx, char* str, uint64_t strlen)
{
    for(uint64_t i = 0; i < strlen; i++)
    {
        sha1_append_char(ctx, str[i]);
    }
}

void sha1_append_int(sha1_ctx_t* ctx, uint32_t value)
{
    for(int8_t i = 31; i >= 0; i--)
    {
        sha1_append_bit(ctx, (value >> i) & 1);
    }
}

void sha1_append_long(sha1_ctx_t* ctx, uint64_t value)
{
    for(int8_t i = 63; i >= 0; i--)
    {
        sha1_append_bit(ctx, (value >> i) & 1);
    }
}

uint32_t rotate_left(const uint32_t value, int32_t shift)
{
    if ((shift &= sizeof(value)*8 - 1) == 0)
        return value;
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

uint32_t rotate_right(const uint32_t value, int32_t shift)
{
    if ((shift &= sizeof(value)*8 - 1) == 0)
        return value;
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}

void sha1_pad(sha1_ctx_t* ctx)
{
    uint64_t cap = BITS_IN_CHUNK*(ctx->num_of_chunks - ctx->chunk_counter) -
                   ctx->word_counter * SHA1_BIT_COUNTER_INIT - SHA1_BIT_COUNTER_INIT + ctx->counter - 64;

    for(uint64_t i = 0; i < cap; i++) {
        sha1_append_bit(ctx, 0);
    }
}

void sha1_ctx_reset_counters(sha1_ctx_t* ctx)
{
    ctx->word_counter 	= SHA1_WORD_COUNTER_INIT;
    ctx->chunk_counter 	= SHA1_CHUNK_COUNTER_INIT;
    ctx->counter 		= SHA1_BIT_COUNTER_INIT;
}

void sha1_ctx_init(sha1_ctx_t* ctx, uint64_t num_of_chunks)
{
    uint32_t i, j;

    ctx->num_of_chunks = num_of_chunks;
    ctx->chunks = (chunk_t*) malloc(ctx->num_of_chunks * sizeof(chunk_t));

    for(i = 0; i < ctx->num_of_chunks; i++)
        for(j = 0; j < WORDS_IN_CHUNK; j++)
            ctx->chunks[i].words[j] = 0;

    for(i = 0; i < WORDS_IN_HASH; i++)
        ctx->digest[i] = 0;

    sha1_ctx_reset_counters(ctx);
}

void sha1_ctx_finalize(sha1_ctx_t* ctx)
{
    uint32_t len = ctx->chunk_counter*BITS_IN_CHUNK+ctx->word_counter*BITS_IN_WORD + (SHA1_BIT_COUNTER_INIT - ctx->counter);

    sha1_append_bit(ctx, 1);
    sha1_pad(ctx);
    sha1_append_long(ctx, len);
}

void sha1_ctx_dispose(sha1_ctx_t* ctx)
{
    free(ctx->chunks);
    ctx->chunks = NULL;
}

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
void sha1(sha1_ctx_t* ctx)
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    uint32_t h0, h1, h2, h3, h4;
    uint32_t f, k, temp;
    int32_t word_index, chunk_index;

    h0 = _h0;
    h1 = _h1;
    h2 = _h2;
    h3 = _h3;
    h4 = _h4;

    for(chunk_index = 0; chunk_index < ctx->num_of_chunks; chunk_index++)
    {
        for(word_index = 0; word_index < WORDS_IN_CHUNK; word_index++)
            w[word_index] = ctx->chunks[chunk_index].words[word_index];

        for(; word_index < 80; word_index++)
            w[word_index] = rotate_left(w[word_index-3] ^ w[word_index-8] ^ w[word_index-14] ^ w[word_index-16], 1);

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

        for(word_index = 0; word_index < 80; word_index++)
        {
            if(word_index < 20)
            {
                f = ((b & c) ^ ((~b) & d));
                k = 0x5A827999;
            }
            else if(word_index >= 20 && word_index < 40)
            {
                f = (b ^ c ^ d);
                k = 0x6ED9EBA1;
            }
            else if(word_index >= 40 && word_index < 60)
            {
                f = ((b & c) ^ (b & d) ^ (c & d));
                k = 0x8F1BBCDC;
            }
            else if(word_index >= 60 && word_index < 80)
            {
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
