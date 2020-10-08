#ifndef SHA1_TYPES_H
#define SHA1_TYPES_H

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

/** Constant words defined as dictated in SHA1 algorithm */
#define H0                             0x67452301;
#define H1                             0xEFCDAB89;
#define H2                             0x98BADCFE;
#define H3                             0x10325476;
#define H4                             0xC3D2E1F0;

/** Typedefs */
/** Definition of the boolean type bit_t */
typedef enum {
    false,
    true
} bit_t;

/** Definition of the struct chunk_t: contains a static array of [WORDS_IN_CHUNK] words */
typedef struct {
    uint32_t words[WORDS_IN_CHUNK];
} chunk_t;

#endif //SHA1_TYPES_H
