/*
 * pbkdf2_hmac_sha1.h
 *
 *  Created on: Mar 27, 2020
 *      Author: Delta
 */

#ifndef PBKDF2_H
#define PBKDF2_H

/** Includes */
#include "hmac.h"

/** Defines */
/** Max length of the password */
#define MAX_LENGTH          64

/**
 * Definition of the structure pbkdf2_ctx_t, containing:
 *
 *  - hmac_ctx:             a struct containing all the variables needed in order to execute the hmac_sha1 algorithm.
 *
 *  - password:             a string containing the password as dictated in the pbkdf2 algorithm.
 *
 *  - salt:                 a string containing the salt to be applied as dictated in the pbkdf2 algorithm.
 *
 *  - strlen_password:      a 32 bit unsigned integer containing the length of the password in chars (bytes).
 *
 *  - strlen_salt:          a 32 bit unsigned integer containing the length of the salt in chars (bytes).
 *
 *  - iteration_count:      a 32 bit unsigned integer representing the number of iterations of hmac_sha1 that need to be
 *                          applied according to the pbkdf2 algotithm.
 *
 *  - T:                    dynamic array of [words_in_T] words containing pbkdf2's output.
 *
 *  - words_in_T:           number of 32 bit unsigned integer words in output dynamic array.
 *
 *  - bits_in_result_hash:  number of bits contained in the output hash (not necessarily equal to words_in_T * 32).
 */
typedef struct {
    hmac_ctx_t hmac_ctx;
    unsigned char password[MAX_LENGTH];
    unsigned char salt[MAX_LENGTH];
    uint32_t strlen_password;
    uint32_t strlen_salt;
    uint32_t iteration_count;
    uint32_t *T;
    uint32_t words_in_T;
    uint32_t bits_in_result_hash;
} pbkdf2_ctx_t;

/** Function declarations */
void pbkdf2_ctx_init(pbkdf2_ctx_t *ctx);

void pbkdf2(pbkdf2_ctx_t *ctx);

void pbkdf2_ctx_dispose(pbkdf2_ctx_t *ctx);

#endif /* PBKDF2_H */
