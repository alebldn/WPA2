/*
 * pbkdf2_hmac_sha1.h
 *
 *  Created on: Mar 27, 2020
 *      Author: Delta
 */

#ifndef PBKDF2_H
#define PBKDF2_H

#include "hmac.h"

#define MAX_LENGHT          64


typedef struct
{
	hmac_ctx_t hmac_ctx;
	char password[MAX_LENGHT];
	char salt[MAX_LENGHT];
	uint32_t strlen_password;
	uint32_t strlen_salt;
	uint64_t iteration_count;
	uint32_t* T;
    uint32_t bits_in_result_hash;
} pbkdf2_ctx_t;

void pbkdf2_append_str_password(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen);
void pbkdf2_append_int_password(pbkdf2_ctx_t* ctx, uint64_t value);
void pbkdf2_append_str_salt(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen);
void pbkdf2_append_int_salt(pbkdf2_ctx_t* ctx, uint64_t value);

void pbkdf2_ctx_init(pbkdf2_ctx_t* ctx);
void pbkdf2(pbkdf2_ctx_t* ctx);
void pbkdf2_ctx_dispose(pbkdf2_ctx_t* ctx);

#endif /* PBKDF2_H */
