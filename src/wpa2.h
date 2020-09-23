#ifndef WPA2_WPA2_H
#define WPA2_WPA2_H

#include "pbkdf2.h"

#define WORDS_IN_PMK    8

typedef struct {
    pbkdf2_ctx_t pbkdf2_ctx;
    uint32_t PMK[WORDS_IN_PMK];
} wpa2_ctx_t;

void pbkdf2_append_str_password(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen);
void pbkdf2_append_int_password(pbkdf2_ctx_t* ctx, uint64_t value);
void pbkdf2_append_str_salt(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen);
void pbkdf2_append_int_salt(pbkdf2_ctx_t* ctx, uint64_t value);


void wpa2(wpa2_ctx_t* ctx);


#endif //WPA2_WPA2_H
