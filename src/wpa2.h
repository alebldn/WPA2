#ifndef WPA2_WPA2_H
#define WPA2_WPA2_H

#include "pbkdf2.h"

#define WORDS_IN_PMK    8

typedef struct {
    pbkdf2_ctx_t pbkdf2_ctx;
    uint32_t PMK[WORDS_IN_PMK];
} wpa2_ctx_t;

;


void wpa2(wpa2_ctx_t* ctx);


#endif //WPA2_WPA2_H
