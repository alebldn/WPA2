#include <string.h>
#include "pbkdf2.h"

/*
 * Internally, the PBKDF2 key derivation function employed in WPA2-Personal
 * utilizes 4096 iterations of the well known HMAC construction with the SHA1
 * cryptographic hash algorithm at its core to obtain 160 bit hash outputs (Fig.
 * 3). Since the WPA2 Pairwise Master Key PMK needs to be 256 bits long, two
 * PBKDF2 rounds are necessary. Their output is concatenated, but from the second
 * iteration the output is truncated to 96 bits to achieve a 256 bit result. In
 * both PBKDF2 iterations the secret password is used as key while the SSID of
 * the Wi-Fi network concatenated with a 32 bit counter value serves as input. In
 * the 1rst iteration, the counter value is one while in the second iteration it is two.
 * Consequently within both PBKDF2 iterations, there are 8192 HMAC-SHA1 iterations
 * required to compute the PMK from the secret password and the network's
 * SSID.
 */

uint32_t* wpa2(char password[MAX_LENGHT], char salt[MAX_LENGHT])
{
    uint32_t PMK[8];
    uint32_t strlen_password, strlen_salt;
    uint32_t iteration_count = 4096;
    pbkdf2_ctx_t ctx;

    strlen_password = strlen(password);
    strlen_salt = strlen(salt);

    ctx.strlen_password = strlen_password;
    ctx.strlen_salt = strlen_salt;

    ctx.iteration_count = iteration_count;
    strncpy(ctx.password, password, ctx.strlen_password);
    strncpy(ctx.salt, salt, ctx.strlen_salt);

    /* Iterazione 1 */
    pbkdf2_ctx_init(&ctx);

    hmac_append_str_key(&ctx.hmac_ctx, ctx.password, ctx.strlen_password);
    hmac_append_str_text(&ctx.hmac_ctx, ctx.salt, ctx.strlen_salt);
    hmac_append_int_text(&ctx.hmac_ctx, 1);

    pbkdf2(&ctx);

    pbkdf2_ctx_dispose(&ctx);

    PMK[0] = ctx.T[0];
    PMK[1] = ctx.T[1];
    PMK[2] = ctx.T[2];
    PMK[3] = ctx.T[3];
    PMK[4] = ctx.T[4];

    /* Iterazione 2 */
    pbkdf2_ctx_init(&ctx);

    hmac_append_str_key(&ctx.hmac_ctx, ctx.password, ctx.strlen_password);
    hmac_append_str_text(&ctx.hmac_ctx, ctx.salt, ctx.strlen_salt);
    hmac_append_int_text(&ctx.hmac_ctx, 2);

    pbkdf2(&ctx);

    pbkdf2_ctx_dispose(&ctx);

    PMK[5] = ctx.T[0];
    PMK[6] = ctx.T[1];
    PMK[7] = ctx.T[2];
    return PMK;
}