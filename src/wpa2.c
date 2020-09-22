#include "wpa2.h"

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

void pbkdf2_append_str_password(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen)
{
    hmac_append_str_key(&ctx->hmac_ctx, value, strlen);
}

void pbkdf2_append_int_password(pbkdf2_ctx_t* ctx, uint64_t value)
{
    hmac_append_int_key(&ctx->hmac_ctx, value);
}

void pbkdf2_append_str_salt(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen)
{
    hmac_append_str_text(&ctx->hmac_ctx, value, strlen);
}

void pbkdf2_append_int_salt(pbkdf2_ctx_t* ctx, uint64_t value)
{
    hmac_append_int_text(&ctx->hmac_ctx, value);
}

void wpa2(wpa2_ctx_t* ctx)
{
    /* Iterazione 1 */
    pbkdf2_ctx_init(&ctx->pbkdf2_ctx);

    pbkdf2_append_str_password(&ctx->pbkdf2_ctx, ctx->pbkdf2_ctx.password, ctx->pbkdf2_ctx.strlen_password);
    pbkdf2_append_str_salt(&ctx->pbkdf2_ctx, ctx->pbkdf2_ctx.salt, ctx->pbkdf2_ctx.strlen_salt);
    pbkdf2_append_int_salt(&ctx->pbkdf2_ctx, 1);

    pbkdf2(&ctx->pbkdf2_ctx);

    pbkdf2_ctx_dispose(&ctx->pbkdf2_ctx);

    ctx->PMK[0] = ctx->pbkdf2_ctx.T[0];
    ctx->PMK[1] = ctx->pbkdf2_ctx.T[1];
    ctx->PMK[2] = ctx->pbkdf2_ctx.T[2];
    ctx->PMK[3] = ctx->pbkdf2_ctx.T[3];
    ctx->PMK[4] = ctx->pbkdf2_ctx.T[4];

    /* Iterazione 2 */
    pbkdf2_ctx_init(&ctx->pbkdf2_ctx);

    pbkdf2_append_str_password(&ctx->pbkdf2_ctx, ctx->pbkdf2_ctx.password, ctx->pbkdf2_ctx.strlen_password);
    pbkdf2_append_str_salt(&ctx->pbkdf2_ctx, ctx->pbkdf2_ctx.salt, ctx->pbkdf2_ctx.strlen_salt);
    pbkdf2_append_int_salt(&ctx->pbkdf2_ctx, 2);

    pbkdf2(&ctx->pbkdf2_ctx);

    pbkdf2_ctx_dispose(&ctx->pbkdf2_ctx);

    ctx->PMK[5] = ctx->pbkdf2_ctx.T[0];
    ctx->PMK[6] = ctx->pbkdf2_ctx.T[1];
    ctx->PMK[7] = ctx->pbkdf2_ctx.T[2];
}