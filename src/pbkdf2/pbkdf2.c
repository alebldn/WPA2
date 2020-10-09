#include "pbkdf2.h"

/**                         pbkdf2(pbkdf2_ctx_t*);
 *
 *  Requires:               - pbkdf2_ctx_init(pbkdf2_ctx_t *ctx);
 *
 *  Allows:                 - pbkdf2_ctx_dispose(pbkdf2_ctx_t *ctx);
 *
 *  Description:            Main function, implemented according to the pbkdf2 algorithm. It initializes the underlying
 *                          hmac context by itself.
 *
 * @param ctx:              pbkdf2_ctx_t struct containing the hmac_context, already processed by the pbkdf2_ctx_init function.
 */
void pbkdf2(pbkdf2_ctx_t *ctx) {

    uint32_t i;

    for (i = 0; i < WORDS_IN_T; i++) {
        ctx->T[i] = 0;
    }

    ps_hmac_ctx_init(&ctx->hmac_ctx, ctx->strlen_password * 8, ctx->strlen_salt * 8 + 32);
    //                                                                        + 32 per l'intero i aggiunto dopo al text (↑)

    ps_hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);
    ps_hmac_append_str_text(&ctx->hmac_ctx, ctx->salt, ctx->strlen_salt);
    ps_hmac_append_int_text(&ctx->hmac_ctx, 1);

    for (i = 1; i <= ITERATION_COUNT; i++) {

        ps_hmac(&ctx->hmac_ctx);

        ps_hmac_ctx_init(&ctx->hmac_ctx, BITS_IN_HASH, ctx->strlen_salt * 8 + 32);
        //                                         + 32 per l'intero i aggiunto dopo al text (↑)

        ctx->T[0] ^= ctx->hmac_ctx.digest[0];
        ctx->T[1] ^= ctx->hmac_ctx.digest[1];
        ctx->T[2] ^= ctx->hmac_ctx.digest[2];
        ctx->T[3] ^= ctx->hmac_ctx.digest[3];
        ctx->T[4] ^= ctx->hmac_ctx.digest[4];

        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[0]);
        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[1]);
        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[2]);
        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[3]);
        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[4]);
        ps_hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);

    }

    ps_hmac_ctx_init(&ctx->hmac_ctx, ctx->strlen_password * 8, ctx->strlen_salt * 8 + 32);
    //                                                                        + 32 per l'intero i aggiunto dopo al text (↑)

    ps_hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);
    ps_hmac_append_str_text(&ctx->hmac_ctx, ctx->salt, ctx->strlen_salt);
    ps_hmac_append_int_text(&ctx->hmac_ctx, 2);

    for (i = 1; i <= ITERATION_COUNT; i++) {

        ps_hmac(&ctx->hmac_ctx);

        ps_hmac_ctx_init(&ctx->hmac_ctx, BITS_IN_HASH, ctx->strlen_salt * 8 + 32);
        //                                         + 32 per l'intero i aggiunto dopo al text (↑)

        ctx->T[5] ^= ctx->hmac_ctx.digest[0];
        ctx->T[6] ^= ctx->hmac_ctx.digest[1];
        ctx->T[7] ^= ctx->hmac_ctx.digest[2];

        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[0]);
        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[1]);
        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[2]);
        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[3]);
        ps_hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[4]);
        ps_hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);

    }
}


/*     CHEATSHEET

Input:
        P =         password
        S =         salt
        c =         1
        Output =    0c60c80f 961f0e71 f3a9b524 af601206 2fe037a6

Input:
        P =         password
        S =         salt
        c =         2
        Output =    ea6c014d c72d6f8c cd1ed92a ce1d41f0 d8de8957

Input:
        P =         password
        S =         salt
        c =         4096
        Output =    4b007901 b765489a bead49d9 26f721d0 65a429c1

Input:
        P =         password
        S =         salt
        c =         16777216
        Output =    eefe3d61 cd4da4e4 e9945b3d 6ba2158c 2634e984
*/