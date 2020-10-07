#include "pbkdf2.h"


/**                         pbkdf2_ctx_init(pbkdf2_ctx_t*);
 *
 *  Requires:               [Variables: ctx->password, ctx->salt, ctx->strlen_salt, ctx->strlen_password,
 *                          ctx->iteration_count set.]
 *
 *  Allows:                 - pbkdf2(pbkdf2_ctx_t*);
 *                          - pbkdf2_ctx_dispose(pbkdf2_ctx_t*);
 *
 *  Description:            Utility function that has to be called once password, salt, strlen_salt, strlen_password and
 *                          iteration_count are defined, in order to initialize the underlying hmac_sha1_key and text
 *                          contexts with the correct amount of bits needed for the pbkdf2 algorithm.
 *
 * @param ctx:              pbkdf2_ctx_t struct containing the hmac_context, whose password, salt, strlen_salt, strlen_password
 *                          and iteration_count values have already been set.
 */
void pbkdf2_ctx_init(pbkdf2_ctx_t *ctx) {
    hmac_ctx_init(&ctx->hmac_ctx, ctx->strlen_password * 8, ctx->strlen_salt * 8 + 32 + BITS_IN_CHUNK);
}


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
    uint64_t i, j, index, mk_index;
    uint64_t len;

    if ((ctx->bits_in_result_hash & BITS_IN_WORD - 1) != 0) {
        fprintf(stderr, "Bits in result hash is not a multiple of 32 (%d)\n", ctx->bits_in_result_hash);
        exit(-1);
    }

    len = (ctx->bits_in_result_hash + BITS_IN_HASH - 1) / BITS_IN_HASH;
    ctx->words_in_T = ctx->bits_in_result_hash / BITS_IN_WORD;

    ctx->T = (uint32_t *) malloc(ctx->words_in_T * sizeof(uint32_t));

    for (index = 0; index < ctx->words_in_T; index++) {
        ctx->T[index] = 0;
    }

    for (i = 1; i <= len; i++) {

        hmac_ctx_init(&ctx->hmac_ctx, ctx->strlen_password * 8, ctx->strlen_salt * 8 + 32);
        //                                                                        + 32 per l'intero i aggiunto dopo al text (↑)

        hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);
        hmac_append_str_text(&ctx->hmac_ctx, ctx->salt, ctx->strlen_salt);
        hmac_append_int_text(&ctx->hmac_ctx, i);

        for (j = 1; j <= ctx->iteration_count; j++) {

            hmac(&ctx->hmac_ctx);

            hmac_ctx_dispose(&ctx->hmac_ctx);
            hmac_ctx_init(&ctx->hmac_ctx, BITS_IN_HASH, ctx->strlen_salt * 8 + 32);
            //                                         + 32 per l'intero i aggiunto dopo al text (↑)


            for (index = 0; index < WORDS_IN_HASH; index++) {
                mk_index = (i - 1) * WORDS_IN_HASH + index;
                if (mk_index >= ctx->words_in_T) {
                    break;
                }
                ctx->T[mk_index] ^= ctx->hmac_ctx.digest[index];
            }

            hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[0]);
            hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[1]);
            hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[2]);
            hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[3]);
            hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[4]);
            hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);

        }

        hmac_ctx_dispose(&ctx->hmac_ctx);
    }
}

/**                         pbkdf2_ctx_dispose(pbkdf2_ctx_t*):
 *
 *  Requires:               - pbkdf2_ctx_init(pbkdf2_ctx_t*);
 *
 *  Allows:                 []
 *
 *  Description:            Utility function that properly handles the disposal of the output digest array.
 *
 * @param ctx:              pbkdf2 context with the soon to be disposed output array.
 */
void pbkdf2_ctx_dispose(pbkdf2_ctx_t *ctx) {
    free(ctx->T);
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

/* Example Main
int main(int argc, char** argv)
{
    char salt[MAX_LENGTH] = "salt";
    char password[MAX_LENGTH] = "password";

    uint32_t strlen_password, strlen_salt;
    uint32_t iteration_count = 4096;
    pbkdf2_ctx_t ctx;

    strlen_password = strlen(password);
    strlen_salt = strlen(salt);

    ctx.strlen_password = strlen_password;
    ctx.strlen_salt = strlen_salt;
    ctx.iteration_count = iteration_count;
    ctx.bits_in_result_hash = 256;

    strncpy((char*) ctx.password, password, ctx.strlen_password);
    strncpy((char*) ctx.salt, salt, ctx.strlen_salt);

    pbkdf2_ctx_init(&ctx);

    hmac_append_str_text(&ctx.hmac_ctx, ctx.salt, ctx.strlen_salt);
    hmac_append_str_key(&ctx.hmac_ctx, ctx.password, ctx.strlen_password);

    pbkdf2(&ctx);

    for(uint32_t i = 0; i < ctx.bits_in_result_hash / BITS_IN_WORD; i++)
    {
        printf("%08x ", ctx.T[i]);
    }
    printf("\n");

    pbkdf2_ctx_dispose(&ctx);

}
*/