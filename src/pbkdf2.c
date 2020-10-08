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

    uint32_t  j, index, mk_index;

    for (index = 0; index < WORDS_IN_T; index++) {
        ctx->T[index] = 0;
    }

    hmac_ctx_init(&ctx->hmac_ctx, ctx->strlen_password * 8, ctx->strlen_salt * 8 + 32);
    //                                                                        + 32 per l'intero i aggiunto dopo al text (↑)

    hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);
    hmac_append_str_text(&ctx->hmac_ctx, ctx->salt, ctx->strlen_salt);
    hmac_append_int_text(&ctx->hmac_ctx, 1);

    for (j = 1; j <= ITERATION_COUNT; j++) {

        hmac(&ctx->hmac_ctx);

        hmac_ctx_dispose(&ctx->hmac_ctx);
        hmac_ctx_init(&ctx->hmac_ctx, BITS_IN_HASH, ctx->strlen_salt * 8 + 32);
        //                                         + 32 per l'intero i aggiunto dopo al text (↑)

        ctx->T[0] ^= ctx->hmac_ctx.digest[0];
        ctx->T[1] ^= ctx->hmac_ctx.digest[1];
        ctx->T[2] ^= ctx->hmac_ctx.digest[2];
        ctx->T[3] ^= ctx->hmac_ctx.digest[3];
        ctx->T[4] ^= ctx->hmac_ctx.digest[4];

        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[0]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[1]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[2]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[3]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[4]);
        hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);

    }

    hmac_ctx_dispose(&ctx->hmac_ctx);

    hmac_ctx_init(&ctx->hmac_ctx, ctx->strlen_password * 8, ctx->strlen_salt * 8 + 32);
    //                                                                        + 32 per l'intero i aggiunto dopo al text (↑)

    hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);
    hmac_append_str_text(&ctx->hmac_ctx, ctx->salt, ctx->strlen_salt);
    hmac_append_int_text(&ctx->hmac_ctx, 2);

    for (j = 1; j <= ITERATION_COUNT; j++) {

        hmac(&ctx->hmac_ctx);

        hmac_ctx_dispose(&ctx->hmac_ctx);
        hmac_ctx_init(&ctx->hmac_ctx, BITS_IN_HASH, ctx->strlen_salt * 8 + 32);
        //                                         + 32 per l'intero i aggiunto dopo al text (↑)

        ctx->T[5] ^= ctx->hmac_ctx.digest[0];
        ctx->T[6] ^= ctx->hmac_ctx.digest[1];
        ctx->T[7] ^= ctx->hmac_ctx.digest[2];

        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[0]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[1]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[2]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[3]);
        hmac_append_int_text(&ctx->hmac_ctx, ctx->hmac_ctx.digest[4]);
        hmac_append_str_key(&ctx->hmac_ctx, ctx->password, ctx->strlen_password);

    }

    hmac_ctx_dispose(&ctx->hmac_ctx);
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

    for(int i = 0; i < ctx.bits_in_result_hash / BITS_IN_WORD; i++)
    {
        printf("%08x ", ctx.T[i]);
    }
    printf("\n");

    pbkdf2_ctx_dispose(&ctx);

}
*/