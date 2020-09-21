#include "src/wpa2.h"

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



int main(int argc, char** argv)
{
    /*
     * TODO:
     * - Inserire PMK in una struttura e fare in modo che la funzione wpa2 faccia ritornare quella struttura lì,
     *      oppure passare come argomento un puntatore a struttura
     *
     */
    /*
    char salt[MAX_LENGHT] = "salt";
    char password[MAX_LENGHT] = "password";



    printf("%08x %08x %08x %08x %08x\n", ctx.T[0], ctx.T[1], ctx.T[2], ctx.T[3], ctx.T[4]);
     */
}

/*
 * int main(int argc, char** argv)
{
    uint32_t PMK[8];
    char salt[MAX_LENGHT] = "salt";
    char password[MAX_LENGHT] = "password";

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

    pbkdf2_ctx_init(&ctx);

    hmac_append_str_text(&ctx.hmac_ctx, ctx.salt, ctx.strlen_salt);
    hmac_append_str_key(&ctx.hmac_ctx, ctx.password, ctx.strlen_password);

    pbkdf2(&ctx);

    pbkdf2_ctx_dispose(&ctx);

    printf("%08x %08x %08x %08x %08x\n", ctx.T[0], ctx.T[1], ctx.T[2], ctx.T[3], ctx.T[4]);
}
 */
