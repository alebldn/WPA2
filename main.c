#include "src/wpa2.h"
#include <string.h>

int main(int argc, char** argv)
{
    wpa2_ctx_t ctx;
    hmac_ctx_t hmac_ctx;
    uint32_t strlen_password, strlen_salt;
    uint32_t iteration_count = 4096;

    char password[MAX_LENGHT] = "";
    char salt[MAX_LENGHT] = "";
    // {0xf4, 0xf5, 0x24, 0xd8, 0x79, 0x75}

    strlen_password = strlen(ctx.pbkdf2_ctx.password);
    strlen_salt = 10;

    memset(ctx.pbkdf2_ctx.password, 0, MAX_LENGHT);
    memset(ctx.pbkdf2_ctx.salt, 0, MAX_LENGHT);

    strncpy(ctx.pbkdf2_ctx.password, password, strlen_password);
    strncpy(ctx.pbkdf2_ctx.salt, salt, strlen_salt);

    ctx.pbkdf2_ctx.strlen_password = strlen_password;
    ctx.pbkdf2_ctx.strlen_salt = strlen_salt;
    ctx.pbkdf2_ctx.iteration_count = iteration_count;

    wpa2(&ctx);

    hmac_ctx_init(&hmac_ctx, 128, 0);

    hmac_append_int_key(&hmac_ctx, ctx.PMK[0]);
    hmac_append_int_key(&hmac_ctx, ctx.PMK[1]);
    hmac_append_int_key(&hmac_ctx, ctx.PMK[2]);
    hmac_append_int_key(&hmac_ctx, ctx.PMK[3]);

    hmac(&hmac_ctx);

    hmac_ctx_dispose(&hmac_ctx);


    printf("+---------------------------------- PMK ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %08x %08x %08x %08x |\n", ctx.PMK[0], ctx.PMK[1], ctx.PMK[2], ctx.PMK[3], ctx.PMK[4], ctx.PMK[5], ctx.PMK[6], ctx.PMK[7]);
    printf("+---------------------------------- PTK ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %35s |\n", ctx.PMK[0], ctx.PMK[1], ctx.PMK[2], ctx.PMK[3], " ");
    printf("+---------------------------------- MIC ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %35s |\n", hmac_ctx.digest[0], hmac_ctx.digest[1], hmac_ctx.digest[2], hmac_ctx.digest[3], " ");
    printf("+-------------------------------------------------------------------------+\n");


}
