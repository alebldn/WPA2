#include "src/wpa2.h"
#include <string.h>

int main(int argc, char** argv)
{
    wpa2_ctx_t ctx;
    uint32_t strlen_password, strlen_salt;
    uint32_t iteration_count = 4096;

    char password[MAX_LENGHT] = "password";
    char salt[MAX_LENGHT] = {0x01, 0x23, 0x45, 0x56, 0x78, 0x9a};

    strlen_password = strlen(ctx.pbkdf2_ctx.password);

    strncpy(ctx.pbkdf2_ctx.password, password, ctx.pbkdf2_ctx.strlen_password);
    strncpy(ctx.pbkdf2_ctx.salt, salt, ctx.pbkdf2_ctx.strlen_salt);

    ctx.pbkdf2_ctx.strlen_password = strlen_password;
    ctx.pbkdf2_ctx.strlen_salt = 10;
    ctx.pbkdf2_ctx.iteration_count = iteration_count;

    wpa2(&ctx);
}
