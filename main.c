#include "src/pbkdf2.h"
#include <string.h>

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
 * Consequently within both PBKDF2 iterations, there are 8; 192 HMAC-SHA1 iterations
 * required to compute the PMK from the secret password and the network's
 * SSID. With regard to the HMAC internals, Fig. 3 shows that a number of SHA1
 * iterations are necessary to obtain the MAC (Message Authentication Code). In
 * general to compute the SHA1 hash digest of a message, the rst SHA1 iteration
 * is computed by using the initial SHA1 state and hashing the rst part of the
 * message
 */

int main(int argc, char** argv)
{
    char salt[] = "salt";
    char password[] = "password";
    int iteration_count = 2;

    pbkdf2_ctx_t ctx;
    ctx.iteration_count = iteration_count;

    ctx.strlen_password = strlen(password);
    ctx.strlen_salt = strlen(salt);

    ctx.password = (char*) malloc(ctx.strlen_password * sizeof(char));
    ctx.salt = (char*) malloc(ctx.strlen_salt * sizeof(char));

    strncpy(ctx.password, password, ctx.strlen_password);
    strncpy(ctx.salt, salt, ctx.strlen_salt);

    pbkdf2(&ctx);

    printf("%08x %08x %08x %08x %08x\n", ctx.T[0], ctx.T[1], ctx.T[2], ctx.T[3], ctx.T[4]);
    free(ctx.password);
    free(ctx.salt);
}
