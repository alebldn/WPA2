#include "src/pbkdf2.h"
#include "cap2hccapx/cap2hccapx.h"
#include <string.h>


/*
4 WAY HANDSHAKE:
1-  The AP sends a nonce-value (ANonce) to the STA together with a Key Replay Counter, which is a number that is used to match
    each pair of messages sent, and discard replayed messages. The STA now has all the attributes to construct the PTK.
2-  The STA sends its own nonce-value (SNonce) to the AP together with a Message Integrity Code (MIC), including authentication,
    which is really a Message Authentication and Integrity Code (MAIC), and the Key Replay Counter which will be the same as
    Message 1, to allow AP to match the right Message 1.
3-  The AP verifies Message 2, by checking MIC, RSN, ANonce and Key Replay Counter Field, and if valid constructs and sends the GTK with another MIC.
4-  The STA verifies Message 3, by checking MIC and Key Replay Counter Field, and if valid sends a confirmation to the AP.

The Pairwise Transient Key (64 bytes) is divided into five separate keys:
-   16 bytes of EAPOL-Key Confirmation Key (KCK) – Used to compute MIC on WPA EAPOL Key message
-   16 bytes of EAPOL-Key Encryption Key (KEK) – AP uses this key to encrypt additional data sent (in the 'Key Data' field)
    to the client (for example, the RSN IE or the GTK)
-   16 bytes of Temporal Key (TK) – Used to encrypt/decrypt Unicast data packets
-   8 bytes of Michael MIC Authenticator Tx Key – Used to compute MIC on unicast data packets transmitted by the AP
-   8 bytes of Michael MIC Authenticator Rx Key – Used to compute MIC on unicast data packets transmitted by the station
 */

unsigned char *min(unsigned char *A, unsigned char *S, int strlen) {
    for (int i = 0; i < strlen; i++) {
        if (A[i] < S[i])
            return A;
        else if (A[i] > S[i])
            return S;
    }
    return A;
}

unsigned char *max(unsigned char *A, unsigned char *S, int strlen) {
    for (int i = 0; i < strlen; i++) {
        if (A[i] > S[i])
            return A;
        else if (A[i] < S[i])
            return S;
    }
    return A;
}

int main(int argc, char **argv) {
    /* TODO: inserire gli argomenti (file.cap) (wordlist) */
    hccapx_t hccapx;
    FILE *fp;

    fp = fopen("C:\\Users\\Delta\\CLionProjects\\WPA2\\Jarvis.hccapx", "rb");
    if (fp == NULL) {
        perror("Error in opening input file, exiting.\n");
        exit(-1);
    }

    memset(&hccapx, 0, sizeof(hccapx_t));

    /* TODO: Legge sempre e solo la prima struttura hccapx_t, nel caso in cui fossero di più, bisogna verificare e iterare */
    fread(&hccapx, sizeof(hccapx_t), 1, fp);

    free(fp);

    pbkdf2_ctx_t ctx;
    hmac_ctx_t hmac_ctx;
    uint32_t strlen_password, strlen_salt;
    uint32_t iteration_count = 4096;
    unsigned char password[MAX_LENGTH] = "passwordtest";
    unsigned char salt[MAX_LENGTH] = "Jarvis";

    strlen_password = strlen((char *) password);
    strlen_salt = strlen((char *) hccapx.essid);

    memset(ctx.password, 0, MAX_LENGTH);
    memset(ctx.salt, 0, MAX_LENGTH);

    strncpy((char *) ctx.password, (char *) password, strlen_password);
    strncpy((char *) ctx.salt, (char *) hccapx.essid, strlen_salt);

    ctx.strlen_password = strlen_password;
    ctx.strlen_salt = strlen_salt;
    ctx.iteration_count = iteration_count;
    ctx.bits_in_result_hash = 256;

    pbkdf2_ctx_init(&ctx);

    pbkdf2(&ctx);

    printf("+---------------------------------- PMK ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %08x %08x %08x %08x |\n", ctx.T[0], ctx.T[1], ctx.T[2],
           ctx.T[3], ctx.T[4], ctx.T[5], ctx.T[6], ctx.T[7]);
    printf("+-------------------------------------------------------------------------+\n");

    /*
     * È necessario scrivere "Pairwise key expansion\0", min(AMAC, SMAC), max(AMAC, SMAC),
     * min(ANonce, Snonce), max(ANonce, Snonce), '\0'
     *
     * Quindi i byte totali da scrivere sono 22 + 1 + 6 + 6 + 32 + 32 + 1 = 100 byte.
     * Mentre il numero di bit è 100 * 8 = 800.
     */
    hmac_ctx_init(&hmac_ctx, 256, 800);

    hmac_append_int_key(&hmac_ctx, ctx.T[0]);
    hmac_append_int_key(&hmac_ctx, ctx.T[1]);
    hmac_append_int_key(&hmac_ctx, ctx.T[2]);
    hmac_append_int_key(&hmac_ctx, ctx.T[3]);
    hmac_append_int_key(&hmac_ctx, ctx.T[4]);
    hmac_append_int_key(&hmac_ctx, ctx.T[5]);
    hmac_append_int_key(&hmac_ctx, ctx.T[6]);
    hmac_append_int_key(&hmac_ctx, ctx.T[7]);

    hmac_append_str_text(&hmac_ctx, (unsigned char *) "Pairwise key expansion", 22);
    hmac_append_char_text(&hmac_ctx, 0x00);
    hmac_append_str_text(&hmac_ctx, min(hccapx.mac_ap, hccapx.mac_sta, 6), 6);
    hmac_append_str_text(&hmac_ctx, max(hccapx.mac_ap, hccapx.mac_sta, 6), 6);
    hmac_append_str_text(&hmac_ctx, min(hccapx.nonce_ap, hccapx.nonce_sta, 32), 32);
    hmac_append_str_text(&hmac_ctx, max(hccapx.nonce_ap, hccapx.nonce_sta, 32), 32);
    hmac_append_char_text(&hmac_ctx, 0x00);

    hmac(&hmac_ctx);

    printf("+---------------------------------- KCK ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %35s |\n", hmac_ctx.digest[0], hmac_ctx.digest[1], hmac_ctx.digest[2],
           hmac_ctx.digest[3], " ");
    printf("+-------------------------------------------------------------------------+\n");

    pbkdf2_ctx_dispose(&ctx);

    hmac_ctx_dispose(&hmac_ctx);

    hmac_ctx_init(&hmac_ctx, 128, hccapx.eapol_len * 8);

    hmac_append_int_key(&hmac_ctx, hmac_ctx.digest[0]);
    hmac_append_int_key(&hmac_ctx, hmac_ctx.digest[1]);
    hmac_append_int_key(&hmac_ctx, hmac_ctx.digest[2]);
    hmac_append_int_key(&hmac_ctx, hmac_ctx.digest[3]);

    hmac_append_str_text(&hmac_ctx, hccapx.eapol, hccapx.eapol_len);

    hmac(&hmac_ctx);

    // 402a7cff 1ab41483 66030581 1c269cf2

    printf("+---------------------------------- MIC ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %35s |\n", hmac_ctx.digest[0], hmac_ctx.digest[1], hmac_ctx.digest[2],
           hmac_ctx.digest[3], " ");
    printf("+-------------------------------------------------------------------------+\n");

    hmac_ctx_dispose(&hmac_ctx);

/*
    printf("+---------------------------------- PMK ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %08x %08x %08x %08x |\n", ctx.PMK[0], ctx.PMK[1], ctx.PMK[2], ctx.PMK[3], ctx.PMK[4], ctx.PMK[5], ctx.PMK[6], ctx.PMK[7]);
    printf("+---------------------------------- PTK ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %35s |\n", ctx.PMK[0], ctx.PMK[1], ctx.PMK[2], ctx.PMK[3], " ");
    printf("+---------------------------------- MIC ----------------------------------+\n");
    printf("| %08x %08x %08x %08x %35s |\n", hmac_ctx.digest[0], hmac_ctx.digest[1], hmac_ctx.digest[2], hmac_ctx.digest[3], " ");
    printf("+-------------------------------------------------------------------------+\n");
*/
}