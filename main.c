#include "src/pbkdf2.h"
#include "cap2hccapx/cap2hccapx.h"
#include <string.h>

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

void check_arguments(int argc, char **argv) {

    /* Checking number of arguments */
    if(argc != 3 && argc != 4)
    {
        fprintf(stderr, "Usage: %s <cap_file> <wordlist_file> [Filter by essid]\n", argv[0]);
        exit(-1);
    }

    /* Checking extension is "cap" (magic number check is performed within cap2hccapx */
    char* extension = strrchr(argv[1], '.');

    if(strcmp(extension + 1, "cap") != 0)
    {
        fprintf(stderr, "File \"%s\" is not a .cap file\n", argv[1]);
        exit(-1);
    }

    /* Checking cap filename length */
    if(strlen(argv[1]) > MAX_LENGTH - 3)
    /*
     * - 3 because strlen(".cap") = 4, strlen(".hccapx") = 7, 7 - 4 = 3,
     * We check this since we need to append the .hccapx extension to the filename,
     * trimmed of his .cap extension
     */
    {
        fprintf(stderr, "Filename \"%s\" exceeds filename length [%d]\n", argv[1], MAX_LENGTH);
        exit(-1);
    }
}


void derive_hccapx_filename(char cap_filename[MAX_LENGTH], char hccapx_filename[MAX_LENGTH]) {

    /* We already asserted cap_filename has ".cap" extension */
    uint8_t cap_filename_len = strlen(cap_filename);

    memset(hccapx_filename, 0, MAX_LENGTH);
    strncpy(hccapx_filename, cap_filename, cap_filename_len - 3);
    strcat(hccapx_filename, "hccapx");
}


hccapx_t process_cap_file(int argc, char **argv) {

    FILE* hccapx_file;

    hccapx_t temp_hccapx, chosen_hccapx;
    hccapx_t* hccapx_list;

    char hccapx_filename[MAX_LENGTH];

    uint32_t number_of_hccapx_structs = 0;
    uint32_t hccapx_choice = -1;    /* set to -1 in order to achieve the highest number possible in uint32_t, due to overflow) */
    uint32_t hccapx_struct_size = (uint32_t) sizeof(hccapx_t);

    uint32_t cap2hccapx_argc;
    char** cap2hccapx_argv;

    derive_hccapx_filename(argv[1], hccapx_filename);

    cap2hccapx_argv = (char**) malloc(argc * sizeof(char*));
    cap2hccapx_argv[0] = argv[0];
    cap2hccapx_argv[1] = argv[1];
    cap2hccapx_argv[2] = hccapx_filename;
    cap2hccapx_argc = 3;

    if(argc == 4) {

        cap2hccapx_argv[3] = argv[3];
        cap2hccapx_argc++;
        printf("argv[3] = \"%s\"", argv[3]);

    }

    cap2hccapx(cap2hccapx_argc, cap2hccapx_argv);
    free(cap2hccapx_argv);


    hccapx_file = fopen(hccapx_filename, "rb");
    if(hccapx_file) {

        hccapx_list = (hccapx_t*) malloc(hccapx_struct_size);

        while (fread(&temp_hccapx, hccapx_struct_size, 1, hccapx_file) == 1) {

            number_of_hccapx_structs++;
            hccapx_list = (hccapx_t *) realloc(hccapx_list, number_of_hccapx_structs * hccapx_struct_size);
            hccapx_list[number_of_hccapx_structs - 1] = temp_hccapx;

        }

        fclose(hccapx_file);

        if(number_of_hccapx_structs > 0) {
            while (number_of_hccapx_structs < hccapx_choice) {
                printf("Select the HS you want to crack between:\n");
                for (uint32_t i = 0; i < number_of_hccapx_structs; i++) {
                    printf("%d) [AP]: \"%s\" - [MAC_AP]: %02x:%02x:%02x:%02x:%02x:%02x - [MAC_STA]: %02x:%02x:%02x:%02x:%02x:%02x\n",
                           i+1,
                           hccapx_list[i].essid,
                           hccapx_list[i].mac_ap[0], hccapx_list[i].mac_ap[1], hccapx_list[i].mac_ap[2],
                           hccapx_list[i].mac_ap[3], hccapx_list[i].mac_ap[4], hccapx_list[i].mac_ap[5],
                           hccapx_list[i].mac_sta[0], hccapx_list[i].mac_sta[1], hccapx_list[i].mac_sta[2],
                           hccapx_list[i].mac_sta[3], hccapx_list[i].mac_sta[4], hccapx_list[i].mac_sta[5]
                    );
                }
                scanf("%u", &hccapx_choice);
                if (hccapx_choice > number_of_hccapx_structs)
                {
                    printf("Choice [%u] not valid.\n", hccapx_choice);
                }
            }
        }
        else
        {
            printf("No HS found in the given .cap file, exiting.\n");
            free(hccapx_list);
            remove(hccapx_filename);
            exit(-1);
        }

        chosen_hccapx = hccapx_list[hccapx_choice-1];

        free(hccapx_list);

        return chosen_hccapx;
    }
    else {

        fprintf(stderr, "Error in opening input hccapx file \"%s\", exiting.\n", argv[1]);
        exit(-1);

    }
}

/** ./wpa2 <cap_file> <wordlist_file> [Essid Filter] */

int main(int argc, char **argv) {

    FILE *wordlist;

    uint32_t strlen_password, strlen_salt;
    unsigned char password[MAX_LENGTH];

    hccapx_t hccapx;
    pbkdf2_ctx_t ctx;
    hmac_ctx_t hmac_ctx;

    check_arguments(argc, argv);

    hccapx = process_cap_file(argc, argv);

    wordlist = fopen(argv[2], "r");
    if (wordlist) {

        while(fgets((char*) password, MAX_LENGTH, wordlist) != NULL) {

            strlen_password = strlen((char *) password);
            strlen_salt = hccapx.essid_len;

            memset(ctx.password, 0, MAX_LENGTH);
            memset(ctx.salt, 0, MAX_LENGTH);

            strncpy((char *) ctx.password, (char *) password, strlen_password);
            strncpy((char *) ctx.salt, (char *) hccapx.essid, strlen_salt);

            ctx.strlen_password = strlen_password;
            ctx.strlen_salt = strlen_salt;
            ctx.iteration_count = 4096;
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

            printf("+---------------------------------- MIC ----------------------------------+\n");
            printf("| %08x %08x %08x %08x %35s |\n", hmac_ctx.digest[0], hmac_ctx.digest[1], hmac_ctx.digest[2],
                   hmac_ctx.digest[3], " ");
            printf("+-------------------------------------------------------------------------+\n");

            for(uint8_t i = 0; i < 16; i++)
            {
                printf("%02x", hccapx.keymic[i]);
            }
            printf("\n");

            hmac_ctx_dispose(&hmac_ctx);
        }
        fclose(wordlist);
    }
    else {  // if(wordlist)
        fprintf(stderr,"Error in opening wordlist file \"%s\", exiting.\n", argv[2]);
        exit(-1);
    }
}




