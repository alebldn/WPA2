#ifndef WPA2_CAP2HCCAPX
#define WPA2_CAP2HCCAPX

#include <stdint.h>

#define MAX_ESSID_LENGTH    32

struct hccapx {
    uint32_t signature;
    uint32_t version;
    uint8_t message_pair;
    uint8_t essid_len;
    uint8_t essid[MAX_ESSID_LENGTH];
    uint8_t keyver;
    uint8_t keymic[16];
    uint8_t mac_ap[6];
    uint8_t nonce_ap[32];
    uint8_t mac_sta[6];
    uint8_t nonce_sta[32];
    uint16_t eapol_len;
    uint8_t eapol[256];

} __attribute__((packed));

int cap2hccapx(int arc, char *argv[]);

typedef struct hccapx hccapx_t;

#endif //WPA2_CAP2HCCAPX
