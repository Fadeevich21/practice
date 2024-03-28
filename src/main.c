#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bignum.h"
#include "montgomery.h"
#include "rsa.h"


typedef struct {
    uint8_t hours;
    uint8_t minutes;
    uint8_t seconds;
} packet_time_t;

typedef struct {
    uint32_t plc_number;
    packet_time_t time;
} packet_t;

void print_packet(packet_t packet);

int main() {
    rsa_pub_key_t pub_key;
    char *pub_data =
        "-----BEGIN PUBLIC KEY-----"
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOIkleXcUNZTiBRuAxYU6dCEKJLW6ZET"
        "FE81NUIVffzm+E75/mKGSkpgmb5KamsNo7SEgEAdKro0RkZZ0ia4Rc8CAwEAAQ=="
        "-----END PUBLIC KEY-----";
    import_pub_key(&pub_key, pub_data);

    rsa_pvt_key_t pvt_key;
    char *pvt_data =
        "-----BEGIN PRIVATE KEY-----"
        "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA4iSV5dxQ1lOIFG4D"
        "FhTp0IQoktbpkRMUTzU1QhV9/Ob4Tvn+YoZKSmCZvkpqaw2jtISAQB0qujRGRlnS"
        "JrhFzwIDAQABAkEApRBHSYxShN5byW2zWv7Q255bbzLnMTlX7ajMwvulBl7ArgD+"
        "mjD30CzkN3C5m3MEuqC4Yz+/C3AgndnCRWrCIQIhAP8b2kDrrxXf9oloIKVHs85Q"
        "Trjxuh8VINHPWZIc+lWrAiEA4u7UEKH6G6RsDXHmoj6ekZwYOLJKSY6Em/h53BMB"
        "ZG0CIDtkpqmatYaoP+O5xG/2g5wzAkD4tlZqOtveJIJqELZFAiEAy029bN1ALW2D"
        "ZBQr1CSXeMnIJVsNFJL6mKTlv1TDhY0CIBFMJL5vaKTx5TSEEZPRB/NmbeV7joIq"
        "GLq7YHwu01m2"
        "-----END PRIVATE KEY-----";
    import_pvt_key(&pvt_key, pvt_data);

    montg_t montg_domain;
    montg_init(&montg_domain, &pub_key.mod);

    const char test_msg[BN_MSG_LEN + 1] = "";
    char out_enc[BN_BYTE_SIZE * 2 + 1] = "", out_dec[BN_MSG_LEN + 1] = "";

    packet_t test_enc_packet;
    test_enc_packet.plc_number = 21;
    test_enc_packet.time.hours = 10;
    test_enc_packet.time.minutes = 20;
    test_enc_packet.time.seconds = 30;

    print_packet(test_enc_packet);
    memmove((char *)test_msg, &test_enc_packet, sizeof(packet_t));
    encrypt_buf(&pub_key, &montg_domain, test_msg, sizeof(test_msg), out_enc, sizeof(out_enc));

    packet_t test_dec_packet;
    decrypt_buf(&pvt_key, &montg_domain, out_enc, strlen(out_enc), out_dec, sizeof(out_dec));
    memmove(&test_dec_packet, out_dec, sizeof(packet_t));
    
    print_packet(test_dec_packet);
    puts(strcmp(test_msg, out_dec) == 0 ? "Работает" : "Увы");

    return 0;
}

void print_packet(packet_t packet) {
    printf("%u) %02u:%02u:%02u\n", packet.plc_number, packet.time.hours, packet.time.minutes, packet.time.seconds);
}