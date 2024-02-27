#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "bignum.h"
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

int main() {
    rsa_pub_key_t pub_key;
    char *pub_data =
        "-----BEGIN PUBLIC KEY-----\r\n"
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOIkleXcUNZTiBRuAxYU6dCEKJLW6ZET"
        "FE81NUIVffzm+E75/mKGSkpgmb5KamsNo7SEgEAdKro0RkZZ0ia4Rc8CAwEAAQ=="
        "-----END PUBLIC KEY-----\r\n";
    import_pub_key(&pub_key, pub_data);

    rsa_pvt_key_t pvt_key;
    char *pvt_data =
        "-----BEGIN PRIVATE KEY-----\r\n"
        "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA4iSV5dxQ1lOIFG4D"
        "FhTp0IQoktbpkRMUTzU1QhV9/Ob4Tvn+YoZKSmCZvkpqaw2jtISAQB0qujRGRlnS"
        "JrhFzwIDAQABAkEApRBHSYxShN5byW2zWv7Q255bbzLnMTlX7ajMwvulBl7ArgD+"
        "mjD30CzkN3C5m3MEuqC4Yz+/C3AgndnCRWrCIQIhAP8b2kDrrxXf9oloIKVHs85Q"
        "Trjxuh8VINHPWZIc+lWrAiEA4u7UEKH6G6RsDXHmoj6ekZwYOLJKSY6Em/h53BMB"
        "ZG0CIDtkpqmatYaoP+O5xG/2g5wzAkD4tlZqOtveJIJqELZFAiEAy029bN1ALW2D"
        "ZBQr1CSXeMnIJVsNFJL6mKTlv1TDhY0CIBFMJL5vaKTx5TSEEZPRB/NmbeV7joIq"
        "GLq7YHwu01m2"
        "-----END PRIVATE KEY-----\r\n";
    import_pvt_key(&pvt_key, pvt_data);

    const char test_msg[BN_MSG_LEN + 1];
    char out_enc[BN_BYTE_SIZE * 2 + 1], out_dec[BN_MSG_LEN + 1];
    size_t out_enc_len = sizeof(out_enc), out_dec_len = sizeof(out_dec);

    packet_t test_enc_packet;
    test_enc_packet.plc_number = 21;
    test_enc_packet.time.hours = 10;
    test_enc_packet.time.minutes = 20;
    test_enc_packet.time.seconds = 30;

    printf("%d) %02d:%02d:%02d\n", test_enc_packet.plc_number, test_enc_packet.time.hours, test_enc_packet.time.minutes, test_enc_packet.time.seconds);
    memcpy((char *)test_msg, &test_enc_packet, sizeof(packet_t));

    puts("encrypt");
    clock_t start_encrypt = clock();
    encrypt_buf(&pub_key, test_msg, sizeof(test_msg), out_enc, out_enc_len);
    clock_t end_encrypt = clock();
    double time_taken_encrypt = ((double)end_encrypt - start_encrypt) / CLOCKS_PER_SEC;
    printf("time: %lf\n", time_taken_encrypt);
    puts(out_enc);
    puts("");

    puts("decrypt");
    clock_t start_decrypt = clock();
    decrypt_buf(&pvt_key, out_enc, out_enc_len, out_dec, out_dec_len);
    clock_t end_decrypt = clock();
    double time_taken_decrypt = ((double)end_decrypt - start_decrypt) / CLOCKS_PER_SEC;
    printf("time: %lf\n", time_taken_decrypt);
    // puts(out_dec);

    packet_t test_dec_packet;
    memcpy(&test_dec_packet, out_dec, sizeof(packet_t));

    printf("%d) %02d:%02d:%02d\n", test_dec_packet.plc_number, test_dec_packet.time.hours, test_dec_packet.time.minutes, test_dec_packet.time.seconds);

    puts(strcmp(test_msg, out_dec) == 0 ? "Работает" : "Увы");

    return 0;
}