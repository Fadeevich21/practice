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

int main() {
    rsa_pub_key_t pub_key;
    char *pub_data =
"-----BEGIN PUBLIC KEY-----\r\n"
"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3pYBTtKpxyDYfO0SyWmP"
"U/F+6EKUTpW09r4tlScc1pGhLjeXC6bRhYWpAaznaVdXiSFTKy++O+pxr2J0ZpF+"
"10z9D/CJtzl0KBqAA+ciimJu7ulToXlwGZnsLysKdnj9EsQDA4EezY1iKktFiYe5"
"S0bYtT1Ze7UOksYEM66SlkV8ZIBgYBrSmyqf29QFHJrg5VP5hHQjUePMd889QnQW"
"saXEzwpFQgt+mNVoeiGKbUBB7zYEgXZSY1KgjuqwZ1CN2Sn1CXh/mg3IshtCTI+R"
"6DKvveBqkqom0ezynQ1o3oos1nPKJNV2K8gIJd6jMXTmvixCvVzb2k3bVWsFG+DH"
"Ouq/zewuBOiVM5jZLiTnhUumPFNUc5yyvj4HSmwhmmLbOsmPd6h2Ex+fTIVCQuln"
"Dm91Rsx4h7u/yzgObKOwXGQVGGIk7+1dCbXgMdlTxdwJdX9H1/OMA9s1hQVOCf+V"
"NX1l1i37awLL23WbUD1IZ3V7tuhGCA5pXhRkIXhiFrz4UFPc7iPqX4dFJIWPcuO1"
"XHaMmr8UlVCUeoviC9GbiBJqxINDeHBSTdEEwmqvtWoJDzaUn5LJFBFE2wZBQtog"
"7D2dd8fhMwFHB9cJ6vajnufTOI2zW98grmxb1ZVRLwKEw0AOdpNdaYWuLkBvFMZr"
"c1HDRc24bnN8LNS8C9qBphMCAwEAAQ=="
"-----END PUBLIC KEY-----\r\n";
        // "-----BEGIN PUBLIC KEY-----\r\n"
        // "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOIkleXcUNZTiBRuAxYU6dCEKJLW6ZET"
        // "FE81NUIVffzm+E75/mKGSkpgmb5KamsNo7SEgEAdKro0RkZZ0ia4Rc8CAwEAAQ=="
        // "-----END PUBLIC KEY-----\r\n";
    import_pub_key(&pub_key, pub_data);

    rsa_pvt_key_t pvt_key;
    char *pvt_data =
"-----BEGIN PRIVATE KEY-----\r\n"
"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"
"e+g+BbLBfY4E4fcODbFeYtaiRtHY0MU="
"-----END PRIVATE KEY-----\r\n";
        // "-----BEGIN PRIVATE KEY-----\r\n"
        // "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA4iSV5dxQ1lOIFG4D"
        // "FhTp0IQoktbpkRMUTzU1QhV9/Ob4Tvn+YoZKSmCZvkpqaw2jtISAQB0qujRGRlnS"
        // "JrhFzwIDAQABAkEApRBHSYxShN5byW2zWv7Q255bbzLnMTlX7ajMwvulBl7ArgD+"
        // "mjD30CzkN3C5m3MEuqC4Yz+/C3AgndnCRWrCIQIhAP8b2kDrrxXf9oloIKVHs85Q"
        // "Trjxuh8VINHPWZIc+lWrAiEA4u7UEKH6G6RsDXHmoj6ekZwYOLJKSY6Em/h53BMB"
        // "ZG0CIDtkpqmatYaoP+O5xG/2g5wzAkD4tlZqOtveJIJqELZFAiEAy029bN1ALW2D"
        // "ZBQr1CSXeMnIJVsNFJL6mKTlv1TDhY0CIBFMJL5vaKTx5TSEEZPRB/NmbeV7joIq"
        // "GLq7YHwu01m2"
        // "-----END PRIVATE KEY-----\r\n";
    import_pvt_key(&pvt_key, pvt_data);

    montg_t montg_domain_n, montg_domain_p, montg_domain_q;
    
    montg_init(&montg_domain_n, &pub_key.mod);
    montg_init(&montg_domain_p, &pvt_key.p);
    montg_init(&montg_domain_q, &pvt_key.q);

    const char test_msg[BN_MSG_LEN + 1] = "";
    char out_enc[BN_BYTE_SIZE * 2 + 1] = "", out_dec[BN_MSG_LEN + 1] = "";
    size_t out_enc_len = sizeof(out_enc), out_dec_len = sizeof(out_dec);

    packet_t test_enc_packet;
    test_enc_packet.plc_number = 21;
    test_enc_packet.time.hours = 10;
    test_enc_packet.time.minutes = 20;
    test_enc_packet.time.seconds = 30;

    printf("%u) %02u:%02u:%02u\n", test_enc_packet.plc_number, test_enc_packet.time.hours, test_enc_packet.time.minutes, test_enc_packet.time.seconds);
    memmove((char *)test_msg, &test_enc_packet, sizeof(packet_t));
    encrypt_buf(&pub_key, &montg_domain_n, test_msg, sizeof(test_msg), out_enc, out_enc_len);

    packet_t test_dec_packet;
    decrypt_buf(&pvt_key, &montg_domain_n, &montg_domain_p, &montg_domain_q, out_enc, out_enc_len, out_dec, out_dec_len);
    memmove(&test_dec_packet, out_dec, sizeof(packet_t));
    
    printf("%u) %02u:%02u:%02u\n", test_dec_packet.plc_number, test_dec_packet.time.hours, test_dec_packet.time.minutes, test_dec_packet.time.seconds);
    puts(strcmp(test_msg, out_dec) == 0 ? "Работает" : "Увы");

    return 0;
}