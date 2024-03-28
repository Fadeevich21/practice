#include "gtest/gtest.h"
#include <stdint.h>

extern "C" {
#include "rsa.h"
#include <string.h>
}

typedef struct {
    uint8_t hours;
    uint8_t minutes;
    uint8_t seconds;
} packet_time_t;

typedef struct {
    uint16_t year;
    uint8_t month;
    uint8_t day;
} packet_date_t;

typedef struct {
    uint32_t plc_number;
    packet_time_t time;
    packet_date_t date;
} packet_t;

class RsaKeyTest : public testing::Test {
protected:
    void SetUp() override {
#if (KEY_SIZE == 512)
        char pub_data[] =
            "-----BEGIN PUBLIC KEY-----"
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOIkleXcUNZTiBRuAxYU6dCEKJLW6ZET"
            "FE81NUIVffzm+E75/mKGSkpgmb5KamsNo7SEgEAdKro0RkZZ0ia4Rc8CAwEAAQ=="
            "-----END PUBLIC KEY-----";

        char pvt_data[] =
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
#elif (KEY_SIZE == 1024)
        char pub_data[] =
        "-----BEGIN PUBLIC KEY-----"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDibMXilRETH48WqBsvERGg6jqr"
        "49YegC11gMx2TI82syTHJ3JforZiKktyRXiKufZE6L4aVOTD2nrKCQ74jb2o2W9h"
        "3CTealASUAHbGXaPYh+wNVoN6vaCPQ7hSIBZKahFIUVfQXY3xUL06BNWSYsCK5/g"
        "dMc2r6N0Evj8EaDsnQIDAQAB"
        "-----END PUBLIC KEY-----";

        char pvt_data[] =
        "-----BEGIN PRIVATE KEY-----"
        "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOJsxeKVERMfjxao"
        "Gy8REaDqOqvj1h6ALXWAzHZMjzazJMcncl+itmIqS3JFeIq59kTovhpU5MPaesoJ"
        "DviNvajZb2HcJN5qUBJQAdsZdo9iH7A1Wg3q9oI9DuFIgFkpqEUhRV9BdjfFQvTo"
        "E1ZJiwIrn+B0xzavo3QS+PwRoOydAgMBAAECgYEAjBVDsFUNRUmHGztR5iKnR2ji"
        "d6nztNcUSNgwpxfimrLmlBgBmM1wDPehycbVNu6qQCPGSUAwcENhKFHGY1w982i6"
        "SHTWgvc0YLkCCLP/jUIQlcyFV5vW+NdAkMGf55DkWGyYkpdRw5PvEWPMdbLEy8i5"
        "vbaBSWLdzU1EUnwZvnkCQQD614OV45h7E0c8BgiVp3EAptJTrZSHqXUeul47BbKd"
        "kORjXaKAHmz2VsARcs+xXh/w1CO5yTZmwF2HClNZp30PAkEA5xS5CoUpG4Bgd4KJ"
        "JevGhSVsl5FMdsTlU8/YkNcXB3a/AEuGqL34J/GDp5PTVmHaZ0+uO3wTek3aiImt"
        "bRQTkwJBANyohu1s9+6Uh95qZFTZpdNv7KeFk5o/XHL6ePgsy/JFylMKxG811J5i"
        "s7TlrYSWizx8MS02rq922w926tl8N8sCQDqBm6wXNOY6pbH8gd7xCC1T4V+qsRJt"
        "HacPu8RIQRNptEhN1wVIO9lZI709B0gatGJt4S48Zu4TYh4pxZgVejMCQQDoa4/7"
        "MJ80Lc2j7ImLWaaZaDCRojJDSi7b39Dq6RSN+XIK7uiVbDjXz7HziUMTcpvQi7fd"
        "sBS1ndZPpzoFueAO"
        "-----END PRIVATE KEY-----";
#elif (KEY_SIZE == 2048)
        char pub_data[] = 
        "-----BEGIN PUBLIC KEY-----"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtxF6i699W2SCyIm8iEBU"
        "Sdn7gtql5fWUWK3jLEgPpyHPrnMgW+Rysb8xnjWpAXsgDv1vJfqVgjHJ4liarK8I"
        "43e0mpS/jzJw6ocYGM+9caudKWCYbYU0pV4Zc/zu8SOkzgp1jsCyW67im0OGz7g7"
        "rj+Fkp2S7HdDDnOk4P4vNlfhZ+wtzBGpIvFUzPgr3Vixufun+dL4eUnXlw66KMFU"
        "Zgy5TaqYPMOi3kfS66g6XZg1NVLtpPd+68X1FpxxUraAv1668v6Y8YkskvkgCSZ1"
        "3jEVKzXtDI6dIjtXZBY/reVK9KUXOSbBoRL++n+pbvW63jPK7Vp9F+J+kPewdk0Q"
        "bwIDAQAB"
        "-----END PUBLIC KEY-----";

        char pvt_data[] =
        "-----BEGIN PRIVATE KEY-----"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3EXqLr31bZILI"
        "ibyIQFRJ2fuC2qXl9ZRYreMsSA+nIc+ucyBb5HKxvzGeNakBeyAO/W8l+pWCMcni"
        "WJqsrwjjd7SalL+PMnDqhxgYz71xq50pYJhthTSlXhlz/O7xI6TOCnWOwLJbruKb"
        "Q4bPuDuuP4WSnZLsd0MOc6Tg/i82V+Fn7C3MEaki8VTM+CvdWLG5+6f50vh5SdeX"
        "DroowVRmDLlNqpg8w6LeR9LrqDpdmDU1Uu2k937rxfUWnHFStoC/Xrry/pjxiSyS"
        "+SAJJnXeMRUrNe0Mjp0iO1dkFj+t5Ur0pRc5JsGhEv76f6lu9breM8rtWn0X4n6Q"
        "97B2TRBvAgMBAAECggEAA/1q49QPP5Yttz551Khi1wvJjHPpWwHHR7WB7YI2jtYs"
        "UGAaZzriL6COW1wpnAXeK8oJiZ4CTpsLVXGj7MxIGPR9utWdicPuvjphY7YwhVE0"
        "kC5ftBmnMd8w8Yn/7AnynzohRe2TXrhSIHaZX8xQ64fNCIrL7i5vh1ma42lSPodt"
        "oZ01sMMcOGQ2+bLm2MGV8EAGxaakCWYODh9aM60tUGuTeV428rk7+aoL3loP1v31"
        "hl8+n16b5VoftBRjiXtBI0yeu0S1MKToxu/QL7zK2lfJTWP0YmGKJ2oPy+5quFFn"
        "AvOW3ZOEjGmNA8bM1QPuQjMO7KOR2aWaxHf3jf9bxQKBgQDm+TNH4A/C7iNkd6Xh"
        "DrWETB82+12gq84c7VCgugh7nmkb+8s8c624EDzn7EC8CqptXKmlTLwW8OYXwvMo"
        "rlaSZgh1c5AMp6eZ3nypHnpq3r3+goGOMOTPolEIKobwbIargHHGW8094uCMJ07e"
        "ImAtRBru+33O3rCiSeXmGdTKPQKBgQDK53kNNAdA651d1/YixdrHm0NTkahdCBY+"
        "agtDLKW/fc305RypVnnJqoNxMV6tT2SkuPdzvEntW3ytmmnrP+4JXTvXwQ1z8LX1"
        "TrHaH1sRQmQ2VnHQuOGc4t+1yENQ3V1cRR9daA3E1yfjIPUAo7FMCGSSuIk9Ve4t"
        "47kU8FJsGwKBgBxx3i3g2zAPcc5iqcwQqqwTT9jOlhY+clC/rSlOH9NRi/JFTR8x"
        "w9giL84EG2jNC3YSblYMIDHXEw8kFBwTdFftNud4Bup4Dzz02HdfaIYWzmE0o03m"
        "mZc0jzQpQJsFUoR2egyKq7kOYsb/5EeZBi0s8QAzeqfqZuhln2l6DumlAoGBAIX9"
        "YZT0fK3EagEksie4XIdf4o/3KiV1R6sjwBg2DaZs32sPOWQh9P7VmUNQhOMSALY+"
        "ZzqIZpFVzvmddMCjUP/iD7ikhcvAc4hw1UXjWvIE08SGRVa+IE7IC08x1jI6XIKo"
        "KtQ1+JG6O17jzqcDcftxt2ikcAyPCGBJd1l6chNtAoGBAK2fPKQR5AIPZQyqmmSj"
        "argo2rIALY3lvu6mJShZrXtMcYJj3TSr/KV3mugj3NP70lxCGX43Pc0hJZ0fsNBK"
        "TfuXOE5XsTCcM0DNxkAlfwKh4uVwed6eVQPy20MnsEuxgmY3kaZvYjL2VVe7XBgG"
        "9pi7EU+Gmp1XGreG5C6Uo2gw"
        "-----END PRIVATE KEY-----";
#elif (KEY_SIZE == 4096)
        char pub_data[] = "-----BEGIN PUBLIC KEY-----"
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
        "-----END PUBLIC KEY-----";
        
        char pvt_data[] = "-----BEGIN PRIVATE KEY-----"
        "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"
        "e+g+BbLBfY4E4fcODbFeYtaiRtHY0MU="
        "-----END PRIVATE KEY-----";
#endif

        import_pub_key(&pub_key, pub_data);
        import_pvt_key(&pvt_key, pvt_data);
        montg_init(&montg_domain, &pub_key.mod);

        test_enc_packet.plc_number = 21;
        test_enc_packet.time.hours = 10;
        test_enc_packet.time.minutes = 20;
        test_enc_packet.time.seconds = 30;
        test_enc_packet.date.year = 2024;
        test_enc_packet.date.month = 3;
        test_enc_packet.date.day = 28;

        memmove((char *)test_msg, &test_enc_packet, sizeof(packet_t));
    }

    rsa_pub_key_t pub_key;
    rsa_pvt_key_t pvt_key;
    montg_t montg_domain;
    const char test_msg[BN_MSG_LEN + 1] = "";
    char out_enc[BN_BYTE_SIZE * 2 + 1] = "", out_dec[BN_MSG_LEN + 1] = "";
    packet_t test_enc_packet;
    packet_t test_dec_packet;
};

TEST_F(RsaKeyTest, CryptAndDecrypt) {
    encrypt_buf(&pub_key, &montg_domain, test_msg, sizeof(test_msg), out_enc, sizeof(out_enc));

    decrypt_buf(&pvt_key, &montg_domain, out_enc, strlen(out_enc), out_dec, sizeof(out_dec));
    memmove(&test_dec_packet, out_dec, sizeof(packet_t));
    
    ASSERT_TRUE(memcmp(&test_enc_packet, &test_dec_packet, sizeof(packet_t)) == 0);
}

TEST_F(RsaKeyTest, SignAndVerify) {
    sign_buf(&pvt_key, &montg_domain, test_msg, sizeof(test_msg), out_enc, sizeof(out_enc));

    verify_buf(&pub_key, &montg_domain, out_enc, strlen(out_enc), out_dec, sizeof(out_dec));
    memmove(&test_dec_packet, out_dec, sizeof(packet_t));
    
    ASSERT_TRUE(memcmp(&test_enc_packet, &test_dec_packet, sizeof(packet_t)) == 0);
}
