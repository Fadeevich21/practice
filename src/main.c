#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
        // "-----BEGIN PUBLIC KEY-----\r\n"
        // "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5BOLF0kmmno0zhVVkvbE"
        // "z8CcAqolJM/wCYPBs+SVQymO7N+IrhPn2O2OcBjlTPo/hQG88EFV7RLAiFBp9HeR"
        // "fo3Zu8gJ1vYPPWHeNZaD5gwErAlyMaHcxHDy958BXMfAPQYjFrqCyIPDS3JNjXaA"
        // "Veaxlkegk/Rh4HruNl79wJFS5jLLPClqWrIwjRy7U76OVUt02R2Ye9aPX4IBFhfo"
        // "YuYp1cIDsNARVtTh+tG5adw9V/kV5j3Ayr+2m+1nfFDDfOTxkXxm3LfDJS88wFIY"
        // "PRI6D/0nnH5m02mJt5/Aoox6Io8p+dJKUGL4w/ZAOoUq7HV2AHgjNzsjAWzF1L3v"
        // "/ViVoF8qSVcoC2uJ7CJ+Hhj//9oSMT/74T2RB5tYyRrfmgWr2eKN0rKsEfVSs4b7"
        // "31U5DAxJkikFl6bscnrTIw84aKPfJtPfmdBCRH9jr/KZGoW3Tr7Sjjn1VJmF/4yg"
        // "ErEL6A53LnDRK4Q98rJNo0vfSxb3pFcyEarOnLx+VcBgZY9eYH5E7cm/tYgTMrtd"
        // "wCEWtBnUipy4IIfmtl0V77qdGeuYsXTzUwQkFc+vgEOA3pSmv+VFpgh+q3zxvQDb"
        // "ZWQ5yMuS0g2mEw+dHpp0wKDZt1aQplaMEOmR8YfWTCvRZbettKYtTHxGNII9+SuB"
        // "xd4I5eA8cLvawXI67v5cvt8CAwEAAQ=="
        // "-----END PUBLIC KEY-----\r\n";
        "-----BEGIN PUBLIC KEY-----\r\n"
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOIkleXcUNZTiBRuAxYU6dCEKJLW6ZET"
        "FE81NUIVffzm+E75/mKGSkpgmb5KamsNo7SEgEAdKro0RkZZ0ia4Rc8CAwEAAQ=="
        "-----END PUBLIC KEY-----\r\n";
    import_pub_key(&pub_key, pub_data);

    rsa_pvt_key_t pvt_key;
    char *pvt_data =
        // "-----BEGIN PRIVATE KEY-----\r\n"
        // "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDkE4sXSSaaejTO"
        // "FVWS9sTPwJwCqiUkz/AJg8Gz5JVDKY7s34iuE+fY7Y5wGOVM+j+FAbzwQVXtEsCI"
        // "UGn0d5F+jdm7yAnW9g89Yd41loPmDASsCXIxodzEcPL3nwFcx8A9BiMWuoLIg8NL"
        // "ck2NdoBV5rGWR6CT9GHgeu42Xv3AkVLmMss8KWpasjCNHLtTvo5VS3TZHZh71o9f"
        // "ggEWF+hi5inVwgOw0BFW1OH60blp3D1X+RXmPcDKv7ab7Wd8UMN85PGRfGbct8Ml"
        // "LzzAUhg9EjoP/SecfmbTaYm3n8CijHoijyn50kpQYvjD9kA6hSrsdXYAeCM3OyMB"
        // "bMXUve/9WJWgXypJVygLa4nsIn4eGP//2hIxP/vhPZEHm1jJGt+aBavZ4o3SsqwR"
        // "9VKzhvvfVTkMDEmSKQWXpuxyetMjDzhoo98m09+Z0EJEf2Ov8pkahbdOvtKOOfVU"
        // "mYX/jKASsQvoDncucNErhD3ysk2jS99LFvekVzIRqs6cvH5VwGBlj15gfkTtyb+1"
        // "iBMyu13AIRa0GdSKnLggh+a2XRXvup0Z65ixdPNTBCQVz6+AQ4DelKa/5UWmCH6r"
        // "fPG9ANtlZDnIy5LSDaYTD50emnTAoNm3VpCmVowQ6ZHxh9ZMK9Flt620pi1MfEY0"
        // "gj35K4HF3gjl4Dxwu9rBcjru/ly+3wIDAQABAoICAAIY0pHIWZ303sukDCFCj8o8"
        // "UI9WKAdFLGGy5voFqlWohn3+YJb/XWken81qC2fj48ssfbHi6ayOcbErmW+RazJ7"
        // "ArskenjnYLLv48BamkCEqVM5Ya0RJSLQyiXBzCpoxRWYxaBDF9iDchDIEiVbJzsi"
        // "9ROzpDkYBciTXFNT3yUrxjc8uIpOgkkK93qkqVElPULi1UYVwiF7IPr/7je8yMHb"
        // "lI1VIeGN9KAwh8Sy7Sh8yVeZnJHSlDHB6UMfv8Xwf7ZLQXeNvuvremKelOXa4nwq"
        // "l/T1dFgdABGw30XVQy57ainWEZP0GgN6+Qc4qH+hPgiQ+MtUFo3pVWRIS6Dmxprb"
        // "JGPQ60CU39IcIUYULM3A6RRbr64OjQc/RTn7Nr2FQDLPpe/uVGGiW7YnOSsp69QD"
        // "qVS+oKU0xRUKgsq76Y37hVhLRb7BAUxX5DSkSqAo+Y7s6zrhkFC2S5NSOIy3trlV"
        // "guk2DO6TcZdEzgnjcBqy+rDrhGIvHmotErRt7KKK+qOZX/XMZEX8fU9SfNLseejY"
        // "GpVlllG2pKOLTtkLavIoJ9eikziDOwOgQlsasDs3OIpfFS8k1l49OFvsnEsxPU1O"
        // "FgIxQGcD3GK6kUFzjCvYujg7uDZN6c9S4nu6eBb4FK2tMnH+RObzv0yDlTyFg7bl"
        // "9UG+XGJ3aeg9gT8aCz2hAoIBAQD/7xZuWO6i53V0N5Ev6CK60eAWPLNlmnunJkaY"
        // "BdZ6gkpUczcgyMDjc3E+vvQ9fsI8GuzuuzzrZXvIC/hfSx23ttMWdTHB8awHuvi1"
        // "/DNrJiQRZeg9R7pDD+OBkea8GrDt3aB7olREgbogIHlmuVj78UCqTxglKUPV3NMQ"
        // "wohJXw3Vshg8p9AqdkyZWFQV5Ye5RmsOgMOfNL+L4nAU2YZa+dwuBAy8bnUy5ptp"
        // "cOCmEmgNi1N8Td7VrVeVjmA7uUKCdbBf6Xu+jXr18WEBJ7My1MA1iL4rL7VOe+9c"
        // "a/RSm9P4vqPEpDdgKbDaia+q8z0OR1RTbTYmbDQ3MI2+h/vRAoIBAQDkIp1mbUzd"
        // "t6WcwjFbYvtxLksO7E6YieQpmA88U3Ay9xVQ4rXPL3DaHt8x4o8ZMzdHR8YaFfry"
        // "igynevlD9X1nFjifwrGrzMiZOwUkxssDoIMRcvRmyYrdnPRFqCsEx5eSdENLTN4q"
        // "6uvRXJPPwpa0LASr1Ujax1hdL3Y52DYMnoe6bTxCDifrZjD8ExCy/ocj1/TBbakH"
        // "v7kwP8smTHQkBDKQaxCJg4LgToG+qUGTnyoSabym06H8avhiOIkbN25XdbWB1O/a"
        // "j+rTYyEZV+JTgixbPGPkIAWVgM/eKy8JdlhZPzBM1S3ymtJl9RqvVRkGQsHo/wce"
        // "vOtryWb6w6uvAoIBAQCuzcQKVl+XkHNej11w1SJza0mcppT5PoxaXAA3cTVOs5LF"
        // "H3R1xehI8d5VNuNm5R8RImrVm7k+JjBnMBXSMGH5yrteSWlUyBXxqbiZw8ny0zgr"
        // "UelPgaAskbuYEekAbVKPBKLKDtNzfw97RfLlQI8QdXTvXdpl90tH1O2sMtIXGv8+"
        // "B8gaFZxOhEJJMlUsJ3uOBhS08SmrocF6b4ySEQh9Ns819rokMWWHAI8Bc4FcrJG5"
        // "PoIlEqKyWxTJJ1d/M0fEB1ISEEzel492UAkrWsxAWaN2bRFGOe2hz3BrNajIi3o6"
        // "GSuN8YOJALC0cvoyzrPS/tEPsjYcBCed0mHd0s8hAoIBAQC2juyd9oE4O6mPk+aj"
        // "VsYXgBAYVQlgD5hBoKkwgSSb5BVusL0EmtYX9fRtmvsgE1f89naUkVpLlCUkMMgf"
        // "ledQAvw0/DvpWup7lDs9fscek+fOosrpJga16M+gnj4uiPnF/LuNGmn+thcXZpnx"
        // "+6lVbJQgXYD7ceJIT56wE1DNMF801A0QXvua6B/y197ZHc1O5ZW64+ILjWTIM4SB"
        // "lVSrLaC46LRHFrI4hRpWVGNhmlC0g2Cvr1NFBuTU1KEC4oyt+EfTKW7224vytLTb"
        // "7vPyF40fRWg6OVW+mWG+S5hMXiO850/jbARky3fqlwVPoS1xUSKTLOGpu0w46OY7"
        // "bTGJAoIBABNbDPnlrVIFayHW38abk1vE5xr72UCV9Q0pgzm/P/KQOMKRTpuYWmQr"
        // "tJscdJ9+VfgeOXJ2f1+IxF1xYLNqhykZBRDif0+QCNEJFtSiYKC0HKD4P0AoET84"
        // "p+U/MoTAPUDStsYsc3P18sevCaGxjOEoAmzMZmTe2/2xMfKMawIGUtWB6y+1eQA7"
        // "jitKJGtoAX8JDfY6NOgc4BefyyXryDdG8UU6rImC6sXR+qRDEjc/Ej+4W9X42WIQ"
        // "CTleWMsLLlIFN+RGK8EUxlNqqiyJRa4M3fzhu30OyfiDrvA6rlz0br/qUWu2wASq"
        // "r7dQplWTRGThsQcoIDGpF/a/aEVu1BI="
        // "-----END PRIVATE KEY-----\r\n";
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

    montg_t montg_domain;
    montg_init(&montg_domain, &pub_key.mod);

    const char test_msg[BN_MSG_LEN + 1];
    char out_enc[BN_BYTE_SIZE * 2 + 1], out_dec[BN_MSG_LEN + 1];
    size_t out_enc_len = sizeof(out_enc), out_dec_len = sizeof(out_dec);

    packet_t test_enc_packet;
    test_enc_packet.plc_number = 21;
    test_enc_packet.time.hours = 10;
    test_enc_packet.time.minutes = 20;
    test_enc_packet.time.seconds = 30;

    printf("%d) %02d:%02d:%02d\n", test_enc_packet.plc_number, test_enc_packet.time.hours, test_enc_packet.time.minutes, test_enc_packet.time.seconds);
    memmove((char *)test_msg, &test_enc_packet, sizeof(packet_t));

    puts("encrypt");
    clock_t start_encrypt = clock();
    encrypt_buf(&pub_key, &montg_domain, test_msg, sizeof(test_msg), out_enc, out_enc_len);
    clock_t end_encrypt = clock();
    double time_taken_encrypt = ((double)end_encrypt - start_encrypt) / CLOCKS_PER_SEC;
    printf("time: %lf\n", time_taken_encrypt);
    puts(out_enc);
    puts("");

    puts("decrypt");
    clock_t start_decrypt = clock();
    decrypt_buf(&pvt_key, &montg_domain, out_enc, out_enc_len, out_dec, out_dec_len);
    clock_t end_decrypt = clock();
    double time_taken_decrypt = ((double)end_decrypt - start_decrypt) / CLOCKS_PER_SEC;
    printf("time: %lf\n", time_taken_decrypt);
    // puts(out_dec);

    packet_t test_dec_packet;
    memmove(&test_dec_packet, out_dec, sizeof(packet_t));

    printf("%d) %02d:%02d:%02d\n", test_dec_packet.plc_number, test_dec_packet.time.hours, test_dec_packet.time.minutes, test_dec_packet.time.seconds);

    puts(strcmp(test_msg, out_dec) == 0 ? "Работает" : "Увы");

    return 0;
}