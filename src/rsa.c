#include "rsa.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "base64.h"
#include "bignum.h"
#include "montgomery.h"

static void pow_mod_faster(const bignum_t *bignum_base, const bignum_t *bignum_exp, const bignum_t *bignum_mod, bignum_t *bignum_res) {
    bn_from_int(bignum_res, 1);

    bignum_t x;
    bignum_t y;
    bignum_t tmp;

    bn_assign(&x, 0, bignum_base, 0, BN_ARRAY_SIZE);
    bn_assign(&y, 0, bignum_exp, 0, BN_ARRAY_SIZE);

    while (1) {
        if (y[0] & 1) {
            // bn_karatsuba(bignum_res, &x, &tmp);
            bn_mul(bignum_res, &x, &tmp);
            bn_mod(&tmp, bignum_mod, bignum_res);
        }
        bn_rshift(&y, &tmp, 1);
        bn_assign(&y, 0, &tmp, 0, BN_ARRAY_SIZE);

        if (bn_is_zero(&y)) {
            break;
        }

        // bn_karatsuba(&x, &x, &tmp);
        bn_mul(&x, &x, &tmp);
        bn_mod(&tmp, bignum_mod, &x);
    }
}

void import_pub_key(rsa_pub_key_t *key, const char *data) {
    const char begin[] = "-----BEGIN PUBLIC KEY-----\r\n";
    const char end[] = "-----END PUBLIC KEY-----\r\n";
    size_t in_size = 2048; // FIXME: убрать константу и сделать зависимость от размера ключа
    char pem[in_size];
    strcpy(pem, data);

    size_t beg_size = strlen(begin);
    size_t end_size = strlen(end);
    size_t pem_size = strlen(pem);
    char *beg_pos = strstr(pem, begin);
    size_t beg_idx = beg_pos - pem;
    char *end_pos = strstr(pem, end);
    size_t end_idx = end_pos - pem;

    if (beg_idx == 0 && end_idx == pem_size - end_size) {
        const uint8_t *int_ptr;
        size_t int_size;
        uint8_t *read_ptr;
        size_t read_size;
        uint8_t buffer[in_size];
        memset(buffer, 0, in_size);

        base64_read((uint8_t *)data + beg_size, pem_size - beg_size - end_size, buffer, in_size);

        const size_t key_padding = asn1_get_padding_pub_key(buffer, in_size);
        read_ptr = buffer + key_padding;

        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(&key->mod, int_ptr, int_size);
        read_ptr += read_size;

        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(&key->pub_exp, int_ptr, int_size);
        read_ptr += read_size;
    }
}

void import_pvt_key(rsa_pvt_key_t *key, const char *data) {
    const char begin[] = "-----BEGIN PRIVATE KEY-----\r\n";
    const char end[] = "-----END PRIVATE KEY-----\r\n";
    size_t in_size = 9192; // FIXME: убрать константу и сделать зависимость от размера ключа
    char pem[in_size];
    strcpy(pem, data);

    size_t beg_size = strlen(begin);
    size_t end_size = strlen(end);
    size_t pem_size = strlen(pem);
    char *beg_pos = strstr(pem, begin);
    size_t beg_idx = beg_pos - pem;
    char *end_pos = strstr(pem, end);
    size_t end_idx = end_pos - pem;

    if (!(beg_idx == 0 && end_idx == pem_size - end_size)) {
        return;
    }
    
    const uint8_t *int_ptr;
    size_t int_size;
    uint8_t *read_ptr;
    size_t read_size;
    uint8_t buffer[in_size];
    memset(buffer, 0, in_size);

    base64_read((uint8_t *)data + beg_size, pem_size - beg_size - end_size, buffer, in_size);

    const size_t key_padding = asn1_get_padding_pvt_key(buffer, in_size);
    read_ptr = buffer + key_padding;
    read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
    if (read_size == -1) {
        return;
    }

    bignum_t version;
    bn_from_bytes(&version, int_ptr, int_size);
    if (!bn_is_zero(&version)) {
        return;
    }
    read_ptr += read_size;

    bignum_t *targets[] = {&key->mod, &key->pub_exp, &key->pvt_exp, &key->p, &key->q, &key->exp1, &key->exp2, &key->coeff};
    for (size_t i = 0; i < sizeof(*targets); i++) {
        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(targets[i], int_ptr, int_size);
        read_ptr += read_size;
    }
}

void encrypt(const rsa_pub_key_t *key, const montg_t *montg_domain, const bignum_t *bignum_in, bignum_t *bignum_out) {
    bignum_t bignum_montg_in, bignum_montg_out;

    montg_transform(montg_domain, bignum_in, &bignum_montg_in);
    bn_init(&bignum_montg_out);

    montg_pow(montg_domain, &bignum_montg_in, &key->pub_exp, &bignum_montg_out);
    montg_revert(montg_domain, &bignum_montg_out, bignum_out);
}

void encrypt_buf(const rsa_pub_key_t *key, const montg_t *montg_domain, const char *bignum_in, size_t bignum_in_len, char *bignum_out, size_t bignum_out_len) {
    bignum_t in_bn, out_bn;
    bn_init(&in_bn);
    // out[0] = '\0';

    memmove(in_bn, bignum_in, bignum_in_len * sizeof(uint8_t));
    encrypt(key, montg_domain, &in_bn, &out_bn);
    bn_to_string(&out_bn, bignum_out, bignum_out_len);
}

void decrypt(const rsa_pvt_key_t *key, const montg_t *montg_domain, const bignum_t *bignum_in, bignum_t *bignum_out) {
    bignum_t bignum_montg_in, bignum_montg_out;

    montg_transform(montg_domain, bignum_in, &bignum_montg_in);
    bn_init(&bignum_montg_out);

    montg_pow(montg_domain, &bignum_montg_in, &key->pvt_exp, &bignum_montg_out);
    montg_revert(montg_domain, &bignum_montg_out, bignum_out);
}

void decrypt_buf(const rsa_pvt_key_t *k, const montg_t *montg_domain, const char *bignum_in, size_t bignum_in_len, char *bignum_out, size_t bignum_out_len) {
    bignum_t in_bn, out_bn;
    bn_init(&in_bn);
    // out[0] = '\0';

    bn_from_string(&in_bn, bignum_in, bignum_in_len - 1);
    decrypt(k, montg_domain, &in_bn, &out_bn);
    memmove(bignum_out, out_bn, bignum_out_len * sizeof(uint8_t));
}