#ifndef RSA_H
#define RSA_H

#include "bignum.h"
#include "montgomery.h"
#include <stddef.h>

/**
 * \brief Публичный ключ
 */
typedef struct {
    bignum_t mod;
    bignum_t pub_exp;
} rsa_pub_key_t;

/**
 * \brief Приватный ключ
 */
typedef struct {
    bignum_t mod;
    bignum_t pub_exp;
    bignum_t pvt_exp;
    bignum_t p;
    bignum_t q;
    bignum_t exp1;
    bignum_t exp2;
    bignum_t coeff;
} rsa_pvt_key_t;

void import_pub_key(rsa_pub_key_t *key, const char *data);
void import_pvt_key(rsa_pvt_key_t *key, const char *data);

void encrypt(const rsa_pub_key_t *key, const montg_t *montg_domain_n, const bignum_t *bignum_in, bignum_t *bignum_out);
void encrypt_buf(const rsa_pub_key_t *key, const montg_t *montg_domain_n, const char *buffer_in, size_t buffer_in_len, char *buffer_out, size_t buffer_out_len);
void decrypt(const rsa_pvt_key_t *key, const montg_t *montg_domain_n, const montg_t *montg_domain_p, const montg_t *montg_domain_q, const bignum_t *bignum_in, bignum_t *bignum_out);
void decrypt_buf(const rsa_pvt_key_t *key, const montg_t *montg_domain_n, const montg_t *montg_domain_p, const montg_t *montg_domain_q, const char *buffer_in, size_t buffer_in_len, char *out, size_t buffer_out_len);

#endif // RSA_H