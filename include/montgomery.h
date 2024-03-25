#ifndef __MONTGOMERY_H__
#define __MONTGOMERY_H__

#include "bignum.h"

typedef struct montgomery_domain {
    bignum_t mod;
    bignum_t r;
    bignum_t r_inv;
    BN_DTYPE_TMP shift;
    BN_DTYPE_TMP shift_byte_size;
} montg_t;

void montg_init(montg_t *md, const bignum_t *mod);
void montg_transform(const montg_t *md, const bignum_t *val, bignum_t *res);
void montg_revert(const montg_t *md, const bignum_t *val, bignum_t *res);
void montg_mul(const montg_t *md, const bignum_t *lhs, const bignum_t *rhs, bignum_t *res);
void montg_pow(const montg_t *md, const bignum_t *b, const bignum_t *exp, bignum_t *res);

#endif