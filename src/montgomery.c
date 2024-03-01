#include "montgomery.h"
#include "bignum.h"
#include <string.h>

// Extended Euclidian algorithm
static void montg_inverse(const bignum_t *val, const bignum_t *mod, bignum_t *res) {
    if (bn_cmp(val, mod) != BN_CMP_SMALLER) {
        return;
    }

    bignum_t n, b, q, r, t1, t3;
    bignum_t *n_ptr = &n, *b_ptr = &b, *q_ptr = &q, *r_ptr = &r, *t1_ptr = &t1, *t3_ptr = &t3;
    bn_assign(&n, 0, mod, 0, BN_ARRAY_SIZE);
    bn_assign(&b, 0, val, 0, BN_ARRAY_SIZE);
    bn_init(&q);
    bn_init(&r);
    bn_init(&t1);
    bn_from_int(res, 1);
    bn_init(&t3);

    bn_divmod(&n, &b, &q, &r);
    // bn_karatsuba(res, &q, &t3);
    bn_mul(res, &q, &t3);

    uint8_t sign = 1;
    while (!bn_is_zero(&r)) {
        bn_assign(&n, 0, &b, 0, BN_ARRAY_SIZE);
        bn_assign(&b, 0, &r, 0, BN_ARRAY_SIZE);
        bn_assign(&t1, 0, res, 0, BN_ARRAY_SIZE);
        bn_assign(res, 0, &t3, 0, BN_ARRAY_SIZE);

        bn_divmod(n_ptr, b_ptr, &q, &r);
        // bn_karatsuba(res, &q, &t3);
        bn_mul(res, &q, &t3);
        bn_add(&t3, &t1, &t3);
        sign = !sign;
    }

    if (!sign) {
        bn_sub(mod, res, res);
    }

    // Если b != 1 в конце, то res не существует. Данная функция не учитывает этот случай.
}

// mod - RSA key mod
void montg_init(montg_t *md, const bignum_t *mod) {
    if (mod == NULL) {
        return;
    }

    md->shift = BN_ARRAY_SIZE / 2;    // 512 для ключа 512 бит - лучше передавать ключ вместо mod для инициализации
    md->shift_byte_size = BN_BYTE_SIZE / 2;

    bn_assign(&md->mod, 0, mod, 0, BN_ARRAY_SIZE);

    bn_init(&md->r);
    md->r[BN_ARRAY_SIZE / 2] = 1;

    bn_sub(&md->r, &md->mod, &md->r_inv);
    montg_inverse(&md->r_inv, &md->r, &md->r_inv);
}

void montg_transform(const montg_t *md, const bignum_t *val, bignum_t *res) {
    bignum_t temp;
    memmove(temp + md->shift, (*val), md->shift_byte_size);
    memset(temp, 0, md->shift_byte_size);
    bn_mod(&temp, &md->mod, res);
}

void montg_revert(const montg_t *md, const bignum_t *val, bignum_t *res) {
    bignum_t one;
    bn_from_int(&one, 1);
    montg_mul(md, val, &one, res);
}

void montg_mul(const montg_t *md, const bignum_t *lhs, const bignum_t *rhs, bignum_t *res) {
    bignum_t m, m_r_inv, t;
    uint8_t overflow = 0;
    // bn_karatsuba(lhs, rhs, &t);
    bn_mul(lhs, rhs, &t);
    bn_assign(res, 0, &t, 0, BN_ARRAY_SIZE);
    bn_assign(&m, 0, res, 0, BN_ARRAY_SIZE);

    memset(m + md->shift, 0, md->shift_byte_size);
    // bn_karatsuba(&m, &md->r_inv, &m_r_inv);
    bn_mul(&m, &md->r_inv, &m_r_inv);
    memset(m_r_inv + md->shift, 0, md->shift_byte_size);

    // bn_karatsuba(&m_r_inv, &md->mod, &m);
    bn_mul(&m_r_inv, &md->mod, &m);
    bn_add(res, &m, res);

    if (bn_cmp(res, &t) == BN_CMP_SMALLER && bn_cmp(res, &m) == BN_CMP_SMALLER) {
        overflow = 1;
    }

    memmove((*res), (*res) + md->shift, md->shift_byte_size);
    memset((*res) + md->shift, 0, md->shift_byte_size);

    if (overflow) {
        (*res)[BN_ARRAY_SIZE / 2] = 1;
    }

    if (bn_cmp(res, &md->mod) != BN_CMP_SMALLER) {
        bn_sub(res, &md->mod, res);
    }
}

void montg_pow(const montg_t *md, const bignum_t *b, const bignum_t *exp, bignum_t *res) {
    bignum_t b_copy;
    bn_assign(&b_copy, 0, b, 0, BN_ARRAY_SIZE);
    
    size_t len = bn_bitcount(exp) - 1;
    uint8_t *end = (uint8_t *)(*exp) + len / 8;
    uint8_t *beg = (uint8_t *)(*exp);
    uint8_t mask = 1 << ((len - 1) & 7);

    if (mask == 128) {
        end--;
    }

    while (end >= beg) {
        montg_mul(md, &b_copy, &b_copy, res);
        bn_assign(&b_copy, 0, res, 0, BN_ARRAY_SIZE);

        if (*end & mask) {
            montg_mul(md, &b_copy, b, res);
            bn_assign(&b_copy, 0, res, 0, BN_ARRAY_SIZE);
        }
        mask >>= 1;
        if (!mask) {
            mask = 128;
            end--;
        }
    }
}
