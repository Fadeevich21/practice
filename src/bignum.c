#include "bignum.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void lshift_one_bit(bignum_t *bignum);
static void rshift_one_bit(bignum_t *bignum);
static void lshift_word(bignum_t *bignum, size_t nwords);
static void rshift_word(bignum_t *bignum, size_t nwords);

void bn_fill(bignum_t *bignum, size_t offset, BN_DTYPE value, size_t count) {
    memset(bignum->data + offset, value, count * BN_WORD_SIZE);
}

void bn_init(bignum_t *bignum) {
    bn_fill(bignum, 0, 0, BN_ARRAY_SIZE);
}

void bn_assign(bignum_t *bignum_dst, size_t bignum_dst_offset, const bignum_t *bignum_src, size_t bignum_src_offset,
               size_t count) {
    // memcpy(bignum_dst->data + bignum_dst_offset, bignum_src->data + bignum_src_offset, count * BN_WORD_SIZE);
    memmove(bignum_dst->data + bignum_dst_offset, bignum_src->data + bignum_src_offset, count * BN_WORD_SIZE);
}

void bn_from_bytes(bignum_t *bignum, const uint8_t *bytes, const size_t nbytes) {
    char hex_str[nbytes * 2];
    for (size_t i = 0; i < nbytes; ++i) {
        sprintf(hex_str + i * 2, "%02x", bytes[i]);
    }

    bn_from_string(bignum, hex_str, nbytes * 2);
}

void bn_from_string(bignum_t *bignum, const char *str, const size_t nbytes) {
    bn_init(bignum);

    size_t i = nbytes;
    size_t j = 0;
    while (i > 0) {
        BN_DTYPE tmp = 0;
        i = i > sizeof(BN_DTYPE_TMP) ? i - sizeof(BN_DTYPE_TMP) : 0;
        sscanf(&str[i], BN_SSCANF_FORMAT_STR, &tmp);
        bignum->data[j] = tmp;
        ++j;
    }
}

void bn_from_int(bignum_t *bignum, const BN_DTYPE_TMP value) {
    bn_init(bignum);
    bignum->data[0] = value;
    bignum->data[1] = value >> (BN_WORD_SIZE * 8);
}

void bn_to_string(const bignum_t *bignum, char *str, size_t nbytes) {
    int j = BN_ARRAY_SIZE - 1; // TODO: поменять тип на size_t
    size_t i = 0;
    while (j >= 0 && nbytes > i + 1) {
        sprintf(&str[i], BN_SPRINTF_FORMAT_STR, bignum->data[j]);
        i += sizeof(BN_DTYPE_TMP);
        --j;
    }

    str[i] = '\0';
}

void bn_add(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    uint8_t carry = 0;
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        BN_DTYPE_TMP tmp = (BN_DTYPE_TMP)bignum1->data[i] + bignum2->data[i] + carry;
        carry = tmp > BN_MAX_VAL;
        bignum_res->data[i] = tmp & BN_MAX_VAL;
    }
}

void bn_sub(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    if (bn_cmp(bignum1, bignum2) == BN_CMP_SMALLER) {
        return;
    }

    uint8_t borrow = 0;
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        BN_DTYPE_TMP tmp1 = (BN_DTYPE_TMP)bignum1->data[i] + BN_MAX_VAL + 1;
        BN_DTYPE_TMP tmp2 = (BN_DTYPE_TMP)bignum2->data[i] + borrow;
        BN_DTYPE_TMP res = tmp1 - tmp2;
        bignum_res->data[i] = (BN_DTYPE)(res & BN_MAX_VAL);
        borrow = res <= BN_MAX_VAL;
    }
}

void bn_mul(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    bn_fill(bignum_res, 0, 0, BN_ARRAY_SIZE);
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        bignum_t row;
        bn_init(&row);
        for (size_t j = 0; j < BN_ARRAY_SIZE; ++j) {
            if (i + j >= BN_ARRAY_SIZE) {
                break;
            }

            bignum_t tmp;
            BN_DTYPE_TMP intermediate = ((BN_DTYPE_TMP)bignum1->data[i] * (BN_DTYPE_TMP)bignum2->data[j]);
            bn_from_int(&tmp, intermediate);
            lshift_word(&tmp, i + j);
            bn_add(&tmp, &row, &row);
        }
        bn_add(bignum_res, &row, bignum_res);
    }
}

void bn_div(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    if (bn_is_zero(bignum2)) {
        return;
    }

    bignum_t current;
    bignum_t denom;
    bignum_t tmp;

    bn_from_int(&current, 1);
    bn_assign(&denom, 0, bignum2, 0, BN_ARRAY_SIZE);
    bn_assign(&tmp, 0, bignum1, 0, BN_ARRAY_SIZE);

    uint8_t overflow = 0;
    while (bn_cmp(&denom, bignum1) != BN_CMP_LARGER) {
        const BN_DTYPE_TMP half_max = 1 + (BN_DTYPE_TMP)(BN_MAX_VAL / 2);
        if (denom.data[BN_ARRAY_SIZE - 1] >= half_max) {
            overflow = 1;
            break;
        }
        lshift_one_bit(&current);
        lshift_one_bit(&denom);
    }
    if (!overflow) {
        rshift_one_bit(&denom);
        rshift_one_bit(&current);
    }
    bn_init(bignum_res);

    while (!bn_is_zero(&current)) {
        if (bn_cmp(&tmp, &denom) != BN_CMP_SMALLER) {
            bn_sub(&tmp, &denom, &tmp);
            bn_or(bignum_res, &current, bignum_res);
        }
        rshift_one_bit(&current);
        rshift_one_bit(&denom);
    }
}

void bn_mod(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    if (bn_is_zero(bignum2)) {
        return;
    }

    bignum_t tmp;
    bn_divmod(bignum1, bignum2, &tmp, bignum_res);
}

void bn_divmod(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_div, bignum_t *bignum_mod) {
    if (bn_is_zero(bignum2)) {
        return;
    }

    bignum_t tmp;
    bn_div(bignum1, bignum2, bignum_div);
    bn_mul(bignum_div, bignum2, &tmp);
    bn_sub(bignum1, &tmp, bignum_mod);
}

void bn_and(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        bignum_res->data[i] = bignum1->data[i] & bignum2->data[i];
    }
}

void bn_or(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        bignum_res->data[i] = bignum1->data[i] | bignum2->data[i];
    }
}

void bn_xor(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        bignum_res->data[i] = bignum1->data[i] ^ bignum2->data[i];
    }
}

void bn_lshift(const bignum_t *bignum, bignum_t *bignum_res, size_t nbits) {
    bn_assign(bignum_res, 0, bignum, 0, BN_ARRAY_SIZE);

    const size_t nbits_pr_word = BN_WORD_SIZE * 8;
    size_t nwords = nbits / nbits_pr_word;
    if (nwords != 0) {
        lshift_word(bignum_res, nwords);
        nbits -= nwords * nbits_pr_word;
    }

    if (nbits != 0) {
        size_t i;
        for (i = BN_ARRAY_SIZE - 1; i > 0; --i) {
            bignum_res->data[i] =
                (bignum_res->data[i] << nbits) | (bignum_res->data[i - 1] >> (BN_WORD_SIZE * 8 - nbits));
        }
        bignum_res->data[i] <<= nbits;
    }
}

void bn_rshift(const bignum_t *bignum, bignum_t *bignum_res, size_t nbits) {
    bn_assign(bignum_res, 0, bignum, 0, BN_ARRAY_SIZE);

    const size_t nbits_pr_word = BN_WORD_SIZE * 8;
    size_t nwords = nbits / nbits_pr_word;
    if (nwords != 0) {
        rshift_word(bignum_res, nwords);
        nbits -= nwords * nbits_pr_word;
    }

    if (nbits != 0) {
        size_t i;
        for (i = 0; i < BN_ARRAY_SIZE - 1; ++i) {
            bignum_res->data[i] =
                (bignum_res->data[i] >> nbits) | (bignum_res->data[i + 1] << (BN_WORD_SIZE * 8 - nbits));
        }
        bignum_res->data[i] >>= nbits;
    }
}

bignum_compare_state bn_cmp(const bignum_t *bignum1, const bignum_t *bignum2) {
    size_t i = BN_ARRAY_SIZE;
    do {
        --i;
        if (bignum1->data[i] > bignum2->data[i]) {
            return BN_CMP_LARGER;
        } else if (bignum1->data[i] < bignum2->data[i]) {
            return BN_CMP_SMALLER;
        }
    } while (i != 0);

    return BN_CMP_EQUAL;
}

uint8_t bn_is_zero(const bignum_t *bignum) {
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        if (bignum->data[i]) {
            return 0;
        }
    }

    return 1;
}

void bn_inc(bignum_t *bignum) {
    BN_DTYPE_TMP tmp;
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        tmp = bignum->data[i];
        bignum->data[i] = tmp + 1;
        if (bignum->data[i] > tmp) {
            break;
        }
    }
}

void bn_dec(bignum_t *bignum) {
    BN_DTYPE tmp;
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        tmp = bignum->data[i];
        bignum->data[i] = tmp - 1;
        if (bignum->data[i] <= tmp) {
            break;
        }
    }
}

static void lshift_one_bit(bignum_t *bignum) {
    for (size_t i = BN_ARRAY_SIZE - 1; i > 0; --i) {
        bignum->data[i] = (bignum->data[i] << 1) | (bignum->data[i - 1] >> (BN_WORD_SIZE * 8 - 1));
    }
    bignum->data[0] <<= 1;
}

static void rshift_one_bit(bignum_t *bignum) {
    for (size_t i = 0; i < BN_ARRAY_SIZE - 1; ++i) {
        bignum->data[i] = (bignum->data[i] >> 1) | (bignum->data[i + 1] << (BN_WORD_SIZE * 8 - 1));
    }
    bignum->data[BN_ARRAY_SIZE - 1] >>= 1;
}

static void lshift_word(bignum_t *bignum, size_t nwords) {
    if (nwords >= BN_ARRAY_SIZE) {
        bn_fill(bignum, 0, 0, BN_ARRAY_SIZE);
        return;
    }

    memmove(bignum->data + nwords, bignum->data, (BN_ARRAY_SIZE - nwords) * BN_WORD_SIZE);
    memset(bignum->data, 0, nwords * BN_WORD_SIZE);
}

static void rshift_word(bignum_t *bignum, size_t nwords) {
    if (nwords >= BN_ARRAY_SIZE) {
        bn_fill(bignum, 0, 0, BN_ARRAY_SIZE);
        return;
    }

    memmove(bignum->data, bignum->data + nwords, (BN_ARRAY_SIZE - nwords) * BN_WORD_SIZE);
    memset(bignum->data + (BN_ARRAY_SIZE - nwords), 0, nwords * BN_WORD_SIZE);
}

size_t bn_bitcount(bignum_t *bignum) {
    size_t bits = (BN_BYTE_SIZE << 3) - (BN_WORD_SIZE << 3);
    int i;
    for (i = BN_ARRAY_SIZE - 1; i >= 0 && bignum->data[i] == 0; --i) {
        bits -= BN_WORD_SIZE << 3;
    }

    for (BN_DTYPE value = bignum->data[i]; value != 0; value >>= 1) {
        bits++;
    }

    return bits;
}