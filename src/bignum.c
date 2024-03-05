#include "bignum.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static void lshift_one_bit(bignum_t *bignum);
static void rshift_one_bit(bignum_t *bignum);
static void lshift_word(bignum_t *bignum, size_t nwords);
static void rshift_word(bignum_t *bignum, size_t nwords);

static uint8_t bn_is_zero_size(const bignum_t *bignum, size_t size);
static bignum_compare_state bn_cmp_size(const bignum_t *bignum1, const bignum_t *bignum2, size_t size);
static void bn_sub_size(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
static void bn_add_size(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
static void bn_inner_karatsuba(bignum_t *left, const bignum_t *right, const size_t in_bn_size);
static void bn_inner_square(bignum_t *bignum, size_t in_bn_size);

void bn_fill(bignum_t *bignum, size_t offset, BN_DTYPE value, size_t count) {
    memset((*bignum) + offset, value, count * BN_WORD_SIZE);
}

void bn_init(bignum_t *bignum) {
    bn_fill(bignum, 0, 0, BN_ARRAY_SIZE);
}

void bn_assign(bignum_t *bignum_dst, size_t bignum_dst_offset, const bignum_t *bignum_src, size_t bignum_src_offset,
               size_t count) {
    memmove((*bignum_dst) + bignum_dst_offset, (*bignum_src) + bignum_src_offset, count * BN_WORD_SIZE);
}

// TODO: переписать
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
        (*bignum)[j] = tmp;
        ++j;
    }
}

void bn_from_int(bignum_t *bignum, const BN_DTYPE_TMP value) {
    bn_init(bignum);
    (*bignum)[0] = value;
    (*bignum)[1] = value >> (BN_WORD_SIZE * 8);
}

void bn_to_string(const bignum_t *bignum, char *str, size_t nbytes) {
    int j = BN_ARRAY_SIZE - 1; // TODO: поменять тип на size_t
    size_t i = 0;
    while (j >= 0 && nbytes > i + 1) {
        sprintf(&str[i], BN_SPRINTF_FORMAT_STR, (*bignum)[j]);
        i += sizeof(BN_DTYPE_TMP);
        --j;
    }

    str[i] = '\0';
}

void bn_add(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    uint8_t carry = 0;
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        BN_DTYPE_TMP tmp = (BN_DTYPE_TMP)(*bignum1)[i] + (*bignum2)[i] + carry;
        carry = tmp > BN_MAX_VAL;
        (*bignum_res)[i] = tmp & BN_MAX_VAL;
    }
}

void bn_sub(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    if (bn_cmp(bignum1, bignum2) == BN_CMP_SMALLER) {
        return;
    }

    uint8_t borrow = 0;
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        BN_DTYPE_TMP tmp1 = (BN_DTYPE_TMP)(*bignum1)[i] + BN_MAX_VAL + 1;
        BN_DTYPE_TMP tmp2 = (BN_DTYPE_TMP)(*bignum2)[i] + borrow;
        BN_DTYPE_TMP res = tmp1 - tmp2;
        (*bignum_res)[i] = (BN_DTYPE)(res & BN_MAX_VAL);
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
            BN_DTYPE_TMP intermediate = ((BN_DTYPE_TMP)(*bignum1)[i] * (BN_DTYPE_TMP)(*bignum2)[j]);
            bn_from_int(&tmp, intermediate);
            lshift_word(&tmp, i + j);
            bn_add(&tmp, &row, &row);
        }
        bn_add(bignum_res, &row, bignum_res);
    }
}

void bn_karatsuba(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    bn_assign(bignum_res, 0, bignum1, 0, BN_ARRAY_SIZE);
    bn_inner_karatsuba(bignum_res, bignum2, BN_ARRAY_SIZE / 2);
}

static void bn_inner_karatsuba(bignum_t *left, const bignum_t *right, const size_t in_bn_size) {
    if (in_bn_size == 1) {
        bn_from_int(left, (BN_DTYPE_TMP)(*left)[0] * (BN_DTYPE_TMP)(*right)[0]);
        return;
    }
    
    if (bn_is_zero_size(left, in_bn_size) || bn_is_zero_size(right, in_bn_size)) {
        bn_fill(left, 0, 0, in_bn_size << 1);
        return;
    }

    const size_t z_size = 3;
    bignum_t z[z_size];
    bignum_t* z0_ptr = z + 0;
    bignum_t* z1_ptr = z + 1;
    bignum_t* z2_ptr = z + 2;
    memset(z, 0, z_size * BN_BYTE_SIZE);

    const size_t bn_size_shift = in_bn_size >> 1;

    // (L1 + L2)
    bn_add_size((bignum_t*)*left, (bignum_t*)(*left + bn_size_shift), z0_ptr, bn_size_shift);

    // (R1 + R2)
    bn_add_size((bignum_t*)*right, (bignum_t*)(*right + bn_size_shift), z1_ptr, bn_size_shift);

    // (L1 + L2) * (R1 + R2)
    const size_t size = ((*z0_ptr)[bn_size_shift] | (*z1_ptr)[bn_size_shift]) ? in_bn_size : bn_size_shift;
    bn_inner_karatsuba(z0_ptr, z1_ptr, size);

    // Z1 = L1 * R1
    bn_assign(z1_ptr, 0, left, 0, bn_size_shift);
    bn_inner_karatsuba(z1_ptr, right, bn_size_shift);
    bn_sub_size(z0_ptr, z1_ptr, z0_ptr, in_bn_size << 1);

    // Z2 = L2 * R2
    bn_assign(z2_ptr, 0, left, bn_size_shift, bn_size_shift);
    bn_inner_karatsuba(z2_ptr, (bignum_t*)(*(bignum_t *)right + bn_size_shift), bn_size_shift);
    bn_sub_size(z0_ptr, z2_ptr, z0_ptr, in_bn_size << 1);

    // Result Z2 + Z1 + Z0 (shift adjusted)
    bn_assign(z1_ptr, in_bn_size, z2_ptr, 0, in_bn_size);
    bn_fill(z2_ptr, 0, 0, bn_size_shift);
    bn_assign(z2_ptr, bn_size_shift, z0_ptr, 0, in_bn_size + 1);
    bn_add_size(z1_ptr, z2_ptr, z1_ptr, in_bn_size << 1);

    bn_assign(left, 0, z1_ptr, 0, in_bn_size << 1);
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
        if (denom[BN_ARRAY_SIZE - 1] >= half_max) {
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
    bn_karatsuba(bignum_div, bignum2, &tmp);
    bn_sub(bignum1, &tmp, bignum_mod);
}

void bn_and(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        (*bignum_res)[i] = (*bignum1)[i] & (*bignum2)[i];
    }
}

void bn_or(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        (*bignum_res)[i] = (*bignum1)[i] | (*bignum2)[i];
    }
}

void bn_xor(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res) {
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        (*bignum_res)[i] = (*bignum1)[i] ^ (*bignum2)[i];
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
            (*bignum_res)[i] =
                ((*bignum_res)[i] << nbits) | ((*bignum_res)[i - 1] >> (BN_WORD_SIZE * 8 - nbits));
        }
        (*bignum_res)[i] <<= nbits;
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
            (*bignum_res)[i] =
                ((*bignum_res)[i] >> nbits) | ((*bignum_res)[i + 1] << (BN_WORD_SIZE * 8 - nbits));
        }
        (*bignum_res)[i] >>= nbits;
    }
}

bignum_compare_state bn_cmp(const bignum_t *bignum1, const bignum_t *bignum2) {
    size_t i = BN_ARRAY_SIZE;
    do {
        --i;
        if ((*bignum1)[i] > (*bignum2)[i]) {
            return BN_CMP_LARGER;
        } else if ((*bignum1)[i] < (*bignum2)[i]) {
            return BN_CMP_SMALLER;
        }
    } while (i != 0);

    return BN_CMP_EQUAL;
}

uint8_t bn_is_zero(const bignum_t *bignum) {
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        if ((*bignum)[i]) {
            return 0;
        }
    }

    return 1;
}

void bn_inc(bignum_t *bignum) {
    BN_DTYPE_TMP tmp;
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        tmp = (*bignum)[i];
        (*bignum)[i] = tmp + 1;
        if ((*bignum)[i] > tmp) {
            break;
        }
    }
}

void bn_dec(bignum_t *bignum) {
    BN_DTYPE tmp;
    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        tmp = (*bignum)[i];
        (*bignum)[i] = tmp - 1;
        if ((*bignum)[i] <= tmp) {
            break;
        }
    }
}

static void lshift_one_bit(bignum_t *bignum) {
    for (size_t i = BN_ARRAY_SIZE - 1; i > 0; --i) {
        (*bignum)[i] = ((*bignum)[i] << 1) | ((*bignum)[i - 1] >> (BN_WORD_SIZE * 8 - 1));
    }
    (*bignum)[0] <<= 1;
}

static void rshift_one_bit(bignum_t *bignum) {
    for (size_t i = 0; i < BN_ARRAY_SIZE - 1; ++i) {
        (*bignum)[i] = ((*bignum)[i] >> 1) | ((*bignum)[i + 1] << (BN_WORD_SIZE * 8 - 1));
    }
    (*bignum)[BN_ARRAY_SIZE - 1] >>= 1;
}

static void lshift_word(bignum_t *bignum, size_t nwords) {
    if (nwords >= BN_ARRAY_SIZE) {
        bn_fill(bignum, 0, 0, BN_ARRAY_SIZE);
        return;
    }

    bn_assign(bignum, nwords, bignum, 0, BN_ARRAY_SIZE - nwords);
    bn_fill(bignum, 0, 0, nwords);
}

static void rshift_word(bignum_t *bignum, size_t nwords) {
    if (nwords >= BN_ARRAY_SIZE) {
        bn_fill(bignum, 0, 0, BN_ARRAY_SIZE);
        return;
    }

    bn_assign(bignum, 0, bignum, nwords, BN_ARRAY_SIZE - nwords);
    bn_fill(bignum, BN_ARRAY_SIZE - nwords, 0, nwords);
}

size_t bn_bitcount(const bignum_t *bignum) {
    size_t bits = (BN_BYTE_SIZE << 3) - (BN_WORD_SIZE << 3);
    int i;
    for (i = BN_ARRAY_SIZE - 1; i >= 0 && (*bignum)[i] == 0; --i) {
        bits -= BN_WORD_SIZE << 3;
    }

    for (BN_DTYPE value = (*bignum)[i]; value != 0; value >>= 1) {
        bits++;
    }

    return bits;
}

static void bn_add_size(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    uint8_t carry = 0;
    for (size_t i = 0; i < size; ++i) {
        BN_DTYPE_TMP tmp = (BN_DTYPE_TMP)(*bignum1)[i] + (*bignum2)[i] + carry;
        carry = tmp > BN_MAX_VAL;
        (*bignum_res)[i] = tmp & BN_MAX_VAL;
    }
    (*bignum_res)[size] = carry;
}

void bn_square(const bignum_t *bignum, bignum_t *bignum_res) {
    bn_assign(bignum_res, 0, bignum, 0, BN_ARRAY_SIZE);
    bn_inner_square(bignum_res, BN_ARRAY_SIZE / 2); // TODO: мб размер без '/ 2'
}


// FIXME: не работает
static void bn_inner_square(bignum_t *bignum, size_t in_bn_size) {
    if (in_bn_size == 1) {
        bn_from_int(bignum, (BN_DTYPE_TMP)(*bignum)[0] * (BN_DTYPE_TMP)(*bignum)[0]);
        return;
    }

    bignum_t bignum_ab;
    bn_init(&bignum_ab);

    const size_t bn_size_shift = in_bn_size >> 1;
    bn_assign(bignum, in_bn_size, bignum, bn_size_shift, bn_size_shift);
    bn_fill(bignum, bn_size_shift, 0, bn_size_shift);
    bn_assign(&bignum_ab, 0, bignum, 0, in_bn_size << 1);


    bignum_t bignum_tmp1, bignum_tmp2;
    bn_fill(&bignum_tmp1, 0, 0, BN_ARRAY_SIZE);
    bn_assign(&bignum_tmp1, 0, bignum, 0, bn_size_shift);

    bn_fill(&bignum_tmp2, 0, 0, BN_ARRAY_SIZE);
    bn_assign(&bignum_tmp2, 0, bignum, in_bn_size, bn_size_shift);


    bn_inner_square(&bignum_tmp1, bn_size_shift);
    bn_inner_square(&bignum_tmp2, bn_size_shift);
    bn_inner_karatsuba(&bignum_ab, (bignum_t*)(bignum_ab + in_bn_size), bn_size_shift);

    bn_assign(bignum, 0, &bignum_tmp1, 0, bn_size_shift);
    bn_assign(bignum, in_bn_size, &bignum_tmp2, 0, bn_size_shift);

    bn_fill(&bignum_ab, in_bn_size, 0, bn_size_shift);
    bn_lshift(&bignum_ab, &bignum_ab, (in_bn_size << 2) + 1);
    bn_add(bignum, &bignum_ab, bignum);
}

static void bn_sub_size(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    if (bn_cmp_size(bignum1, bignum2, size) == BN_CMP_SMALLER) {
        return;
    }

    uint8_t borrow = 0;
    for (size_t i = 0; i < size; ++i) {
        BN_DTYPE_TMP tmp1 = (BN_DTYPE_TMP)(*bignum1)[i] + BN_MAX_VAL + 1;
        BN_DTYPE_TMP tmp2 = (BN_DTYPE_TMP)(*bignum2)[i] + borrow;
        BN_DTYPE_TMP res = tmp1 - tmp2;
        (*bignum_res)[i] = (BN_DTYPE)(res & BN_MAX_VAL);
        borrow = res <= BN_MAX_VAL;
    }
}

static bignum_compare_state bn_cmp_size(const bignum_t *bignum1, const bignum_t *bignum2, size_t size) {
    size_t i = size;
    do {
        --i;
        if ((*bignum1)[i] > (*bignum2)[i]) {
            return BN_CMP_LARGER;
        } else if ((*bignum1)[i] < (*bignum2)[i]) {
            return BN_CMP_SMALLER;
        }
    } while (i != 0);

    return BN_CMP_EQUAL;
}

static uint8_t bn_is_zero_size(const bignum_t *bignum, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if ((*bignum)[i]) {
            return 0;
        }
    }

    return 1;
}