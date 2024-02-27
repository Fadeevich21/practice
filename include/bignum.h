#ifndef BIGNUM_H
#define BIGNUM_H

#include <stddef.h>
#include <stdint.h>

#define BN_DTYPE uint32_t
#define BN_DTYPE_TMP uint64_t
#define BN_DTYPE_MSB ((BN_DTYPE_TMP)0x80000000)
#define BN_SPRINTF_FORMAT_STR "%.08x"
#define BN_SSCANF_FORMAT_STR "%8x"
#define BN_MAX_VAL ((BN_DTYPE_TMP)0xFFFFFFFF)
#define BN_WORD_SIZE (sizeof(BN_DTYPE))

#define KEY_SIZE (512) // bits
#define BN_MSG_LEN (KEY_SIZE / 8)
#define BN_BYTE_SIZE (BN_MSG_LEN * 2)

#define BN_ARRAY_SIZE (BN_BYTE_SIZE / BN_WORD_SIZE)

typedef struct {
    BN_DTYPE data[BN_ARRAY_SIZE];
} bignum_t;

typedef enum {
    BN_CMP_SMALLER = -1,
    BN_CMP_EQUAL = 0,
    BN_CMP_LARGER = 1
} bignum_compare_state;

void bn_init(bignum_t *n);
void bn_assign(bignum_t *bignum_dst, size_t bignum_dst_offset, const bignum_t *bignum_src, size_t bignum_src_offset,
               size_t count);
void bn_from_bytes(bignum_t *bignum, const uint8_t *bytes, const size_t nbytes);
void bn_from_string(bignum_t *bignum, const char *str, const size_t nbytes);
void bn_from_int(bignum_t *bignum, const BN_DTYPE_TMP value);

void bn_to_string(const bignum_t *bignum, char *str, const size_t nbytes);

void bn_add(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res);
void bn_sub(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res);
void bn_mul(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res);
void bn_div(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res);
void bn_mod(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res);
void bn_divmod(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_div, bignum_t *bignum_mod);

void bn_and(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res);
void bn_or(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res);
void bn_xor(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res);
void bn_lshift(const bignum_t *bignum, bignum_t *bignum_res, size_t nbits);
void bn_rshift(const bignum_t *bignum, bignum_t *bignum_res, size_t nbits);

bignum_compare_state bn_cmp(const bignum_t *bignum1, const bignum_t *bignum2);
uint8_t bn_is_zero(const bignum_t *bignum);
void bn_inc(bignum_t *bignum);
void bn_dec(bignum_t *bignum);
void bn_fill(bignum_t *bignum, size_t offset, BN_DTYPE value, size_t count);

#endif // BIGNUM_H
