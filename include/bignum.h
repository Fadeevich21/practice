#ifndef BIGNUM_H
#define BIGNUM_H

#include <stddef.h>
#include <stdint.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define BN_WORD_SIZE 4 // bytes

#if (BN_WORD_SIZE == 2)
    #define BN_DTYPE uint16_t
    #define BN_DTYPE_TMP uint32_t
    #define BN_SPRINTF_FORMAT_STR "%.04hx"
    #define BN_SSCANF_FORMAT_STR "%4hx"
    #define BN_MAX_VAL ((BN_DTYPE_TMP)0xFFFF)
#elif (BN_WORD_SIZE == 4)
    #define BN_DTYPE uint32_t
    #define BN_DTYPE_TMP uint64_t
    #define BN_SPRINTF_FORMAT_STR "%.08x"
    #define BN_SSCANF_FORMAT_STR "%8x"
    #define BN_MAX_VAL ((BN_DTYPE_TMP)0xFFFFFFFF)
#endif

#define KEY_SIZE (512) // bits
#define BN_MSG_LEN (KEY_SIZE / 8)
#define BN_BYTE_SIZE (BN_MSG_LEN * 2)

#define BN_ARRAY_SIZE (BN_BYTE_SIZE / BN_WORD_SIZE)

/**
 * \brief Большое число
 */
typedef BN_DTYPE bignum_t[BN_ARRAY_SIZE];

/**
 * \brief Состояния сравнения больших чисел
 */
typedef enum {
    BN_CMP_SMALLER = -1,
    BN_CMP_EQUAL = 0,
    BN_CMP_LARGER = 1,
} bignum_compare_state;

void bn_init(bignum_t *n, size_t size);
void bn_assign(bignum_t *bignum_dst, size_t bignum_dst_offset, const bignum_t *bignum_src, size_t bignum_src_offset,
               size_t count);
void bn_from_bytes(bignum_t *bignum, const uint8_t *bytes, size_t nbytes);
void bn_from_string(bignum_t *bignum, const char *str, size_t nbytes);
void bn_from_int(bignum_t *bignum, BN_DTYPE_TMP value, size_t size);

void bn_to_string(const bignum_t *bignum, char *str, size_t nbytes);

void bn_add(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
void bn_add_carry(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
void bn_sub(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
void bn_karatsuba(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
void bn_div(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
void bn_mod(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
void bn_divmod(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_div, bignum_t *bignum_mod, size_t size);

void bn_or(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size);
size_t bn_bitcount(const bignum_t *bignum);

bignum_compare_state bn_cmp(const bignum_t *bignum1, const bignum_t *bignum2, size_t size);
uint8_t bn_is_zero(const bignum_t *bignum, size_t size);
void bn_fill(bignum_t *bignum, size_t offset, BN_DTYPE value, size_t count);

#endif // BIGNUM_H
