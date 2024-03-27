#include "gtest/gtest.h"

extern "C" {
#include "bignum.h"
}

TEST(BignumTest, Fill) {
    bignum_t b1, b2, b3;
    const size_t offset1 = 0, offset2 = 0, offset3 = BN_ARRAY_SIZE / 2;
    const size_t count1 = BN_ARRAY_SIZE, count2 = BN_ARRAY_SIZE, count3 = BN_ARRAY_SIZE / 2;
    // BN_DTYPE val1 = 0, val2 = BN_MAX_VAL / 2, val3 = BN_MAX_VAL;
    const int val1 = 0, val3 = BN_MAX_VAL;

    bn_memset(&b1, offset1, val1, count1);
    // bn_memset(&b2, offset2, val2, count2);
    bn_memset(&b3, offset3, val3, count3);

    for (size_t i = offset1; i < count1; ++i) {
        ASSERT_EQ(b1[i], val1);
    }
    // for (size_t i = offset2; i < count2; ++i) {
    //     ASSERT_EQ(b2[i], val2);
    // }
    for (size_t i = offset3; i < count3; ++i) {
        ASSERT_EQ(b3[i], val3);
    }

    /*
    bn_memset должен вести себя так же, как и обычный memset -
    преобразовывать int value --> unsigned int value (брать первый байт int'а)
    и заполнять им count байт, поэтому тест для b2 некорректный
    */
}

TEST(BignumTest, Init) {
    bignum_t bignum;

    bn_init(&bignum, BN_ARRAY_SIZE);

    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        ASSERT_EQ(bignum[i], 0);
    }
}

TEST(BignumTest, Assign) {
    bignum_t b1, b2, res;
    const int val1 = 0, val2 = BN_MAX_VAL;
    bn_memset(&b1, 0, val1, BN_ARRAY_SIZE);
    bn_memset(&b2, 0, val2, BN_ARRAY_SIZE);

    bn_assign(&res, 0, &b1, 0, BN_ARRAY_SIZE / 2);
    bn_assign(&res, BN_ARRAY_SIZE / 2, &b2, 0, BN_ARRAY_SIZE / 2);

    for (size_t i = 0; i < BN_ARRAY_SIZE / 2; ++i) {
        ASSERT_EQ(res[i], val1);
    }
    for (size_t i = BN_ARRAY_SIZE / 2; i < BN_ARRAY_SIZE; ++i) {
        ASSERT_EQ(res[i], val2);
    }
}

TEST(BignumTest, FromBytes) {
    bignum_t b1, b2;
    const uint8_t bytes1[] = { 0x00, 0x01, 0x00, 0x01 };
    const uint8_t bytes2[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };

    bn_from_bytes(&b1, bytes1, sizeof(bytes1));
    bn_from_bytes(&b2, bytes2, sizeof(bytes2));

#if BN_WORD_SIZE == 2
    ASSERT_EQ(b1[0], 1);
    ASSERT_EQ(b1[1], 1);
    for (size_t i = 2; i < BN_ARRAY_SIZE; ++i) {
        ASSERT_EQ(b1[i], 0);
    }

    ASSERT_EQ(b2[0], 1);
    ASSERT_EQ(b2[1], 0);
    ASSERT_EQ(b2[2], 1);
    for (size_t i = 3; i < BN_ARRAY_SIZE; ++i) {
        ASSERT_EQ(b2[i], 0);
    }
#elif BN_WORD_SIZE == 4
    ASSERT_EQ(b1[0], 65537);
    for (size_t i = 1; i < BN_ARRAY_SIZE; ++i) {
        ASSERT_EQ(b1[i], 0);
    }

    ASSERT_EQ(b2[0], 1);
    ASSERT_EQ(b2[1], 1);
    for (size_t i = 2; i < BN_ARRAY_SIZE; ++i) {
        ASSERT_EQ(b2[i], 0);
    }
#endif
}

TEST(BignumTest, StringConversions) {
    bignum_t inb1, inb2, outb1, outb2;

    const char in1[BN_BYTE_SIZE * 2 + 1] = "", in2[BN_BYTE_SIZE * 2 + 1] = "e1e2e3e4f1f2f3f4";
    char out1[BN_BYTE_SIZE * 2 + 1] = "", out2[BN_BYTE_SIZE * 2 + 1] = "";

    bn_from_string(&inb1, in1, strlen(in1));
    bn_to_string(&inb1, out1, sizeof(out1));
    bn_from_string(&outb1, out1, strlen(out1));

    bn_from_string(&inb2, in2, strlen(in2));
    bn_to_string(&inb2, out2, sizeof(out2));
    bn_from_string(&outb2, out2, strlen(out2));

    for (size_t i = 0; i < BN_ARRAY_SIZE; ++i) {
        ASSERT_EQ(inb1[i], outb1[i]);
        ASSERT_EQ(inb2[i], outb2[i]);
    }
}

TEST(BignumTest, FromInt) {
    bignum_t b1, b2, b3;
    BN_DTYPE_TMP val1, val2, val3;
    val1 = val2 = val3 = (BN_MAX_VAL << BN_WORD_SIZE * 8) | BN_MAX_VAL;
    const size_t val_size1 = 1, val_size2 = 2, val_size3 = BN_ARRAY_SIZE;

    bn_from_int(&b1, val1, val_size1);
    bn_from_int(&b2, val2, val_size2);
    bn_from_int(&b3, val3, val_size3);

    for (size_t i = 0; i < MIN(val_size1, 2); ++i) {
        ASSERT_EQ(b1[i], (BN_DTYPE)(val1 >> BN_WORD_SIZE * 8 * i));
    }
    for (size_t i = MIN(val_size1, 2); i < val_size1; ++i) {
        ASSERT_EQ(b1[i], 0);
    }
    for (size_t i = 0; i < MIN(val_size2, 2); ++i) {
        ASSERT_EQ(b2[i], (BN_DTYPE)(val2 >> BN_WORD_SIZE * 8 * i));
    }
    for (size_t i = MIN(val_size2, 2); i < val_size2; ++i) {
        ASSERT_EQ(b2[i], 0);
    }
    for (size_t i = 0; i < MIN(val_size3, 2); ++i) {
        ASSERT_EQ(b3[i], (BN_DTYPE)(val3 >> BN_WORD_SIZE * 8 * i));
    }
    for (size_t i = MIN(val_size3, 2); i < val_size3; ++i) {
        ASSERT_EQ(b3[i], 0);
    }
}

TEST(BignumTest, Add) {
    const BN_DTYPE important_val = 1337;
    const size_t bo_size1 = BN_ARRAY_SIZE, bo_size2 = 7;
    bignum_t bo1, bo2;
    bo2[bo_size2] = important_val;
    const bignum_t b1 = { 1234, BN_MAX_VAL, BN_MAX_VAL - 1, BN_MAX_VAL - 1, 0, BN_MAX_VAL, BN_MAX_VAL, 0 };
    const bignum_t b2 = { 5678, 1, 3, 1, 0, BN_MAX_VAL, 0, 0 };
    const bignum_t br = { 6912, 0, 2, 0, 1, BN_MAX_VAL - 1, 0, 1 };

    bn_add(&b1, &b2, &bo1, bo_size1);
    bn_add(&b1, &b2, &bo2, bo_size2);

    for (size_t i = 0; i < bo_size1; ++i) {
        ASSERT_EQ(bo1[i], br[i]);
    }
    for (size_t i = 0; i < bo_size2; ++i) {
        ASSERT_EQ(bo2[i], br[i]);
    }
    ASSERT_EQ(bo2[bo_size2], important_val);
}

TEST(BignumTest, AddCarry) {
    const size_t bo_size1 = 1, bo_size2 = 8;
    const BN_DTYPE removed_val = 1337;
    bignum_t bo1 = {removed_val}, bo2 = {0};
    const bignum_t b1 = { 1234, BN_MAX_VAL, BN_MAX_VAL - 1, BN_MAX_VAL - 1, 0, BN_MAX_VAL, BN_MAX_VAL, BN_MAX_VAL, 0 };
    const bignum_t b2 = { 5678, 1, 3, 1, 0, BN_MAX_VAL, 0, BN_MAX_VAL, 0 };
    const bignum_t br = { 6912, 0, 2, 0, 1, BN_MAX_VAL - 1, 0, 1, 0 };

    bn_add_carry(&b1, &b2, &bo1, bo_size1);
    bn_add_carry(&b1, &b2, &bo2, bo_size2);

    ASSERT_EQ(bo1[0], 0);
    for (size_t i = 0; i <= bo_size2; ++i) {
        ASSERT_EQ(bo2[i], br[i]);
    }
}
