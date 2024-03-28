#include "gtest/gtest.h"
#include <cstdint>

extern "C" {
#include "asn1.h"
}

TEST(Asn1Test, GetLenTestSizeLessOneByte) {
    const uint8_t buff[] = {0x03};
    const size_t res = 0x03;

    ASSERT_EQ(asn1_get_len(buff), res);
}

TEST(Asn1Test, GetLenTestSizeMoreOneByte) {
    const uint8_t buff[] = {0x82, 0x01, 0x01};
    const size_t res = 0x0101;

    ASSERT_EQ(asn1_get_len(buff), res);
}

TEST(Asn1Test, ReadIntWithSizeLessOneByte) {
    const uint8_t buff[] = {0x02, 0x03, 0x01, 0x00, 0x01};
    const uint8_t res[] = {0x01, 0x00, 0x01};

    const uint8_t *int_ptr;
    size_t int_size;
    asn1_get_int(buff, &int_ptr, &int_size);

    ASSERT_EQ(int_size, sizeof(res));
    for (size_t i = 0; i < int_size; i++) {
        ASSERT_EQ(int_ptr[i], res[i]);
    }
}