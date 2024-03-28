#include "gtest/gtest.h"

extern "C" {
#include "base64.h"
}

TEST(Base64Test, ReadTestSuccess) {
    const uint8_t base64_enc[] = "SGVsbG8sIFdvcmxkIQpJdCdzIGEgdGVzdCBudW1iZXIgMQ==";
    const uint8_t base64_dec_res[] = "Hello, World!\nIt's a test number 1";

    const size_t dec_size = 64;
    uint8_t base64_dec[dec_size] = "";
    int size = base64_read(base64_enc, strlen((char*)base64_enc), base64_dec, dec_size);

    ASSERT_STREQ((char*)base64_dec, (char*)base64_dec_res);
    ASSERT_EQ(size, 64);
}

TEST(Base64Test, ReadTestError) {
    const uint8_t base64_enc[] = "SGVsbG8sIFdvcmxkIQpJdCdzIGEgdGVzdCBudW1iZXIgMQ==";
    const uint8_t base64_dec_res[] = "Hello, World!\nIt's a test number 1";

    const size_t dec_size = 63;
    uint8_t base64_dec[dec_size] = "";
    int size = base64_read(base64_enc, strlen((char*)base64_enc), base64_dec, dec_size);

    ASSERT_EQ(size, 0);
}