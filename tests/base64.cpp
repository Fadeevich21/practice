#include "gtest/gtest.h"

extern "C" {
#include "base64.h"
}

TEST(Base64Test, ReadTest) {
    const uint8_t base64_enc[] = "SGVsbG8sIFdvcmxkIQpJdCdzIGEgdGVzdCBudW1iZXIgMQ==";
    const uint8_t base64_dec_res[] = "Hello, World!\nIt's a test number 1";

    const size_t dec_size = 2048;
    uint8_t base64_dec[dec_size] = "";
    base64_read(base64_enc, strlen((char*)base64_enc), base64_dec, dec_size);

    ASSERT_STREQ((char*)base64_dec, (char*)base64_dec_res);
}