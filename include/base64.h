#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>
#include <stdint.h>

int base64_read(const uint8_t *in, const size_t in_size, uint8_t *out, const size_t out_size);

#endif // BASE64_H