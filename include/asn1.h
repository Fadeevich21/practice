#ifndef ASN1_H
#define ASN1_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    ASN1_INTEGER = 0x02,
    ASN1_BIT_STRING = 0x03,
    ASN1_OCTET_STRING = 0x04,
    ASN1_NULL = 0x05,
    ASN1_OBJECT_IDENTIFIER = 0x06,
    ASN1_UTF8_STRING = 0x0C,
    ASN1_SEQUENCE = 0x30,
    ASN1_SET = 0x31,
    ASN1_PRINTABLE_STRING = 0x13,
    ASN1_IA5_STRING = 0x16,
    ASN1_UTC_TIME = 0x17,
    ASN1_GENERALIZED_TIME = 0x18
} asn1_tag;

int asn1_get_int(const uint8_t *buffer, const uint8_t **int_ptr, size_t *bytes);

size_t asn1_get_padding_pub_key(const uint8_t *buffer);
size_t asn1_get_padding_pvt_key(const uint8_t *buffer);

size_t asn1_get_len(const uint8_t *buffer);

#endif // ASN1_H