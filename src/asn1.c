#include "asn1.h"

/**
 * \brief Получение числа из структуры asn1
 * @param buffer Буффер данных asn1
 * @param int_ptr Указатель на записанное число
 * @param nbytes Размер данных
 * @return
 */
int asn1_get_int(const uint8_t *buffer, const uint8_t **int_ptr, size_t *nbytes) {
    if (buffer[0] != ASN1_INTEGER) {
        return -1;
    }

    size_t int_index = 2 + (buffer[1] & ~0x7F ? buffer[1] & 0x7F : 0);
    size_t data_bytes = asn1_get_len(buffer + 1);

    if (buffer[int_index] == 0 && data_bytes > 1) {
        ++int_index;
        --data_bytes;
    }

    *int_ptr = buffer + int_index;
    *nbytes = data_bytes;

    return *nbytes + int_index;
}

/**
 * \brief Получение отсупа для публичного ключа (нам не нужны некоторые данные и мы их пропускаем)
 * @param buffer Буффер данных asn1
 * @return Отступ
 */
size_t asn1_get_padding_pub_key(const uint8_t *buffer) {
    size_t i = 0;
    if (buffer[i] != ASN1_SEQUENCE) {
        return -1;
    }

    ++i;
    if (buffer[i] & 0x80) {
        i += buffer[i] & 0x7F;
    }
    ++i;

    if (buffer[i] != ASN1_SEQUENCE) {
        return -1;
    }

    ++i;
    i += asn1_get_len(buffer + i) + 1;

    if (buffer[i] != ASN1_BIT_STRING) {
        return -1;
    }

    ++i;
    if (buffer[i] & 0x80) {
        i += buffer[i] & 0x7F;
    }
    i += 2;

    if (buffer[i] != ASN1_SEQUENCE) {
        return -1;
    }

    ++i;
    if (buffer[i] & 0x80) {
        i += buffer[i] & 0x7F;
    }
    ++i;

    return i;
}

/**
 * \brief Получение отступа для приватного ключа (нам не нужны некоторые данные и мы их пропускаем)
 * @param buffer Буффер данных asn1
 * @return Отступ
 */
size_t asn1_get_padding_pvt_key(const uint8_t *buffer) {
    size_t i = 0;
    if (buffer[i] != ASN1_SEQUENCE) {
        return -1;
    }

    ++i;
    if (buffer[i] & 0x80) {
        i += buffer[i] & 0x7F;
    }
    ++i;

    if (buffer[i] != ASN1_INTEGER) {
        return -1;
    }

    ++i;
    i += asn1_get_len(buffer + i) + 1;

    if (buffer[i] != ASN1_SEQUENCE) {
        return -1;
    }

    ++i;
    i += asn1_get_len(buffer + i) + 1;

    if (buffer[i] != ASN1_OCTET_STRING) {
        return -1;
    }

    ++i;
    if (buffer[i] & 0x80) {
        i += buffer[i] & 0x7F;
    }
    ++i;

    if (buffer[i] != ASN1_SEQUENCE) {
        return -1;
    }

    ++i;
    if (buffer[i] & 0x80) {
        i += buffer[i] & 0x7F;
    }
    ++i;

    return i;
}

/**
 * \brief Получение размера данных в структуре asn1, начиная с buffer
 * @param buffer Буффер данных asn1
 * @return Размер данных
 */
size_t asn1_get_len(const uint8_t *buffer) {
    size_t len = buffer[0];
    if (buffer[0] & ~0x7F) {
        len = 0;
        for (size_t i = 1; i <= (buffer[0] & 0x7F); ++i) {
            len = len << 8 | buffer[i];
        }
    }

    return len;
}
