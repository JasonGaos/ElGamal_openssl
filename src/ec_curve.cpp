#include "ec_curve.h"
#include <openssl/rand.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void initialize_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

EC_GROUP* create_group(int curve_nid) {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(curve_nid);
    if (group == nullptr) {
        ERR_print_errors_fp(stderr);
    }
    return group;
}

EC_POINT* multiply_point(const EC_GROUP* group, const EC_POINT* point, const BIGNUM* scalar) {
    EC_POINT *result = EC_POINT_new(group);
    if (EC_POINT_mul(group, result, nullptr, point, scalar, nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        EC_POINT_free(result);
        return nullptr;
    }
    return result;
}

EC_POINT* add_points(const EC_GROUP* group, const EC_POINT* point1, const EC_POINT* point2) {
    EC_POINT *result = EC_POINT_new(group);
    if (EC_POINT_add(group, result, point1, point2, nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        EC_POINT_free(result);
        return nullptr;
    }
    return result;
}

void print_point(const EC_GROUP* group, const EC_POINT* point, PointConversionForm form) {
    point_conversion_form_t openssl_form = (form == COMPRESSED) ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    char *point_str = EC_POINT_point2hex(group, point, openssl_form, nullptr);
    if (point_str != nullptr) {
        std::cout << point_str << std::endl;
        OPENSSL_free(point_str);
    } else {
        ERR_print_errors_fp(stderr);
    }
}

std::vector<unsigned char> ec_point_to_octet_string(const EC_GROUP* group, const EC_POINT* point, PointConversionForm form) {
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        handleErrors();
    }

    point_conversion_form_t openssl_form = (form == COMPRESSED) ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    size_t point_size = EC_POINT_point2oct(group, point, openssl_form, NULL, 0, ctx);
    if (point_size == 0) {
        BN_CTX_free(ctx);
        handleErrors();
    }

    std::vector<unsigned char> buffer(point_size);
    if (EC_POINT_point2oct(group, point, openssl_form, buffer.data(), buffer.size(), ctx) == 0) {
        BN_CTX_free(ctx);
        handleErrors();
    }

    BN_CTX_free(ctx);
    return buffer;
}



EC_POINT* octet_string_to_ec_point(const EC_GROUP* group, const std::vector<unsigned char>& buffer) {
    EC_POINT* point = EC_POINT_new(group);
    if (point == nullptr) {
        handleErrors();
    }

    if (EC_POINT_oct2point(group, point, buffer.data(), buffer.size(), NULL) == 0) {
        EC_POINT_free(point);
        handleErrors();
    }

    return point;
}

std::vector<unsigned char> batch_serialize_ec_points(const EC_GROUP *group, const std::vector<EC_POINT*> &points, PointConversionForm form) {
    std::vector<unsigned char> buffer;
    std::vector<size_t> sizes;

    size_t num_points = points.size();
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&num_points),
                  reinterpret_cast<unsigned char*>(&num_points) + sizeof(size_t));

    for (const auto& point : points) {
        BN_CTX* ctx = BN_CTX_new();
        point_conversion_form_t openssl_form = (form == COMPRESSED) ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
        size_t point_size = EC_POINT_point2oct(group, point, openssl_form, NULL, 0, ctx);
        if (point_size == 0) {
            BN_CTX_free(ctx);
            handleErrors();
        }

        std::vector<unsigned char> point_buffer(point_size);
        if (EC_POINT_point2oct(group, point, openssl_form, point_buffer.data(), point_size, ctx) == 0) {
            BN_CTX_free(ctx);
            handleErrors();
        }

        BN_CTX_free(ctx);
        sizes.push_back(point_size);
        buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&point_size),
                      reinterpret_cast<unsigned char*>(&point_size) + sizeof(size_t));
        buffer.insert(buffer.end(), point_buffer.begin(), point_buffer.end());
    }

    return buffer;
}

std::vector<EC_POINT*> batch_deserialize_ec_points(const EC_GROUP *group, const std::vector<unsigned char>& buffer) {
    const unsigned char* data = buffer.data();
    size_t offset = 0;

    size_t num_points;
    memcpy(&num_points, data + offset, sizeof(size_t));
    offset += sizeof(size_t);

    std::vector<EC_POINT*> points;

    for (size_t i = 0; i < num_points; ++i) {
        size_t point_size;
        memcpy(&point_size, data + offset, sizeof(size_t));
        offset += sizeof(size_t);

        EC_POINT *point = EC_POINT_new(group);
        if (point == NULL) {
            handleErrors();
        }

        if (EC_POINT_oct2point(group, point, data + offset, point_size, NULL) == 0) {
            EC_POINT_free(point);
            handleErrors();
        }
        offset += point_size;

        points.push_back(point);
    }

    return points;
}
