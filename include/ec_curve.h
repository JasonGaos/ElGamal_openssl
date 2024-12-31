#ifndef EC_EXAMPLE_H
#define EC_EXAMPLE_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <string>
#include <vector>
#include <cstring>
#include <iostream>

enum PointConversionForm {
    COMPRESSED,
    UNCOMPRESSED
};

void handleErrors();

// Function to initialize OpenSSL
void initialize_openssl();

// Function to create a new EC_GROUP for the specified curve
EC_GROUP* create_group(int curve_nid);

// Function to perform point multiplication
EC_POINT* multiply_point(const EC_GROUP* group, const EC_POINT* point, const BIGNUM* scalar);

// Function to perform point addition
EC_POINT* add_points(const EC_GROUP* group, const EC_POINT* point1, const EC_POINT* point2);

// Function to print an EC_POINT
void print_point(const EC_GROUP* group, const EC_POINT* point, PointConversionForm form);

// Function to convert EC_POINT to a vector of bytes
std::vector<unsigned char> ec_point_to_octet_string(const EC_GROUP* group, const EC_POINT* point, PointConversionForm form);

// Function to convert a vector of bytes to EC_POINT
EC_POINT* octet_string_to_ec_point(const EC_GROUP* group, const std::vector<unsigned char>& buffer);

// Conversion in batch
std::vector<unsigned char> batch_serialize_ec_points(const EC_GROUP *group, const std::vector<EC_POINT*> &points, PointConversionForm form);
std::vector<EC_POINT*> batch_deserialize_ec_points(const EC_GROUP *group, const std::vector<unsigned char> &buffer);

#endif // EC_EXAMPLE_H
