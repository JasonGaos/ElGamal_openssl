#include <iostream>
#include <chrono>
#include <openssl/rand.h>
#include "ec_curve.h"
#include <vector>

void test_function() {
    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    std::cout << "Testing functionality for secp256r1 (NIST P-256)..." << std::endl;

    // Get the generator point (as const)
    const EC_POINT *generator = EC_GROUP_get0_generator(group);

    // Generate a random 256-bit value (32 bytes)
    unsigned char rand_bytes[32];
    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
        std::cerr << "Failed to generate random bytes" << std::endl;
        EC_GROUP_free(group);
        return;
    }

    // Convert the random bytes to a BIGNUM
    BIGNUM *priv_key = BN_new();
    if (priv_key == nullptr) {
        std::cerr << "Failed to create BIGNUM" << std::endl;
        EC_GROUP_free(group);
        return;
    }

    BN_bin2bn(rand_bytes, sizeof(rand_bytes), priv_key);

    // Multiply the generator point by the scalar (public key)
    EC_POINT *pub_key = multiply_point(group, generator, priv_key);
    if (pub_key == nullptr) {
        std::cerr << "Failed to multiply point" << std::endl;
        BN_free(priv_key);
        EC_GROUP_free(group);
        return;
    }

    // Variables to measure time
    size_t iterations = 10000;
    std::chrono::duration<double, std::milli> multiply_duration(0);
    std::chrono::duration<double, std::milli> add_duration(0);

    // Perform point multiplication iterations
    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::steady_clock::now();
        EC_POINT *temp_point = multiply_point(group, generator, priv_key);
        auto end = std::chrono::steady_clock::now();
        multiply_duration += end - start;
        EC_POINT_free(temp_point);
    }

    // Perform point addition iterations
    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::steady_clock::now();
        EC_POINT *result = add_points(group, pub_key, generator);
        auto end = std::chrono::steady_clock::now();
        add_duration += end - start;
        EC_POINT_free(result);
    }

    // Print the average time for each operation
    std::cout << "Average point multiplication time for secp256r1 (NIST P-256): " 
              << multiply_duration.count() / iterations << " ms" << std::endl;

    std::cout << "Average point addition time for secp256r1 (NIST P-256): " 
              << add_duration.count() / iterations << " ms" << std::endl;



    // 





    // Free resources
    EC_POINT_free(pub_key);
    BN_free(priv_key);
    EC_GROUP_free(group);
}


void test_ec_point_conversion_performance() {
    // Initialize OpenSSL
    initialize_openssl();

    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    // Create a new EC_POINT object
    EC_POINT *point = EC_POINT_new(group);
    if (point == nullptr) {
        handleErrors();
    }

    // Generate a random private key
    BIGNUM *priv_key = BN_new();
    if (priv_key == nullptr) {
        handleErrors();
    }
    if (BN_rand(priv_key, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 0) {
        handleErrors();
    }

    // Calculate the corresponding public key (EC_POINT) from the private key
    if (EC_POINT_mul(group, point, priv_key, NULL, NULL, NULL) == 0) {
        handleErrors();
    }

    // Variables to measure time
    size_t iterations = 10000;
    std::chrono::duration<double, std::milli> serialization_duration(0);
    std::chrono::duration<double, std::milli> deserialization_duration(0);

    // Perform conversion iterations
    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::steady_clock::now();
        std::vector<unsigned char> serialized_point = ec_point_to_octet_string(group, point);
        auto end = std::chrono::steady_clock::now();
        serialization_duration += end - start;

        start = std::chrono::steady_clock::now();
        EC_POINT *deserialized_point = octet_string_to_ec_point(group, serialized_point);
        end = std::chrono::steady_clock::now();
        deserialization_duration += end - start;

        // Clean up the deserialized point
        EC_POINT_free(deserialized_point);
    }

    // Print the average time for each operation
    std::cout << "Average serialization time for secp256r1 (NIST P-256): "
              << serialization_duration.count() / iterations << " ms" << std::endl;

    std::cout << "Average deserialization time for secp256r1 (NIST P-256): "
              << deserialization_duration.count() / iterations << " ms" << std::endl;

    // Clean up
    EC_POINT_free(point);
    EC_GROUP_free(group);
    BN_free(priv_key);
}

#include <iostream>
#include <chrono>
#include "ec_curve.h"

void test_batch_ec_point_conversion_performance() {
    // Initialize OpenSSL
    initialize_openssl();

    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    // Create a vector of EC_POINT objects
    std::vector<EC_POINT*> points;
    size_t num_points = 10000;

    for (size_t i = 0; i < num_points; ++i) {
        EC_POINT *point = EC_POINT_new(group);
        if (point == nullptr) {
            handleErrors();
        }

        BIGNUM *priv_key = BN_new();
        if (priv_key == nullptr) {
            handleErrors();
        }
        if (BN_rand(priv_key, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 0) {
            handleErrors();
        }

        if (EC_POINT_mul(group, point, priv_key, NULL, NULL, NULL) == 0) {
            handleErrors();
        }

        points.push_back(point);
        BN_free(priv_key);
    }

    // Measure batch serialization performance
    auto start = std::chrono::steady_clock::now();
    std::vector<unsigned char> serialized_points = batch_serialize_ec_points(group, points);
    auto end = std::chrono::steady_clock::now();
    auto serialization_duration = std::chrono::duration<double, std::milli>(end - start).count();

    // Measure batch deserialization performance
    start = std::chrono::steady_clock::now();
    std::vector<EC_POINT*> deserialized_points = batch_deserialize_ec_points(group, serialized_points);
    end = std::chrono::steady_clock::now();
    auto deserialization_duration = std::chrono::duration<double, std::milli>(end - start).count();

    // Print the average time for each operation
    std::cout << "Batch serialization time for " << num_points << " points: " 
              << serialization_duration << " ms" << std::endl;

    std::cout << "Batch deserialization time for " << num_points << " points: " 
              << deserialization_duration << " ms" << std::endl;

    // Clean up
    for (auto point : points) {
        EC_POINT_free(point);
    }
    for (auto point : deserialized_points) {
        EC_POINT_free(point);
    }
    EC_GROUP_free(group);
}


void test_ec_point_conversion_performance2() {
    // Initialize OpenSSL
    initialize_openssl();

    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    // Create a vector of EC_POINT objects
    std::vector<EC_POINT*> points;
    size_t num_points = 10000;

    for (size_t i = 0; i < num_points; ++i) {
        EC_POINT *point = EC_POINT_new(group);
        if (point == nullptr) {
            handleErrors();
        }

        BIGNUM *priv_key = BN_new();
        if (priv_key == nullptr) {
            handleErrors();
        }
        if (BN_rand(priv_key, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 0) {
            handleErrors();
        }

        if (EC_POINT_mul(group, point, priv_key, NULL, NULL, NULL) == 0) {
            handleErrors();
        }

        points.push_back(point);
        BN_free(priv_key);
    }

    // Measure batch serialization performance
    auto start = std::chrono::steady_clock::now();
    std::vector<unsigned char> serialized_points = batch_serialize_ec_points(group, points);
    auto end = std::chrono::steady_clock::now();
    auto batch_serialization_duration = std::chrono::duration<double, std::milli>(end - start).count();

    // Measure batch deserialization performance
    start = std::chrono::steady_clock::now();
    std::vector<EC_POINT*> deserialized_points = batch_deserialize_ec_points(group, serialized_points);
    end = std::chrono::steady_clock::now();
    auto batch_deserialization_duration = std::chrono::duration<double, std::milli>(end - start).count();

    // Clean up deserialized points
    for (auto point : deserialized_points) {
        EC_POINT_free(point);
    }
    deserialized_points.clear();

    // Measure one-by-one serialization and deserialization performance
    std::chrono::duration<double, std::milli> one_by_one_serialization_duration(0);
    std::chrono::duration<double, std::milli> one_by_one_deserialization_duration(0);

    for (size_t i = 0; i < num_points; ++i) {
        // One-by-one serialization
        start = std::chrono::steady_clock::now();
        std::vector<unsigned char> serialized_point = ec_point_to_octet_string(group, points[i]);
        end = std::chrono::steady_clock::now();
        one_by_one_serialization_duration += end - start;

        // One-by-one deserialization
        start = std::chrono::steady_clock::now();
        EC_POINT *deserialized_point = octet_string_to_ec_point(group, serialized_point);
        end = std::chrono::steady_clock::now();
        one_by_one_deserialization_duration += end - start;

        // Clean up the deserialized point
        EC_POINT_free(deserialized_point);
    }

    // Print the average time for each operation
    std::cout << "Batch serialization time for " << num_points << " points: " 
              << batch_serialization_duration << " ms" << std::endl;

    std::cout << "Batch deserialization time for " << num_points << " points: " 
              << batch_deserialization_duration << " ms" << std::endl;

    std::cout << "One-by-one serialization time for " << num_points << " points: " 
              << one_by_one_serialization_duration.count() << " ms" << std::endl;

    std::cout << "One-by-one deserialization time for " << num_points << " points: " 
              << one_by_one_deserialization_duration.count() << " ms" << std::endl;

    // Clean up
    for (auto point : points) {
        EC_POINT_free(point);
    }
    EC_GROUP_free(group);
}


int main() {
    // Initialize OpenSSL
    initialize_openssl();

    // Run the test function
    test_function();

    // Run the EC point conversion performance test
    test_ec_point_conversion_performance2();

    // Run the EC point conversion performance test
    test_batch_ec_point_conversion_performance();

    return 0;
}
