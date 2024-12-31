#include <iostream>
#include <chrono>
#include <openssl/rand.h>
#include "ec_curve.h"

void ec_performance_test(PointConversionForm form) {
    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    std::string form_str = (form == COMPRESSED) ? "Compressed" : "Uncompressed";
    std::cout << "\nTesting performance for secp256r1 (NIST P-256) with " << form_str << " format...\n";

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

    // Multiply the generator point by the scalar to create a public key
    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    EC_POINT *pub_key = multiply_point(group, generator, priv_key);
    if (pub_key == nullptr) {
        std::cerr << "Failed to multiply point" << std::endl;
        BN_free(priv_key);
        EC_GROUP_free(group);
        return;
    }

    // Measure sizes of serialized points
    std::vector<unsigned char> serialized_point = ec_point_to_octet_string(group, pub_key, form);
    std::cout << "Size of serialized point (" << form_str << "): " << serialized_point.size() << " bytes\n";

    // Performance variables
    size_t iterations = 10000;
    std::chrono::duration<double, std::milli> multiply_duration(0);
    std::chrono::duration<double, std::milli> add_duration(0);
    std::chrono::duration<double, std::milli> serialization_duration(0);
    std::chrono::duration<double, std::milli> deserialization_duration(0);

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

    // Perform serialization iterations
    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::steady_clock::now();
        std::vector<unsigned char> serialized = ec_point_to_octet_string(group, pub_key, form);
        auto end = std::chrono::steady_clock::now();
        serialization_duration += end - start;
    }

    // Perform deserialization iterations
    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::steady_clock::now();
        EC_POINT *deserialized_point = octet_string_to_ec_point(group, serialized_point);
        auto end = std::chrono::steady_clock::now();
        deserialization_duration += end - start;
        EC_POINT_free(deserialized_point);
    }

    // Print results
    std::cout << "Average point multiplication time: " 
              << multiply_duration.count() / iterations << " ms per iteration.\n";
    std::cout << "Average point addition time: " 
              << add_duration.count() / iterations << " ms per iteration.\n";
    std::cout << "Average serialization time (" << form_str << "): " 
              << serialization_duration.count() / iterations << " ms per iteration.\n";
    std::cout << "Average deserialization time (" << form_str << "): " 
              << deserialization_duration.count() / iterations << " ms per iteration.\n";

    // Free resources
    EC_POINT_free(pub_key);
    BN_free(priv_key);
    EC_GROUP_free(group);
}

int main() {
    // Initialize OpenSSL
    initialize_openssl();

    // Test performance for uncompressed format
    ec_performance_test(UNCOMPRESSED);

    // Test performance for compressed format
    ec_performance_test(COMPRESSED);

    return 0;
}
