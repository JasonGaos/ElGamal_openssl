#include <iostream>
#include <chrono>
#include <openssl/rand.h>
#include "ec_curve.h"

void run_performance_test() {
    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    std::cout << "Running performance test for secp256r1 (NIST P-256)..." << std::endl;

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

    // Free resources
    EC_POINT_free(pub_key);
    BN_free(priv_key);
    EC_GROUP_free(group);
}

int main() {
    // Initialize OpenSSL
    initialize_openssl();

    // Run performance test
    run_performance_test();

    return 0;
}
