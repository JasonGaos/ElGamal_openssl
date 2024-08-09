#include <iostream>
#include <chrono>
#include <openssl/rand.h>
#include "ec_curve.h"
#include "ec_elgamal.h"

ElGamalCiphertext encrypt_timed(const ElGamalParams &params, const EC_POINT *public_key, const EC_POINT *message, double &time_gen_mul, double &time_pub_mul, double &time_add) {
    ElGamalCiphertext ciphertext;

    // Generate random ephemeral key
    unsigned char rand_bytes[32]; // 32 bytes = 256 bits
    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
        std::cerr << "Failed to generate random bytes" << std::endl;
        exit(EXIT_FAILURE);
    }

    BIGNUM *k = BN_new();
    BN_bin2bn(rand_bytes, sizeof(rand_bytes), k);

    // Compute C1 = generator^k
    ciphertext.C1 = EC_POINT_new(params.group);
    auto start_gen_mul = std::chrono::steady_clock::now();
    EC_POINT_mul(params.group, ciphertext.C1, k, NULL, NULL, NULL);
    auto end_gen_mul = std::chrono::steady_clock::now();
    time_gen_mul = std::chrono::duration<double, std::milli>(end_gen_mul - start_gen_mul).count();

    // Compute C2 = message + public_key^k
    ciphertext.C2 = EC_POINT_new(params.group);
    EC_POINT *pk_k = EC_POINT_new(params.group);
    auto start_pub_mul = std::chrono::steady_clock::now();
    EC_POINT_mul(params.group, pk_k, NULL, public_key, k, NULL);
    auto end_pub_mul = std::chrono::steady_clock::now();
    time_pub_mul = std::chrono::duration<double, std::milli>(end_pub_mul - start_pub_mul).count();

    auto start_add = std::chrono::steady_clock::now();
    EC_POINT_add(params.group, ciphertext.C2, message, pk_k, NULL);
    auto end_add = std::chrono::steady_clock::now();
    time_add = std::chrono::duration<double, std::milli>(end_add - start_add).count();

    EC_POINT_free(pk_k);
    BN_free(k);

    return ciphertext;
}

ElGamalKeyPair generate_keypair_timed(const ElGamalParams &params, double &time_keygen) {
    auto start_keygen = std::chrono::steady_clock::now();
    ElGamalKeyPair keypair = generate_keypair(params);
    auto end_keygen = std::chrono::steady_clock::now();
    time_keygen = std::chrono::duration<double, std::milli>(end_keygen - start_keygen).count();
    return keypair;
}

void test_elgamal() {
    // Initialize OpenSSL
    initialize_openssl();

    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    // Set up ElGamal parameters
    ElGamalParams params = setup_elgamal(group);

    // Variables to measure time
    size_t iterations = 10000;
    double total_time_keygen = 0.0;
    std::chrono::duration<double, std::milli> encryption_duration(0);
    std::chrono::duration<double, std::milli> decryption_duration(0);
    double total_time_gen_mul = 0.0, total_time_pub_mul = 0.0, total_time_add = 0.0;

    // Perform key generation iterations
    for (size_t i = 0; i < iterations; ++i) {
        double time_keygen = 0.0;
        ElGamalKeyPair keypair = generate_keypair_timed(params, time_keygen);
        total_time_keygen += time_keygen;

        // Clean up keypair
        EC_POINT_free(keypair.public_key);
        BN_free(keypair.private_key);
    }

    // Generate key pair for encryption and decryption test
    ElGamalKeyPair keypair = generate_keypair(params);

    // Print the generated keys
    std::cout << "Public Key:" << std::endl;
    print_point(params.group, keypair.public_key);

    std::cout << "Private Key:" << std::endl;
    BN_print_fp(stdout, keypair.private_key);
    std::cout << std::endl;

    // Encrypt a message
    EC_POINT *message = EC_POINT_new(params.group);
    EC_POINT_mul(params.group, message, BN_value_one(), NULL, NULL, NULL); // message = generator^1

    std::cout << "Original Message:" << std::endl;
    print_point(params.group, message);

    // Perform encryption iterations
    for (size_t i = 0; i < iterations; ++i) {
        double time_gen_mul = 0.0, time_pub_mul = 0.0, time_add = 0.0;
        auto start = std::chrono::steady_clock::now();
        ElGamalCiphertext ciphertext = encrypt_timed(params, keypair.public_key, message, time_gen_mul, time_pub_mul, time_add);
        auto end = std::chrono::steady_clock::now();
        encryption_duration += end - start;
        total_time_gen_mul += time_gen_mul;
        total_time_pub_mul += time_pub_mul;
        total_time_add += time_add;

        // Perform decryption for the current ciphertext
        start = std::chrono::steady_clock::now();
        EC_POINT *decrypted_message = decrypt(params, keypair.private_key, ciphertext);
        end = std::chrono::steady_clock::now();
        decryption_duration += end - start;

        // Clean up
        EC_POINT_free(decrypted_message);
        EC_POINT_free(ciphertext.C1);
        EC_POINT_free(ciphertext.C2);
    }

    // Print the average time for each operation
    std::cout << "Average key generation time for secp256r1 (NIST P-256): " 
              << total_time_keygen / iterations << " ms" << std::endl;

    std::cout << "Average encryption time for secp256r1 (NIST P-256): " 
              << encryption_duration.count() / iterations << " ms" << std::endl;

    std::cout << "  - Average time for generator point multiplication (C1): " 
              << total_time_gen_mul / iterations << " ms" << std::endl;

    std::cout << "  - Average time for public key multiplication (C2 part): " 
              << total_time_pub_mul / iterations << " ms" << std::endl;

    std::cout << "  - Average time for addition (C2 part): " 
              << total_time_add / iterations << " ms" << std::endl;

    std::cout << "Average decryption time for secp256r1 (NIST P-256): " 
              << decryption_duration.count() / iterations << " ms" << std::endl;

    // Clean up
    EC_POINT_free(message);
    EC_POINT_free(keypair.public_key);
    BN_free(keypair.private_key);
    EC_GROUP_free(params.group);
}

void test_elgamal_ciphertext_conversion_performance() {
    // Initialize OpenSSL
    initialize_openssl();

    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    // Create a random ElGamal ciphertext
    ElGamalCiphertext ciphertext;
    ciphertext.C1 = EC_POINT_new(group);
    ciphertext.C2 = EC_POINT_new(group);
    BIGNUM *priv_key = BN_new();
    if (priv_key == nullptr) {
        handleErrors();
    }
    if (BN_rand(priv_key, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 0) {
        handleErrors();
    }
    if (EC_POINT_mul(group, ciphertext.C1, priv_key, NULL, NULL, NULL) == 0) {
        handleErrors();
    }
    if (EC_POINT_mul(group, ciphertext.C2, priv_key, NULL, NULL, NULL) == 0) {
        handleErrors();
    }

    // Measure serialization and deserialization performance
    size_t iterations = 10000;
    std::chrono::duration<double, std::milli> serialization_duration(0);
    std::chrono::duration<double, std::milli> deserialization_duration(0);
    size_t total_size = 0;

    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::steady_clock::now();
        std::vector<unsigned char> serialized_ciphertext = serialize_elgamal_ciphertext(group, ciphertext);
        auto end = std::chrono::steady_clock::now();
        serialization_duration += end - start;

        // Accumulate total size of the serialized data
        total_size += serialized_ciphertext.size();

        start = std::chrono::steady_clock::now();
        ElGamalCiphertext deserialized_ciphertext = deserialize_elgamal_ciphertext(group, serialized_ciphertext);
        end = std::chrono::steady_clock::now();
        deserialization_duration += end - start;

        // Clean up the deserialized points
        EC_POINT_free(deserialized_ciphertext.C1);
        EC_POINT_free(deserialized_ciphertext.C2);
    }

    // Print the total time and average time for each operation
    std::cout << "Total serialization time for " << iterations << " ElGamal ciphertexts: " 
              << serialization_duration.count() << " ms" << std::endl;

    std::cout << "Total deserialization time for " << iterations << " ElGamal ciphertexts: " 
              << deserialization_duration.count() << " ms" << std::endl;

    // std::cout << "Average serialization time per ElGamal ciphertext: " 
    //           << serialization_duration.count() / iterations << " ms" << std::endl;

    // std::cout << "Average deserialization time per ElGamal ciphertext: " 
    //           << deserialization_duration.count() / iterations << " ms" << std::endl;

    std::cout << "Total size of serialized data for " << iterations << " ElGamal ciphertexts: " 
              << total_size << " bytes" << std::endl;

    // Check the sizes of C1 and C2
    size_t C1_size = EC_POINT_point2oct(group, ciphertext.C1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    size_t C2_size = EC_POINT_point2oct(group, ciphertext.C2, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    std::cout << "Size of a single C1 point: " << C1_size << " bytes" << std::endl;
    std::cout << "Size of a single C2 point: " << C2_size << " bytes" << std::endl;
    std::cout << "Expected size of one serialized ciphertext: " << (C1_size + sizeof(size_t) + C2_size + sizeof(size_t)) << " bytes" << std::endl;

    // Clean up
    EC_POINT_free(ciphertext.C1);
    EC_POINT_free(ciphertext.C2);
    EC_GROUP_free(group);
    BN_free(priv_key);
}

void test_elgamal_ciphertext_rerandomization_performance() {
    // Initialize OpenSSL
    initialize_openssl();

    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    // Create a random ElGamal ciphertext
    ElGamalCiphertext ciphertext;
    ciphertext.C1 = EC_POINT_new(group);
    ciphertext.C2 = EC_POINT_new(group);
    BIGNUM *priv_key = BN_new();
    if (priv_key == nullptr) {
        handleErrors();
    }
    if (BN_rand(priv_key, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 0) {
        handleErrors();
    }
    if (EC_POINT_mul(group, ciphertext.C1, priv_key, NULL, NULL, NULL) == 0) {
        handleErrors();
    }
    if (EC_POINT_mul(group, ciphertext.C2, priv_key, NULL, NULL, NULL) == 0) {
        handleErrors();
    }

    // Measure rerandomization performance
    size_t iterations = 10000;
    std::chrono::duration<double, std::milli> rerandomization_duration(0);

    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::steady_clock::now();
        ElGamalCiphertext rerandomized_ciphertext = elgamal_rerandomize(group, ciphertext.C1, ciphertext, NULL);
        auto end = std::chrono::steady_clock::now();
        rerandomization_duration += end - start;

        // Clean up the rerandomized points
        EC_POINT_free(rerandomized_ciphertext.C1);
        EC_POINT_free(rerandomized_ciphertext.C2);
    }

    // Print the total time and average time for rerandomization
    std::cout << "Total rerandomization time for " << iterations << " ElGamal ciphertexts: " 
              << rerandomization_duration.count() << " ms" << std::endl;

    // std::cout << "Average rerandomization time per ElGamal ciphertext: " 
    //           << rerandomization_duration.count() / iterations << " ms" << std::endl;

    // Clean up
    EC_POINT_free(ciphertext.C1);
    EC_POINT_free(ciphertext.C2);
    EC_GROUP_free(group);
    BN_free(priv_key);
}


void test_elgamal_rerandomize_given_zero_performance() {
    // Initialize OpenSSL
    initialize_openssl();

    // Create a new EC group for the secp256r1 curve
    EC_GROUP *group = create_group(NID_X9_62_prime256v1);
    if (group == nullptr) {
        std::cerr << "Failed to create EC group for curve secp256r1 (NIST P-256)" << std::endl;
        return;
    }

    BN_CTX* ctx = BN_CTX_new();

    // Generate the ElGamal parameters and keypair
    ElGamalParams params = setup_elgamal(group);
    ElGamalKeyPair keypair = generate_keypair(params);

    // Create a random message point
    EC_POINT *message = EC_POINT_new(group);
    if (EC_POINT_mul(group, message, keypair.private_key, NULL, NULL, ctx) == 0) {
        handleErrors();
    }

    // Encrypt the message to create an initial ciphertext
    ElGamalCiphertext ciphertext = encrypt(params, keypair.public_key, message);

    // Measure rerandomization performance
    size_t iterations = 10000;
    std::chrono::duration<double, std::milli> rerandomization_duration(0);
    std::chrono::duration<double, std::milli> zero_generation_duration(0);

    for (size_t i = 0; i < iterations; ++i) {
        // Generate a zero ciphertext for each iteration by encrypting the point at infinity
        EC_POINT *zero_point = EC_POINT_new(group);
        EC_POINT_set_to_infinity(group, zero_point);

        auto start = std::chrono::steady_clock::now();
        ElGamalCiphertext zero_ciphertext = encrypt(params, keypair.public_key, zero_point);
        auto end = std::chrono::steady_clock::now();
        zero_generation_duration += end - start;
        EC_POINT_free(zero_point);

        // Rerandomize the ciphertext using the zero ciphertext
        start = std::chrono::steady_clock::now();
        ElGamalCiphertext rerandomized_ciphertext = elgamal_rerandomize_given_zero(group, ciphertext, zero_ciphertext, ctx);
        end = std::chrono::steady_clock::now();
        rerandomization_duration += end - start;

        // Clean up the zero and rerandomized points
        EC_POINT_free(zero_ciphertext.C1);
        EC_POINT_free(zero_ciphertext.C2);
        EC_POINT_free(rerandomized_ciphertext.C1);
        EC_POINT_free(rerandomized_ciphertext.C2);
    }

    // Print the total time and average time for rerandomization
    std::cout << "Total rerandomization time for " << iterations << " ElGamal ciphertexts: " 
              << rerandomization_duration.count() + zero_generation_duration.count()<< " ms" << std::endl;

    std::cout << "Total rerandomization time for " << iterations << " ElGamal ciphertexts given zero: " 
              << rerandomization_duration.count() << " ms" << std::endl;

    // std::cout << "Average rerandomization time per ElGamal ciphertext given zero: " 
    //           << rerandomization_duration.count() / iterations << " ms" << std::endl;

    std::cout << "Total time to generate zero ciphertexts for " << iterations << " iterations: " 
              << zero_generation_duration.count() << " ms" << std::endl;

    // std::cout << "Average time to generate zero ciphertext per iteration: " 
    //           << zero_generation_duration.count() / iterations << " ms" << std::endl;

    // Clean up
    EC_POINT_free(ciphertext.C1);
    EC_POINT_free(ciphertext.C2);
    EC_POINT_free(keypair.public_key);
    EC_POINT_free(message);
    EC_GROUP_free(group);
    BN_free(keypair.private_key);
    BN_CTX_free(ctx);
}


int main() {

    // Run the ElGamal test function
    test_elgamal();

    // Run the ElGamal ciphertext conversion performance test
    test_elgamal_ciphertext_conversion_performance();

    // Run the ElGamal ciphertext rerandomization performance test
    test_elgamal_ciphertext_rerandomization_performance();

    // Run the ElGamal ciphertext rerandomization given zero performance test
    test_elgamal_rerandomize_given_zero_performance();

    return 0;
}

