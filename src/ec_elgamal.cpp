#include "ec_elgamal.h"
#include <openssl/rand.h>
#include <iostream>

ElGamalParams setup_elgamal(const EC_GROUP* group) {
    ElGamalParams params;
    params.group = const_cast<EC_GROUP*>(group);
    params.generator = EC_GROUP_get0_generator(group); // Ensure the generator is const
    return params;
}

ElGamalKeyPair generate_keypair(const ElGamalParams &params) {
    ElGamalKeyPair keypair;
    keypair.private_key = BN_new();

    // Generate random private key
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(params.group, order, NULL);
    BN_rand_range(keypair.private_key, order);
    BN_free(order);

    // Generate public key
    keypair.public_key = EC_POINT_new(params.group);
    EC_POINT_mul(params.group, keypair.public_key, keypair.private_key, NULL, NULL, NULL);

    return keypair;
}

ElGamalCiphertext encrypt(const ElGamalParams &params, const EC_POINT *public_key, const EC_POINT *message) {
    ElGamalCiphertext ciphertext;

    // Generate random ephemeral key
    BIGNUM *k = BN_new();
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(params.group, order, NULL);
    BN_rand_range(k, order);
    BN_free(order);

    // Compute C1 = generator^k
    ciphertext.C1 = EC_POINT_new(params.group);
    EC_POINT_mul(params.group, ciphertext.C1, k, NULL, NULL, NULL);

    // Compute C2 = message + public_key^k
    ciphertext.C2 = EC_POINT_new(params.group);
    EC_POINT *pk_k = EC_POINT_new(params.group);
    EC_POINT_mul(params.group, pk_k, NULL, public_key, k, NULL);
    EC_POINT_add(params.group, ciphertext.C2, message, pk_k, NULL);

    EC_POINT_free(pk_k);
    BN_free(k);

    return ciphertext;
}

EC_POINT* decrypt(const ElGamalParams &params, const BIGNUM *private_key, const ElGamalCiphertext &ciphertext) {
    EC_POINT *decrypted_message = EC_POINT_new(params.group);

    // Compute C1^private_key
    EC_POINT *C1_sk = EC_POINT_new(params.group);
    EC_POINT_mul(params.group, C1_sk, NULL, ciphertext.C1, private_key, NULL);

    // Compute message = C2 - C1^private_key
    EC_POINT_invert(params.group, C1_sk, NULL);
    EC_POINT_add(params.group, decrypted_message, ciphertext.C2, C1_sk, NULL);

    EC_POINT_free(C1_sk);

    return decrypted_message;
}

ElGamalCiphertext elgamal_rerandomize(const EC_GROUP* group, const EC_POINT* pub_key, const ElGamalCiphertext& ciphertext, BN_CTX* ctx) {
    ElGamalCiphertext new_ciphertext;
    BIGNUM* k = BN_new();
    EC_POINT* new_C1 = EC_POINT_new(group);
    EC_POINT* new_C2 = EC_POINT_new(group);
    EC_POINT* temp = EC_POINT_new(group);

    BN_rand(k, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    EC_POINT_mul(group, new_C1, k, NULL, NULL, ctx); // new_C1 = g^k
    EC_POINT_mul(group, temp, NULL, pub_key, k, ctx); // temp = pk^k

    EC_POINT_add(group, new_C1, new_C1, ciphertext.C1, ctx); // new_C1 = C1 + g^k
    EC_POINT_add(group, new_C2, ciphertext.C2, temp, ctx); // new_C2 = C2 + pk^k

    new_ciphertext.C1 = new_C1;
    new_ciphertext.C2 = new_C2;

    EC_POINT_free(temp);
    BN_free(k);
    return new_ciphertext;
}

ElGamalCiphertext elgamal_rerandomize_given_zero(const EC_GROUP* group, const ElGamalCiphertext& ciphertext, const ElGamalCiphertext& zero_ciphertext, BN_CTX* ctx) {
    ElGamalCiphertext new_ciphertext;
    EC_POINT* new_C1 = EC_POINT_new(group);
    EC_POINT* new_C2 = EC_POINT_new(group);

    EC_POINT_add(group, new_C1, ciphertext.C1, zero_ciphertext.C1, ctx); // new_C1 = C1 + zero_C1
    EC_POINT_add(group, new_C2, ciphertext.C2, zero_ciphertext.C2, ctx); // new_C2 = C2 + zero_C2

    new_ciphertext.C1 = new_C1;
    new_ciphertext.C2 = new_C2;

    return new_ciphertext;
}

std::vector<unsigned char> serialize_elgamal_ciphertext(const EC_GROUP *group, const ElGamalCiphertext &ciphertext) {
    std::vector<unsigned char> buffer;
    
    // Serialize C1
    size_t C1_size = EC_POINT_point2oct(group, ciphertext.C1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (C1_size == 0) {
        handleErrors();
    }
    std::vector<unsigned char> C1_buffer(C1_size);
    if (EC_POINT_point2oct(group, ciphertext.C1, POINT_CONVERSION_UNCOMPRESSED, C1_buffer.data(), C1_size, NULL) == 0) {
        handleErrors();
    }

    // Serialize C2
    size_t C2_size = EC_POINT_point2oct(group, ciphertext.C2, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (C2_size == 0) {
        handleErrors();
    }
    std::vector<unsigned char> C2_buffer(C2_size);
    if (EC_POINT_point2oct(group, ciphertext.C2, POINT_CONVERSION_UNCOMPRESSED, C2_buffer.data(), C2_size, NULL) == 0) {
        handleErrors();
    }

    // Append sizes and buffers to the main buffer
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&C1_size), reinterpret_cast<unsigned char*>(&C1_size) + sizeof(size_t));
    buffer.insert(buffer.end(), C1_buffer.begin(), C1_buffer.end());
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&C2_size), reinterpret_cast<unsigned char*>(&C2_size) + sizeof(size_t));
    buffer.insert(buffer.end(), C2_buffer.begin(), C2_buffer.end());

    return buffer;
}

ElGamalCiphertext deserialize_elgamal_ciphertext(const EC_GROUP *group, const std::vector<unsigned char> &buffer) {
    ElGamalCiphertext ciphertext;
    const unsigned char* data = buffer.data();
    size_t offset = 0;

    // Deserialize C1
    size_t C1_size;
    memcpy(&C1_size, data + offset, sizeof(size_t));
    offset += sizeof(size_t);
    ciphertext.C1 = EC_POINT_new(group);
    if (ciphertext.C1 == NULL) {
        handleErrors();
    }
    if (EC_POINT_oct2point(group, ciphertext.C1, data + offset, C1_size, NULL) == 0) {
        handleErrors();
    }
    offset += C1_size;

    // Deserialize C2
    size_t C2_size;
    memcpy(&C2_size, data + offset, sizeof(size_t));
    offset += sizeof(size_t);
    ciphertext.C2 = EC_POINT_new(group);
    if (ciphertext.C2 == NULL) {
        handleErrors();
    }
    if (EC_POINT_oct2point(group, ciphertext.C2, data + offset, C2_size, NULL) == 0) {
        handleErrors();
    }
    offset += C2_size;

    return ciphertext;
}

