#ifndef EC_ELGAMAL_H
#define EC_ELGAMAL_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include "ec_curve.h"

// ElGamal parameters
struct ElGamalParams {
    EC_GROUP *group;
    const EC_POINT *generator;
};

// ElGamal keys
struct ElGamalKeyPair {
    EC_POINT *public_key;
    BIGNUM *private_key;
};

// ElGamal ciphertext
struct ElGamalCiphertext {
    EC_POINT *C1;
    EC_POINT *C2;
};

// Set up ElGamal parameters
ElGamalParams setup_elgamal(const EC_GROUP* group);

// Generate ElGamal key pair
ElGamalKeyPair generate_keypair(const ElGamalParams &params);

// Encrypt a message
ElGamalCiphertext encrypt(const ElGamalParams &params, const EC_POINT *public_key, const EC_POINT *message);

// Decrypt a ciphertext
EC_POINT* decrypt(const ElGamalParams &params, const BIGNUM *private_key, const ElGamalCiphertext &ciphertext);

// Re-randomization
ElGamalCiphertext elgamal_rerandomize(const EC_GROUP* group, const EC_POINT* pub_key, const ElGamalCiphertext& ciphertext, BN_CTX* ctx);
ElGamalCiphertext elgamal_rerandomize_given_zero(const EC_GROUP* group, const ElGamalCiphertext& ciphertext, const ElGamalCiphertext& zero_ciphertext, BN_CTX* ctx);
// Conversion
std::vector<unsigned char> serialize_elgamal_ciphertext(const EC_GROUP *group, const ElGamalCiphertext &ciphertext);

ElGamalCiphertext deserialize_elgamal_ciphertext(const EC_GROUP *group, const std::vector<unsigned char> &buffer);



#endif // EC_ELGAMAL_H
