#include "ec_elgamal.h"

ElGamalParams setup_elgamal(EC_GROUP* group) {
    return { group };
}

ElGamalKeyPair generate_keypair(const ElGamalParams& params) {
    BIGNUM* priv_key = BN_new();
    if (priv_key == nullptr) {
        handleErrors();
    }

    if (BN_rand(priv_key, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
        handleErrors();
    }

    EC_POINT* pub_key = multiply_point(params.group, EC_GROUP_get0_generator(params.group), priv_key);
    if (pub_key == nullptr) {
        handleErrors();
    }

    return { priv_key, pub_key };
}

ElGamalCiphertext encrypt(const ElGamalParams& params, const EC_POINT* public_key, const EC_POINT* message, PointConversionForm form) {
    BIGNUM* k = BN_new();
    if (k == nullptr) {
        handleErrors();
    }

    if (BN_rand(k, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
        handleErrors();
    }

    EC_POINT* C1 = multiply_point(params.group, EC_GROUP_get0_generator(params.group), k);
    EC_POINT* pk_k = multiply_point(params.group, public_key, k);
    EC_POINT* C2 = add_points(params.group, message, pk_k);

    EC_POINT_free(pk_k);
    BN_free(k);

    return { C1, C2 };
}

EC_POINT* decrypt(const ElGamalParams& params, const BIGNUM* private_key, const ElGamalCiphertext& ciphertext) {
    EC_POINT* priv_C1 = multiply_point(params.group, ciphertext.C1, private_key);
    EC_POINT_invert(params.group, priv_C1, NULL);
    EC_POINT* message = add_points(params.group, ciphertext.C2, priv_C1);

    EC_POINT_free(priv_C1);
    return message;
}

std::vector<unsigned char> serialize_ciphertext(const ElGamalParams& params, const ElGamalCiphertext& ciphertext, PointConversionForm form) {
    std::vector<unsigned char> serialized_C1 = ec_point_to_octet_string(params.group, ciphertext.C1, form);
    std::vector<unsigned char> serialized_C2 = ec_point_to_octet_string(params.group, ciphertext.C2, form);

    // Combine serialized C1 and C2 directly
    std::vector<unsigned char> serialized_data;
    serialized_data.insert(serialized_data.end(), serialized_C1.begin(), serialized_C1.end());
    serialized_data.insert(serialized_data.end(), serialized_C2.begin(), serialized_C2.end());

    return serialized_data;
}


ElGamalCiphertext deserialize_ciphertext(const ElGamalParams& params, const std::vector<unsigned char>& serialized_data, PointConversionForm form) {
    size_t point_size = (form == COMPRESSED) ? 33 : 65;

    // Deserialize C1
    std::vector<unsigned char> serialized_C1(serialized_data.begin(), serialized_data.begin() + point_size);
    EC_POINT* C1 = octet_string_to_ec_point(params.group, serialized_C1);

    // Deserialize C2
    std::vector<unsigned char> serialized_C2(serialized_data.begin() + point_size, serialized_data.begin() + 2 * point_size);
    EC_POINT* C2 = octet_string_to_ec_point(params.group, serialized_C2);

    return { C1, C2 };
}


