#include "internal.h"

int crypto_ecc_gen_keypair(uint8_t prikey[32], uint8_t pubkey[64])
{
	return crypto_ecc_gen_keypair_internal(NID_X9_62_prime256v1, prikey, pubkey);
}

int crypto_ecc_kg(uint8_t k[32], uint8_t r[64])
{
	return crypto_ecc_kg_internal(NID_X9_62_prime256v1, k, r);
}

int crypto_ecc_kp(uint8_t k[32], uint8_t p[64], uint8_t r[64])
{
	return crypto_ecc_kp_internal(NID_X9_62_prime256v1, k, p, r);
}

int crypto_ecc_sign(uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64])
{
	return crypto_ecc_sign_internal(NID_X9_62_prime256v1, prikey, digest, sign);
}

int crypto_ecc_verify(uint8_t pubkey[64], uint8_t digest[32], uint8_t sign[64])
{
	return crypto_ecc_verify_internal(NID_X9_62_prime256v1, pubkey, digest, sign);
}
