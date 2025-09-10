#include "internal.h"

int crypto_sm2_gen_keypair(uint8_t prikey[32], uint8_t pubkey[64])
{
	return crypto_ecc_gen_keypair_internal(NID_sm2p256v1, prikey, pubkey);
}

int crypto_sm2_kg(uint8_t k[32], uint8_t r[64])
{
	return crypto_ecc_kg_internal(NID_sm2p256v1, k, r);
}

int crypto_sm2_kp(uint8_t k[32], uint8_t p[64], uint8_t r[64])
{
	return crypto_ecc_kp_internal(NID_sm2p256v1, k, p, r);
}

int crypto_sm2_sign(uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64])
{
	return crypto_ecc_sign_internal(NID_sm2p256v1, prikey, digest, sign);
}

int crypto_sm2_verify(uint8_t pubkey[64], uint8_t digest[32], uint8_t sign[64])
{
	return crypto_ecc_verify_internal(NID_sm2p256v1, pubkey, digest, sign);
}

static int crypto_bin_to_sm2_cipher_der(EVP_PKEY_CTX *ctx, uint8_t *in, uint32_t len, uint8_t *der, size_t *derlen)
{
    const EC_GROUP *group;
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
    group = EC_KEY_get0_group(ec_key);
    
    SM2CiphertextValue *cv = NULL;
    int total_len = 1 + len;
    uint8_t *buf_temp = (uint8_t *)malloc(total_len);
    uint8_t *p = buf_temp;
    
    buf_temp[0] = 0x04;
    memcpy(buf_temp + 1, in, 64);
    memcpy(buf_temp + 65, in + 96, len - 96);
    memcpy(buf_temp + 65 + (len - 96), in + 64, 32);

    cv = o2i_SM2CiphertextValue(group, EVP_sm3(), &cv, (const unsigned char **)&p, total_len);
    crypto_assert(cv != NULL);

    *derlen = i2d_SM2CiphertextValue(cv, &der);
    crypto_assert(*derlen >= 0);

    free(buf_temp);
    SM2CiphertextValue_free(cv);
    return CRYPTO_RET_SUCCESS;
}

static int sm2_cipher_der_to_crypto_bin(EVP_PKEY_CTX *ctx, uint8_t *der, uint32_t der_len, uint8_t *out, uint32_t *outlen)
{
    const EC_GROUP *group;
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
    group = EC_KEY_get0_group(ec_key);

    SM2CiphertextValue *cv = NULL;
    uint8_t *p = der;
    if (!(cv = d2i_SM2CiphertextValue(NULL, (const unsigned char **)&p, (long)der_len)))
        return 0;
    
    uint8_t *buf_temp = (uint8_t *)malloc(der_len);
    p = buf_temp;
    int total_len = i2o_SM2CiphertextValue(group, cv, &p);
    *outlen = total_len - 1;

    memcpy(out, buf_temp + 1, 64);
    memcpy(out + 64, buf_temp + 65 + (total_len - 97), 32);
    memcpy(out + 96, buf_temp + 65, total_len - 97);

    free(buf_temp);
    SM2CiphertextValue_free(cv);
    return CRYPTO_RET_SUCCESS;
}

// ssl-> c1/c2/c3, crypto-> c1/c3/c2
int crypto_sm2_encrypt(uint8_t pubkey[64], uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen)
{
	size_t sm2_cipher_out_len = 256 + inlen;
	uint8_t *sm2_cipher_out = (uint8_t *)malloc(sm2_cipher_out_len);

    EVP_PKEY *pkey = EVP_PKEY_new();
    crypto_assert(crypto_key2pkey(NID_sm2p256v1, NULL, pubkey, pkey) == CRYPTO_RET_SUCCESS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    crypto_assert(EVP_PKEY_encrypt_init(ctx) == 1);
    crypto_assert(EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) == 1);
    crypto_assert(EVP_PKEY_CTX_set_ec_encrypt_param(ctx, NID_sm3) == 1);
    crypto_assert(EVP_PKEY_encrypt(ctx, sm2_cipher_out, &sm2_cipher_out_len, in, (size_t)inlen) == 1);
    crypto_assert(sm2_cipher_der_to_crypto_bin(ctx, sm2_cipher_out, sm2_cipher_out_len, out, outlen) == CRYPTO_RET_SUCCESS);

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
        free(sm2_cipher_out);
	return CRYPTO_RET_SUCCESS;
}

// ssl-> c1/c2/c3, crypto-> c1/c3/c2
int crypto_sm2_decrypt(uint8_t prikey[32], uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen)
{
    size_t tlen = *outlen;
	size_t sm2_cipher_out_len = 256 + inlen;
	uint8_t *sm2_cipher_out = (uint8_t *)malloc(sm2_cipher_out_len);

    EVP_PKEY *pkey = EVP_PKEY_new();
    crypto_assert(crypto_key2pkey(NID_sm2p256v1, prikey, NULL, pkey) == CRYPTO_RET_SUCCESS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    crypto_assert(crypto_bin_to_sm2_cipher_der(ctx, in, inlen, sm2_cipher_out, &sm2_cipher_out_len) == CRYPTO_RET_SUCCESS);

    crypto_assert(EVP_PKEY_decrypt_init(ctx) == 1);
    crypto_assert(EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) == 1);
    crypto_assert(EVP_PKEY_CTX_set_ec_encrypt_param(ctx, NID_sm3) == 1);
    crypto_assert(EVP_PKEY_decrypt(ctx, out, &tlen, sm2_cipher_out, sm2_cipher_out_len) == 1);
    *outlen = tlen;

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
        free(sm2_cipher_out);
	return CRYPTO_RET_SUCCESS;
}

