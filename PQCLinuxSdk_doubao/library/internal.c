#include "internal.h"

void tsr_swap_len(uint8_t *p, uint32_t len)
{
    uint8_t tmp;
    uint32_t i = 0;
    uint32_t j = len - 1;

    while(i < j)
    {
        tmp = *(p + i);
        *(p + i) = *(p + j);
        *(p + j) = tmp;
        i++;
        j--;
    }
}

const EVP_MD *get_ssl_md(uint8_t algo)
{
    switch (algo)
	{
        case MD_ALGO_SM3:
            return EVP_sm3();
            break;
    	case MD_ALGO_SHA256:
            return EVP_sha256();
        case MD_ALGO_SHA3:
            return NULL;
    		break;    	
	}
	return NULL;
}

int eckey_to_crypto_key(uint8_t prikey[32], uint8_t pubkey[64], EC_KEY **eckey)
{
    uint8_t temp[65];
    uint8_t *p = temp;
    crypto_assert(i2o_ECPublicKey(*eckey, &p) != 0);
    crypto_assert(temp[0] == 0x04);
    memmove(&pubkey[0], &temp[1], 64);
    
    EC_KEY_priv2oct(*eckey, prikey, 32);

    return CRYPTO_RET_SUCCESS;
}

int crypto_ecc_gen_keypair_internal(int nid, uint8_t prikey[32], uint8_t pubkey[64])
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
    crypto_assert(ec_key != NULL);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    
    do{
        crypto_assert(EC_KEY_generate_key(ec_key) != 0);
    } while(EC_KEY_check_key((const EC_KEY *)ec_key) != 1);

    crypto_assert(eckey_to_crypto_key(prikey, pubkey, &ec_key) == CRYPTO_RET_SUCCESS);
    
    EC_KEY_free(ec_key);

    return CRYPTO_RET_SUCCESS;
}

int crypto_key_to_eckey(uint8_t prikey[32], uint8_t pubkey[64], EC_KEY **eckey)
{
    if(pubkey)
    {
        uint8_t temp[65] = {0x04,};
        memcpy(temp + 1, pubkey, 64);
        uint8_t *p = temp;
        *eckey = o2i_ECPublicKey(eckey, (const uint8_t **)(&p), 65);
        crypto_assert(*eckey != 0);
    }
    
    if(prikey)
        EC_KEY_oct2priv(*eckey, prikey, 32);

    return CRYPTO_RET_SUCCESS;
}

int crypto_key2pkey(int nid, uint8_t prikey[32], uint8_t pubkey[64], EVP_PKEY *pkey)
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
    crypto_assert(ec_key != 0);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    crypto_assert(crypto_key_to_eckey(prikey, pubkey, &ec_key) == CRYPTO_RET_SUCCESS);
    crypto_assert(EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 0);

    EC_KEY_free(ec_key);
    return CRYPTO_RET_SUCCESS;
}

int crypto_sigder2bin(uint8_t *der, size_t derlen, uint8_t sign[64])
{
    BIGNUM *rr1 = BN_new();
    BIGNUM *ss1 = BN_new();
    ECDSA_SIG *s = ECDSA_SIG_new();
    uint8_t *p1 = der;
    d2i_ECDSA_SIG(&s, (const unsigned char **)&p1, derlen);
    ECDSA_SIG_get0((const ECDSA_SIG *)s,(const BIGNUM **)&rr1,(const BIGNUM **)&ss1);
    memset(sign, 0, 64);
    BN_bn2bin(rr1, sign + 32 - BN_num_bytes(rr1));
    BN_bn2bin(ss1, sign + 64 - BN_num_bytes(ss1));    
    ECDSA_SIG_free(s);

    return CRYPTO_RET_SUCCESS;
}

int crypto_bin2sigder(uint8_t *der, size_t *derlen, uint8_t sign[64])
{
    BIGNUM *rr = BN_new();
    BIGNUM *ss = BN_new();
    BN_bin2bn(sign, 32, rr);
    BN_bin2bn(sign + 32, 32, ss);
    ECDSA_SIG *s = ECDSA_SIG_new();
    ECDSA_SIG_set0(s, rr, ss);
    uint8_t *p = der;
    *derlen = i2d_ECDSA_SIG(s, &p);
    ECDSA_SIG_free(s);

    return CRYPTO_RET_SUCCESS;
}

int crypto_ecc_kg_internal(int nid, uint8_t k[32], uint8_t r[64])
{
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    int filed = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

    BN_CTX *bn_ctx;
    BIGNUM *x1, *y1, *ec_k;
    bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    x1 = BN_CTX_get(bn_ctx);
    y1 = BN_CTX_get(bn_ctx);
    ec_k = BN_CTX_get(bn_ctx);
    BN_bin2bn((uint8_t *)k, 32, ec_k);
    
    EC_POINT *ec_r = EC_POINT_new(group);
    crypto_assert(EC_POINT_mul(group, ec_r, ec_k, NULL, NULL, NULL) == 1);
        
    if (filed == NID_X9_62_prime_field)
        crypto_assert(EC_POINT_get_affine_coordinates_GFp(group, ec_r, x1, y1, bn_ctx) == 1);
    else
        crypto_assert(EC_POINT_get_affine_coordinates_GF2m(group, ec_r, x1, y1, bn_ctx) == 1);
    
    memset(r, 0, 64);
    BN_bn2bin(x1, r + 32 - BN_num_bytes(x1));
    BN_bn2bin(y1, r + 64 - BN_num_bytes(y1));

    BN_CTX_free(bn_ctx);
    EC_POINT_free(ec_r);
    EC_GROUP_free((EC_GROUP *)group);

    return CRYPTO_RET_SUCCESS;
}

int crypto_ecc_kp_internal(int nid, uint8_t k[32], uint8_t p[64], uint8_t r[64])
{
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    int filed = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

    BN_CTX *bn_ctx;
    BIGNUM *x1, *y1, *x2, *y2, *ec_k;
    bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    x1 = BN_CTX_get(bn_ctx);
    y1 = BN_CTX_get(bn_ctx);
    x2 = BN_CTX_get(bn_ctx);
    y2 = BN_CTX_get(bn_ctx);
    ec_k = BN_CTX_get(bn_ctx);

    BN_bin2bn((uint8_t *)k, 32, ec_k);
    BN_bin2bn((uint8_t *)p, 32, x1);
    BN_bin2bn((uint8_t *)p + 32, 32, y1);
    
    EC_POINT *ec_r = EC_POINT_new(group);
    EC_POINT *ec_p = EC_POINT_new(group);

    if (filed == NID_X9_62_prime_field)
        crypto_assert(EC_POINT_set_affine_coordinates_GFp(group, ec_p, x1, y1, bn_ctx) == 1);
    else
        crypto_assert(EC_POINT_set_affine_coordinates_GF2m(group, ec_p, x1, y1, bn_ctx) == 1);
    
    crypto_assert(EC_POINT_mul(group, ec_r, NULL, ec_p, ec_k, NULL) == 1);
        
    if (filed == NID_X9_62_prime_field)
        crypto_assert(EC_POINT_get_affine_coordinates_GFp(group, ec_r, x2, y2, bn_ctx) == 1);
    else
        crypto_assert(EC_POINT_get_affine_coordinates_GF2m(group, ec_r, x2, y2, bn_ctx) == 1);
    
    memset(r, 0, 64);
    BN_bn2bin(x2, r + 32 - BN_num_bytes(x2));
    BN_bn2bin(y2, r + 64 - BN_num_bytes(y2));
    
    BN_CTX_free(bn_ctx);
    EC_POINT_free(ec_r);
    EC_POINT_free(ec_p);
    EC_GROUP_free((EC_GROUP *)group);

    return CRYPTO_RET_SUCCESS;
}

int crypto_ecc_sign_internal(int nid, uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64])
{
    uint8_t sig_der[128];
    size_t sig_der_size = 128;

    EVP_PKEY *pkey = EVP_PKEY_new();
    crypto_assert(crypto_key2pkey(nid, prikey, NULL, pkey) == CRYPTO_RET_SUCCESS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    crypto_assert(EVP_PKEY_sign_init(ctx) == 1);
    
    if(nid == NID_sm2p256v1)
        crypto_assert(EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) == 1);

    crypto_assert(EVP_PKEY_sign(ctx, sig_der, &sig_der_size, digest, 32) == 1);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return crypto_sigder2bin(sig_der, sig_der_size, sign);
}

int crypto_ecc_verify_internal(int nid, uint8_t pubkey[64], uint8_t digest[32], uint8_t sign[64])
{
    uint8_t sig_der[128];
    size_t sig_der_size = 128;

    EVP_PKEY *pkey = EVP_PKEY_new();
    crypto_assert(crypto_key2pkey(nid, NULL, pubkey, pkey) == CRYPTO_RET_SUCCESS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    crypto_assert(crypto_bin2sigder(sig_der, &sig_der_size, sign) == CRYPTO_RET_SUCCESS);
    crypto_assert(EVP_PKEY_verify_init(ctx) == 1);

    if(nid == NID_sm2p256v1)
        crypto_assert(EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) == 1);
    
    crypto_assert(EVP_PKEY_verify(ctx, sig_der, sig_der_size, digest, 32) == 1);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return CRYPTO_RET_SUCCESS;
}

void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    printf("%s[%d]", info, len);
    for (int i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\n     ":" ", 
                        buf[i], i == len - 1 ? "\n":"");
    }
}
