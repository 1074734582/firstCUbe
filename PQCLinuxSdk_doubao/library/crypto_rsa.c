#include "internal.h"

int crypto_rsa_gen_keypair(crypto_rsa_key_t *rsa_key)
{
	RSA *rsa = RSA_new();
	BIGNUM *bn = BN_new();

    if (!BN_set_word(bn, RSA_F4) || !RSA_generate_key_ex(rsa, rsa_key->bits, bn, NULL))
    {
    	printf("rsa genkey failed.");
        BN_free(bn);
        RSA_free(rsa);
        return CRYPTO_RET_FAILED;
    }

    BIGNUM *n, *d, *e, *p, *q, *dmp1, *dmq1, *iqmp;

	RSA_get0_key((const RSA *)rsa, (const BIGNUM **)&n, (const BIGNUM **)&e, (const BIGNUM **)&d);
	RSA_get0_factors((const RSA *)rsa, (const BIGNUM **)&p, (const BIGNUM **)&q);
	RSA_get0_crt_params((const RSA *)rsa, (const BIGNUM **)&dmp1, (const BIGNUM **)&dmq1, (const BIGNUM **)&iqmp);

    memset(rsa_key->n, 0, sizeof(rsa_key->n));
    memset(rsa_key->d, 0, sizeof(rsa_key->d));
    memset(rsa_key->e, 0, sizeof(rsa_key->e));
    memset(rsa_key->p, 0, sizeof(rsa_key->p));
    memset(rsa_key->q, 0, sizeof(rsa_key->q));
    memset(rsa_key->dmp1, 0, sizeof(rsa_key->dmp1));
    memset(rsa_key->dmq1, 0, sizeof(rsa_key->dmq1));
    memset(rsa_key->iqmp, 0, sizeof(rsa_key->iqmp));

	BN_bn2bin(n, rsa_key->n + rsa_key->bits/8 - BN_num_bytes(n));
	BN_bn2bin(d, rsa_key->d + rsa_key->bits/8 - BN_num_bytes(d));
    BN_bn2bin(e, rsa_key->e + rsa_key->bits/8 - BN_num_bytes(e));
    BN_bn2bin(p, rsa_key->p + rsa_key->bits/8/2 - BN_num_bytes(p));
    BN_bn2bin(q, rsa_key->q + rsa_key->bits/8/2 - BN_num_bytes(q));
    BN_bn2bin(dmp1, rsa_key->dmp1 + rsa_key->bits/8/2 - BN_num_bytes(dmp1));
    BN_bn2bin(dmq1, rsa_key->dmq1 + rsa_key->bits/8/2 - BN_num_bytes(dmq1));
    BN_bn2bin(iqmp, rsa_key->iqmp + rsa_key->bits/8/2 - BN_num_bytes(iqmp));
    BN_free(bn);
    RSA_free(rsa);
    
    rsa_key->crt = 1;

	return CRYPTO_RET_SUCCESS;
}

int crypto_rsa_pub_enc(crypto_rsa_key_t *rsa_key, uint8_t *in, uint8_t *out)
{
	RSA *rsa = RSA_new();
    BIGNUM *rsa_n = BN_new();
    BIGNUM *rsa_e = BN_new();
    BIGNUM *rsa_d = BN_new();

    BN_bin2bn(rsa_key->n, rsa_key->bits/8, rsa_n);
    BN_bin2bn(rsa_key->e, rsa_key->bits/8, rsa_e);
    BN_bin2bn(rsa_key->d, rsa_key->bits/8, rsa_d);
	RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d);

	crypto_assert(RSA_public_encrypt(rsa_key->bits/8, in, out, rsa, RSA_NO_PADDING) != -1);
	
    RSA_free(rsa);

	return CRYPTO_RET_SUCCESS;
}

int crypto_rsa_pub_dec(crypto_rsa_key_t *rsa_key, uint8_t *in, uint8_t *out)
{
	RSA *rsa = RSA_new();
    BIGNUM *rsa_n = BN_new();
    BIGNUM *rsa_e = BN_new();
    BIGNUM *rsa_d = BN_new();

    BN_bin2bn(rsa_key->n, rsa_key->bits/8, rsa_n);
    BN_bin2bn(rsa_key->e, rsa_key->bits/8, rsa_e);
    BN_bin2bn(rsa_key->d, rsa_key->bits/8, rsa_d);
	RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d);

	crypto_assert(RSA_public_decrypt(rsa_key->bits/8, in, out, rsa, RSA_NO_PADDING) != -1);
	
    RSA_free(rsa);
	return CRYPTO_RET_SUCCESS;
}

int crypto_rsa_priv_enc(crypto_rsa_key_t *rsa_key, uint8_t *in, uint8_t *out)
{
	RSA *rsa = RSA_new();
    BIGNUM *rsa_n = BN_new();
    BIGNUM *rsa_e = BN_new();
    BIGNUM *rsa_d = BN_new();

    BN_bin2bn(rsa_key->n, rsa_key->bits/8, rsa_n);
    BN_bin2bn(rsa_key->e, rsa_key->bits/8, rsa_e);
    BN_bin2bn(rsa_key->d, rsa_key->bits/8, rsa_d);
	RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d);

	crypto_assert(RSA_private_encrypt(rsa_key->bits/8, in, out, rsa, RSA_NO_PADDING) != -1);
	// crypto_assert(RSA_private_encrypt(rsa_key->bits/8, in, out, rsa, RSA_PKCS1_PADDING) != -1);


    RSA_free(rsa);
	return CRYPTO_RET_SUCCESS;
}

int crypto_rsa_priv_dec(crypto_rsa_key_t *rsa_key, uint8_t *in, uint8_t *out)
{
	RSA *rsa = RSA_new();
    BIGNUM *rsa_n = BN_new();
    BIGNUM *rsa_e = BN_new();
    BIGNUM *rsa_d = BN_new();

    BN_bin2bn(rsa_key->n, rsa_key->bits/8, rsa_n);
    BN_bin2bn(rsa_key->d, rsa_key->bits/8, rsa_d);
    BN_bin2bn(rsa_key->e, rsa_key->bits/8, rsa_e);
	RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d);

	crypto_assert(RSA_private_decrypt(rsa_key->bits/8, in, out, rsa, RSA_NO_PADDING) != -1);
	
    RSA_free(rsa);
	return CRYPTO_RET_SUCCESS;
}


