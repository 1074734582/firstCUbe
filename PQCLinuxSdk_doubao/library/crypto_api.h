#ifndef __CRYPTO_API_H__
#define __CRYPTO_API_H__

#include <stdint.h>
#include <stdio.h>

#define CRYPTO_RSA_MAX_BITS                2048

typedef enum crypto_ret_code_
{
    CRYPTO_RET_FAILED = 0,
    CRYPTO_RET_SUCCESS,
} crypto_ret_code_e;

typedef enum crypto_md_algo_
{
    MD_ALGO_SM3 	= 10,
    MD_ALGO_SHA256 	= 11,
    MD_ALGO_SHA3 	= 12, 
} crypto_md_algo_e;
    
typedef enum crypto_cipher_algo_
{
    CIPHER_SM4      = 8,
    CIPHER_AES      = 9,
} crypto_cipher_algo_e;
    
typedef enum crypto_cipher_mode_
{
    CIPHER_MODE_ECB,
    CIPHER_MODE_CBC,
    CIPHER_MODE_CFB,    
    CIPHER_MODE_OFB,   
    CIPHER_MODE_CTR,
    CIPHER_MODE_XTS,
    CIPHER_MODE_CMAC,
    CIPHER_MODE_CBC_MAC,
    CIPHER_MODE_CCM,
    CIPHER_MODE_GCM,
} crypto_cipher_mode_e;

typedef enum crypto_cipher_dir_
{
    CIPHER_DIR_DECRYPT,
    CIPHER_DIR_ENCRYPT,  
} crypto_cipher_dir_e;

/** RSA 密钥结构 */
typedef struct rsa_key_
{
    int bits;                                // 位数，1024/2048
    int crt;
    
    // key pair
    uint8_t n[CRYPTO_RSA_MAX_BITS/8];               // 模数
    uint8_t e[CRYPTO_RSA_MAX_BITS/8];               // 公开指数
    uint8_t d[CRYPTO_RSA_MAX_BITS/8];               // 私密指数

    // crt
    uint8_t p[CRYPTO_RSA_MAX_BITS/8/2];             // p        
    uint8_t q[CRYPTO_RSA_MAX_BITS/8/2];             // q
    uint8_t dmp1[CRYPTO_RSA_MAX_BITS/8/2];            // d mod (p-1)
    uint8_t dmq1[CRYPTO_RSA_MAX_BITS/8/2];            // d mod (q-1)
    uint8_t iqmp[CRYPTO_RSA_MAX_BITS/8/2];          // (inverse of q) mod p
} crypto_rsa_key_t;

int crypto_hash(uint8_t algo, uint8_t *src, uint32_t len, uint8_t *digest, uint32_t *size);
// int crypto_hmac(uint8_t algo, uint8_t *key, uint32_t keylen, uint8_t *src, uint32_t srclen, uint8_t *mac);
int crypto_hmac(uint8_t algo, uint8_t *key, uint32_t keylen, uint8_t *src, uint32_t srclen, uint8_t *out, uint32_t *outlen);

int crypto_cipher(uint8_t algo, uint8_t mode, uint8_t enc, uint8_t *key, uint32_t key_len, 
            uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *src, uint32_t src_len, uint8_t *dst, uint8_t tag[16], uint32_t tag_len);

int crypto_cipher_ccm(uint8_t algo, uint8_t mode, uint8_t enc, uint8_t *key, uint32_t key_len, 
            uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *src, uint32_t src_len, uint8_t *dst, uint8_t tag[16], uint32_t tag_len);

int crypto_cipher_gcm(uint8_t algo, uint8_t mode, uint8_t enc, uint8_t *key, uint32_t key_len, 
            uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *src, uint32_t src_len, uint8_t *dst, uint8_t tag[16], uint32_t tag_len);

int crypto_prf(uint8_t hash_algo, uint8_t *sec, uint32_t seclen, uint8_t *seed, uint32_t seedlen, uint8_t *out, uint32_t outlen);

void dump_buf(char *info, uint8_t *buf, uint32_t len);

// sm2
int crypto_sm2_gen_keypair(uint8_t prikey[32], uint8_t pubkey[64]);
int crypto_sm2_kg(uint8_t k[32], uint8_t r[64]);
int crypto_sm2_kp(uint8_t k[32], uint8_t p[64], uint8_t r[64]);
int crypto_sm2_sign(uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64]);
int crypto_sm2_verify(uint8_t pubkey[64], uint8_t digest[32], uint8_t sign[64]);

// ecc
int crypto_ecc_gen_keypair(uint8_t prikey[32], uint8_t pubkey[64]);
int crypto_ecc_kg(uint8_t k[32], uint8_t r[64]);
int crypto_ecc_kp(uint8_t k[32], uint8_t p[64], uint8_t r[64]);
int crypto_ecc_sign(uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64]);
int crypto_ecc_verify(uint8_t pubkey[32], uint8_t digest[32], uint8_t sign[64]);

//rsa
int crypto_rsa_gen_keypair(crypto_rsa_key_t *rsa_key);
int crypto_rsa_pub_enc(crypto_rsa_key_t *rsa_key, uint8_t *in, uint8_t *out);
int crypto_rsa_pub_dec(crypto_rsa_key_t *rsa_key, uint8_t *in, uint8_t *out);
int crypto_rsa_priv_enc(crypto_rsa_key_t *rsa_key, uint8_t *in, uint8_t *out);
int crypto_rsa_priv_dec(crypto_rsa_key_t *rsa_key, uint8_t *in, uint8_t *out);

#endif
