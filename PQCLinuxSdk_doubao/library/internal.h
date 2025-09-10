#ifndef __CRYPTO_INTERNAL_H__
#define __CRYPTO_INTERNAL_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sm2.h>
#include <openssl/hmac.h>
#include <openssl/zuc.h>

#include <openssl/cmac.h>

#include "crypto_api.h"

#define crypto_assert(cond)                                                  \
    do                                                                              \
    {                                                                               \
        if (!(cond))                                                                \
        {                                                                           \
            printf("\n  crypto_assert: !failed, %s:%d\n", __FILE__, __LINE__); \
            return CRYPTO_RET_FAILED;                                                             \
        }                                                                           \
    } while (0)

const EVP_MD *get_ssl_md(uint8_t algo);
void tsr_swap_len(uint8_t *p, uint32_t len);

int crypto_key2pkey(int nid, uint8_t prikey[32], uint8_t pubkey[64], EVP_PKEY *pkey);
int crypto_ecc_gen_keypair_internal(int nid, uint8_t prikey[32], uint8_t pubkey[64]);
int crypto_ecc_kg_internal(int nid, uint8_t k[32], uint8_t r[64]);
int crypto_ecc_kp_internal(int nid, uint8_t k[32], uint8_t p[64], uint8_t r[64]);
int crypto_ecc_sign_internal(int nid, uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64]);
int crypto_ecc_verify_internal(int nid, uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64]);


#endif