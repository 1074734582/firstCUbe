
//
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "rng.h"
#include "api.h"
#include "crypto_dili.h"

#define	MAX_MARKER_LEN		50

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

__attribute__((visibility("default")))
int crypto_dili_keygen(uint8_t *seed, uint8_t *pk, uint8_t *sk)
{
    // unsigned char       seed[48];
    // unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;
    
    // randombytes_init(seed, NULL, 256);
    if ( (ret_val = crypto_dili2_keypair_user(seed, pk, sk)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
    }
}

__attribute__((visibility("default")))
int crypto_dili_sign(uint8_t *msg, uint32_t msglen, uint8_t *sk, uint8_t *sign, uint32_t *signlen) //seed pk || ss ct
{
    int  ret_val;
    if ( (ret_val = crypto_dili2_sign_user(sign, signlen, msg, msglen, sk))!= 0) {
        printf("crypto_sign returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }
}

__attribute__((visibility("default")))
int crypto_dili_verify( uint8_t *sig,
                       size_t siglen,
                        uint8_t *m,
                       size_t mlen,
                        uint8_t *pk, uint8_t *verify) 
{
    int  ret_val;
    unsigned char ss1[CRYPTO_BYTES];
    unsigned int ver_ok[8] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};
    unsigned int ver_fail[8] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    if (ret_val = crypto_dili2_verify_user(sig, siglen, m, mlen, pk) != 0) {
        memcpy(verify, ver_fail, 32);
        printf("crypto_dili2_verify_user returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }
    memcpy(verify, ver_ok, 32);
    return 0;
}


