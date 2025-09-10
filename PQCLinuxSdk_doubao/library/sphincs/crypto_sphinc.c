
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
#include "rng.h"
#include "api.h"

#define	MAX_MARKER_LEN		50

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4


__attribute__((visibility("default")))
int crypto_sphinc_keygen(uint8_t *seed, uint8_t *pk, uint8_t *sk)
{
    int                 ret_val;
    if ( (ret_val = crypto_sign_keypair_user(seed, pk, sk)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
    }
}

__attribute__((visibility("default")))
int crypto_sphinc_sign(uint8_t *seed, uint8_t *msg, uint32_t msglen, uint8_t *sk, uint8_t *sign, uint32_t *signlen) //seed pk || ss ct
{
    int  ret_val;
    if ( (ret_val = crypto_sign_signature_user(seed, 16,sign, signlen,  msg, msglen, sk)!= 0)) {
        printf("crypto_sign returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }
}

__attribute__((visibility("default")))
int crypto_sphinc_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk, uint8_t *verify) // 
{
    int  ret_val;

    if (ret_val = crypto_sign_verify_user(sig, siglen, m, mlen, pk, verify) != 0) {
        printf("crypto_sphinc_verify returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }
    return 0;
}