
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

__attribute__((visibility("default")))
int crypto_kyber_keygen(uint8_t *seed, uint8_t *pk, uint8_t *sk)
{
    // unsigned char       seed[48];
    // unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;
    
    if ( (ret_val = crypto_kem_keypair_user(seed, pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
    }
}

__attribute__((visibility("default")))
int crypto_kyber_sign(uint8_t *seed, uint8_t *pk, uint8_t *ss, uint8_t *ct) //seed pk || ss ct
{
    int  ret_val;
    if ( (ret_val = crypto_kem_enc_user(seed, ct, ss, pk)) != 0) {
    printf("crypto_kem_enc returned <%d>\n", ret_val);
    return KAT_CRYPTO_FAILURE;
    }
}

__attribute__((visibility("default")))
int crypto_kyber_verify(uint8_t *sk,  uint8_t *ct, uint8_t *ss) // 
{
    int  ret_val;
    if ( (ret_val = crypto_kem_dec(ss, ct, sk)) != 0) {
        printf("crypto_kem_dec returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }
    return 0;
}
