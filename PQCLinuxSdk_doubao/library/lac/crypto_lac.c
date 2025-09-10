
//
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdint.h>
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
int crypto_lac_keygen(uint8_t *seed, uint8_t *pk, uint8_t *sk)
{
    int                 ret_val;
    // random_bytes(seed,SEED_LEN);
    // int kg_seed(unsigned char *pk, unsigned char *sk, unsigned char *seed);
    if ( (ret_val = kg_seed( pk, sk, seed)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
    }
}

__attribute__((visibility("default")))
int crypto_lac_enc(uint8_t *pk, uint8_t *ct, uint8_t *ss) //seed pk || ss ct
{
    int  ret_val;

    crypto_kem_enc(ct,ss,pk);
    // if ( (ret_val = crypto_sign(sign, signlen, msg, msglen, sk))!= 0) {
    //     printf("crypto_sign returned <%d>\n", ret_val);
    //     return KAT_CRYPTO_FAILURE;
    // }
}

__attribute__((visibility("default")))
int crypto_lac_dec( unsigned char *sk, unsigned char *ct, unsigned char *ss1) // 
{
    int  ret_val;
    crypto_kem_dec(ss1,ct,sk);    
    return 0;
}