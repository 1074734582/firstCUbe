
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
#include "api.h"

__attribute__((visibility("default")))
int crypto_hqc128_keygen(uint8_t *seed, uint8_t *pk, uint8_t *sk)  //seed —--> pk sk
{
    // unsigned char       seed[48];
    // unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;
    hqc_pke_keygen_user(seed, pk, sk);
}

__attribute__((visibility("default")))
int crypto_hqc128_enc(uint8_t *pk, uint8_t *ct, uint8_t *ss) //seed pk || ss ct
{
    int  ret_val;
    crypto_kem_enc(ct,ss,pk);
}

__attribute__((visibility("default")))
int crypto_hqc128_dec( unsigned char *sk, unsigned char *ct, unsigned char *ss1) 
{
    int  ret_val;
    crypto_kem_dec(ss1,ct,sk);    
    return 0;
}


