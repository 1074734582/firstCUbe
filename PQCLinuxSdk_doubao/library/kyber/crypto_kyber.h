#include <stdint.h>
#include <stdio.h>

int crypto_kyber_keygen(uint8_t *seed, uint8_t *pk, uint8_t *sk);
int crypto_kyber_sign(uint8_t *seed, uint8_t *pk, uint8_t *ss, uint8_t *ct); //seed pk || ss ct
int crypto_kyber_verify(uint8_t *sk,  uint8_t *ct, uint8_t *ss);