#include <stdio.h>
#include <stdint.h>

int crypto_dili_keygen(uint8_t *seed, uint8_t *pk, uint8_t *sk);

int crypto_dili_sign(uint8_t *msg, uint32_t msglen, uint8_t *sk, uint8_t *sign, uint32_t *signlen);

int crypto_dili_verify( uint8_t *sig,
                       size_t siglen,
                        uint8_t *m,
                       size_t mlen,
                        uint8_t *pk, uint8_t *verify);