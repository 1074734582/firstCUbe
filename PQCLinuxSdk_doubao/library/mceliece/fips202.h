#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>


#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  uint64_t s[25];
} keccak_state;

void KeccakF1600_StatePermute(uint64_t state[25]);

void shake256_absorb(keccak_state *state, const uint8_t *in, uint32_t inlen);
void shake256_squeezeblocks(uint8_t *out, uint32_t nblocks,  keccak_state *state);
void shake256(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen);

#endif
