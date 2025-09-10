
#ifndef __ROCKY_SHA3__H
#define __ROCKY_SHA3__H

#include <stddef.h>
#include <stdint.h>

#define ERR_OK           0
#define ERR_ERR         -1  /* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long int uint64_t;
typedef struct {
    uint64_t high; /* high 64 bits */
    uint64_t low;  /*  low 64 bits */
} uint128_t;


typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef enum sha3_algorithm {
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256,
    RAWSHAKE128,
    RAWSHAKE256,
}SHA3_ALG;

typedef struct sha3_context {
    /* intermedia hash value for each block */
    uint64_t lane[5][5];      /* 5 x 5 x 64 = 1600 bits */

    /* last block */
    struct {
        uint32_t used;      /* used bytes */
        uint8_t  buf[200];  /* block data buffer, 200 x 8 = 1600 bits */
    }last;

    SHA3_ALG alg;

    /*
     * |-------------------------------------------------------------|
     * | l          | 0    | 1    | 2    | 3    | 4    | 5    | 6    |
     * |-------------------------------------------------------------|
     * | w = 2^l    | 1    | 2    | 4    | 8    | 16   | 32   | 64   |
     * |-------------------------------------------------------------|
     * | b = 25*2^l | 25   | 50   | 100  | 200  | 400  | 800  | 1600 |
     * |-------------------------------------------------------------|
     * | SHA3: l = 6, w = 64, b = 1600                          *    |
     * |-------------------------------------------------------------|
     */

    // uint32_t l; /* binary logarithm of lane size */
    // uint32_t w; /* lane size in bits */
    uint32_t b; /* width of the state, b = r + c */
    uint32_t r; /* bit rate, rate of a sponge function, length of one message block */
    uint32_t c; /* capacity, r + c = b */

    uint32_t nr; /* round number, nr = 12 + 2l */

    uint32_t md_size;   /* message digest size in bytes */

    uint32_t absorbing; /* 1: absorbe; 0: squeeze */
}SHA3_CTX;

int SHA3_Init(SHA3_CTX *c, SHA3_ALG alg);
int SHA3_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_Final(unsigned char *md, SHA3_CTX *c);
unsigned char *SHA3(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md);

/* Extendable-Output Functions: SHAKE128, SHAKE256 */
int SHA3_XOF_Init(SHA3_CTX *c, SHA3_ALG alg, uint32_t md_size);
int SHA3_XOF_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_XOF_Final(unsigned char *md, SHA3_CTX *c);
unsigned char *SHA3_XOF(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t md_size);
#endif

void sha3_padding(unsigned char *in , uint32_t in_len, unsigned char *out, uint32_t *out_len);

int mcsip_sha3(uint32_t sha_mode_sel,unsigned char *in, uint32_t inlen, unsigned char *out,uint32_t outlen);

//unsigned char *SHA3_SW(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md);
unsigned char *SHA3_SW_HMAC(unsigned char *key, int keylen, unsigned char *text, int textlen, unsigned char *hmac);
unsigned char *SHA3_SW_PRF(unsigned char *key, int keylen, unsigned char *seed, int seedlen, unsigned char *out, int outlen);


