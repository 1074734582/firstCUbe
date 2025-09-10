#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <endian.h>
#include "sha3.h"

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#define DUMP_BLOCK_DATA 1
#define DUMP_BLOCK_HASH 1
#define DUMP_ROUND_DATA 1
#define DUMP_SCHED_DATA 1
#else
#define DBG(...)
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#define DUMP_SCHED_DATA 0
#endif


/*  q=1: 01 10 0001 <--reverse-- 1000 01 10, 1 byte, 0x86 */
#define SHA3_PADDING_STD1        0x86

/* q>=2: 01 10 0000....0000 0001 <--reverse-- 0000 01 10....1000 0000, 2 bytes, 0x06...0x80 */
#define SHA3_PADDING_STD2_BEGIN  0x06
#define SHA3_PADDING_STD2_END    0x80

/*
 * SHA3 XOF Delimiter + Padding
 *               1111 + 10*1
 */
/*  q=1: 1111 1001 <--reverse-- 1001 1111, 1 byte, 0x9F */
#define SHA3_PADDING_XOF1        0x9F

/* q>=2: 1111 1000....0000 0001 <--reverse 0001 1111....1000 0000, 2 bytes, 0x1F...0x80 */
#define SHA3_PADDING_XOF2_BEGIN  0x1F
#define SHA3_PADDING_XOF2_END    0x80

/*
 * SHA3 XOF Delimiter + Padding
 *               11 + 10*1
 */
/*  q=1: 1111 1001 <--reverse-- 1001 1111, 1 byte, 0x9F */
#define SHA3_PADDING_RAWXOF1        0x87

/* q>=2: 1111 1000....0000 0001 <--reverse 0001 1111....1000 0000, 2 bytes, 0x1F...0x80 */
#define SHA3_PADDING_RAWXOF2_BEGIN  0x07
#define SHA3_PADDING_RAWXOF2_END    0x80

/* ROTate Left (circular left shift) */
static uint64_t ROTL(uint64_t x, uint8_t shift)
{
    return (x << shift) | (x >> (64 - shift));
}

static uint32_t theta(uint64_t A[5][5])
{
    uint32_t x, y;
    uint64_t Ap[5][5];
    uint64_t C[5], D[5];

    memset(C, 0, sizeof(C));
    memset(D, 0, sizeof(D));
    memset(Ap, 0, sizeof(Ap));

    for (x=0; x<5; x++)
    {
        C[x] = A[0][x] ^ A[1][x] ^ A[2][x] ^ A[3][x] ^ A[4][x];
    }

    for (x=0; x<5; x++)
    {
        D[x] = C[(x+4)%5] ^ ROTL(C[(x+1)%5], 1);
    }

    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            Ap[y][x] = A[y][x] ^ D[x];
        }
    }

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

/* rotation constants, aka rotation offsets */
static uint32_t Rp[5][5] =
{
    {   0,   1,  190,  28,  91},
    {  36, 300,    6,  55, 276},
    {   3,  10,  171, 153, 231},
    { 105,  45,   15,  21, 136},
    { 210,  66,  253, 120,  78}
};
static uint32_t rho(uint64_t A[5][5])
{
    uint64_t Ap[5][5];
    uint32_t x, y, m;
    uint32_t t;

    memset(Ap, 0, sizeof(Ap));
    /* let A'[0,0,z]=A[0,0,z] */
    memcpy(Ap[0], A[0], sizeof(Ap[0]));

    /* let (x,y) = (1,0) */
    x = 1;
    y = 0;
    #if 0
    /* calculate directly */
    for (t=0; t<24; t++)
    {
        Ap[y][x] = ROTL(A[y][x], ((t+1)*(t+2)/2)%64);
        m = x;
        x = y;
        y = (2*m + 3*y) % 5;
    }
    #else
    /* look up table */
    for (t=0; t<24; t++)
    {
        Ap[y][x] = ROTL(A[y][x], Rp[y][x]%64);
        /* let (x,y) = (y,(2x+3y)%5) */
        m = x;
        x = y;
        y = (2*m+3*y) % 5;
    }
    #endif

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

static uint32_t pi(uint64_t A[5][5])
{
    uint64_t Ap[5][5];
    uint32_t x, y;

    memset(Ap, 0, sizeof(Ap));
    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            Ap[y][x] = A[x][(x+3*y)%5];
        }
    }

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

static uint32_t chi(uint64_t A[5][5])
{
    uint64_t Ap[5][5];
    uint32_t x, y;

    memset(Ap, 0, sizeof(Ap));
    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            Ap[y][x] = A[y][x] ^ ((~A[y][(x+1)%5]) & A[y][(x+2)%5]);
        }
    }

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

static uint64_t RC[24] =
{
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};
static uint32_t iota(uint64_t A[5][5], uint32_t i)
{
    A[0][0] = A[0][0] ^ RC[i];

    return 0;
}

int SHA3_Init(SHA3_CTX *c, SHA3_ALG alg)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    if ((alg == SHAKE128) || (alg == SHAKE256) || (alg == RAWSHAKE128) || (alg == RAWSHAKE256))
    {
        return ERR_INV_PARAM;
    }

    memset(c, 0, sizeof(SHA3_CTX));

    /* bits */
    // c->l = 6;
    // c->w = 64; /* c->w = 2 ^ l */

    /* bytes */
    c->b = 200; /* 1600 bits, c->b = 25 * 2 ^ c->l; */
    c->alg = alg;
    switch (alg)
    {
        case SHA3_224:   /* SHA3-224(M) = KECCAK[448](M||01,224), FIPS-202, sec 6.1 */
            c->r  = 144;        /* 1152 bits */
            c->c  =  56;        /*  448 bits */
            c->md_size =  28;   /*  224 bits */
            break;
        case SHA3_256:   /* SHA3-256(M) = KECCAK[512](M||01,256), FIPS-202, sec 6.1 */
            c->r  = 136;        /* 1088 bits */
            c->c  =  64;        /*  512 bits */
            c->md_size =  32;   /*  256 bits */
            break;
        case SHA3_384:   /* SHA3-384(M) = KECCAK[768](M||01,384), FIPS-202, sec 6.1 */
            c->r  = 104;        /*  832 bits */
            c->c  =  96;        /*  768 bits */
            c->md_size =  48;   /*  384 bits */
            break;
        default: /* default Keccak setting: SHA3_512 */
        case SHA3_512:   /* SHA3-512(M) = KECCAK[1024](M||01,512), FIPS-202, sec 6.1 */
            c->r  =  72;        /*  576 bits */
            c->c  = 128;        /* 1024 bits */
            c->md_size =  64;   /*  512 bits */
            break;
    }

    c->nr = 24; /* nr = 24 = 12 + 2 * l */
    c->absorbing = 1; /* absorbing phase */

    return ERR_OK;
}

#if (DUMP_SCHED_DATA == 1)
#define sched_show_buffer(info,ptr,len) \
    DBG(info); \
    print_buffer((ptr),(len),"       ");
#else
#define sched_show_buffer(info,ptr,len)
#endif

#if (DUMP_ROUND_DATA == 1)
#define round_show_buffer(info) \
    DBG(info); \
    print_buffer(&ctx->lane[0][0], ctx->b, "       ");

static void dump_lane_buffer(uint64_t lane[5][5])
{
    uint32_t x, y;

    for (y=0; y<5; y++) /* row */
    {
        for (x=0; x<5; x++) /* col */
        {
            DBG("[%d, %d]: %016llx  ", x, y, lane[y][x]);
        }
        DBG("\n");
    }
    return;
}
#else
#define round_show_buffer(info)\
    DBG(info); \

static void dump_lane_buffer(uint64_t lane[5][5]) {}
#endif

//zwd #include <byteswap.h>
//zwd  #define le64toh(x) __bswap_64 (x)
#define le64toh(x)  (x)

static int SHA3_PrepareScheduleWord(SHA3_CTX *ctx, const uint64_t *block)
{
    uint32_t i;
    uint64_t *data;
    uint64_t temp[25];

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

    for (i=0; i<ctx->b/8; i++)
    {
        if (i<ctx->r/8)
        {
            temp[i] = le64toh(block[i]);
        }
        else
        {
            temp[i] = 0x0;
        }
    }

    sched_show_buffer("Data to absorbed:\n", temp, ctx->b);
    sched_show_buffer("  SchedWord: [before]\n", &ctx->lane[0][0], ctx->b);

    /* initial S */
    data = &ctx->lane[0][0];

    for (i=0; i<ctx->b/8; i++)
    {
        data[i] ^= temp[i];
    }

    sched_show_buffer("  SchedWord: [after]\n", &ctx->lane[0][0], ctx->b);

    return ERR_OK;
}

/* r bytes for each block */
static int SHA3_ProcessBlock(SHA3_CTX *ctx, const void *block)
{
    uint32_t t;

    if ((NULL == ctx) || (ctx->absorbing && (NULL == block)))
    {
        return ERR_INV_PARAM;
    }

#if (DUMP_BLOCK_DATA == 1)
    DBG("---------------------------------------------------------\n");
    DBG(" BLOCK DATA:\n");
    print_buffer(block, ctx->r, "       ");
#endif

    if (ctx->absorbing)
    {
        SHA3_PrepareScheduleWord(ctx, block);
    }

    for (t=0; t<ctx->nr; t++)
    {
#if (DUMP_ROUND_DATA == 1)
        DBG("  Round #%02d:\n", t);
#endif
        theta(ctx->lane);
        round_show_buffer("After Theta:\n");

        rho(ctx->lane);
        round_show_buffer("  After Rho:\n");

        pi(ctx->lane);
        round_show_buffer("   After Pi:\n");

        chi(ctx->lane);
        round_show_buffer("  After Chi:\n");

        iota(ctx->lane, t);
        round_show_buffer(" After Iota:\n");
    }

    round_show_buffer("After Permutation:\n");
#if (DUMP_BLOCK_HASH == 1)
    DBG(" BLOCK HASH:\n");
    print_buffer(&ctx->lane[0][0], ctx->b, "       ");
#endif

    return ERR_OK;
}

int SHA3_Update(SHA3_CTX *c, const void *data, size_t len)
{
    uint64_t copy_len = 0;

    if ((NULL == c) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    /* has used data */
    if (c->last.used != 0)
    {
        /* less than 1 block in total, combine data */
        if (c->last.used + len < c->r)
        {
            memcpy(&c->last.buf[c->last.used], data, len);
            c->last.used += len;

            return ERR_OK;
        }
        else /* more than 1 block */
        {
            /* process the block in context buffer */
            copy_len = c->r - c->last.used;
            memcpy(&c->last.buf[c->last.used], data, copy_len);
            SHA3_ProcessBlock(c, &c->last.buf);

            data = (uint8_t *)data + copy_len;
            len -= copy_len;

            /* reset context buffer */
            memset(&c->last.buf[0], 0, c->r);
            c->last.used = 0;
        }
    }

    /* less than 1 block, copy to context buffer */
    if (len < c->r)
    {
        memcpy(&c->last.buf[c->last.used], data, len);
        c->last.used += len;

        return ERR_OK;
    }
    else
    {
        /* process data blocks */
        while (len >= c->r)
        {
            SHA3_ProcessBlock(c, data);

            data = (uint8_t *)data + c->r;
            len -= c->r;
        }

        /* copy rest data to context buffer */
        memcpy(&c->last.buf[0], data, len);
        c->last.used = len;
    }

    return ERR_OK;
}

int SHA3_Final(unsigned char *md, SHA3_CTX *c)
{
    uint32_t md_size = 0; /* message digest size used */

    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    /* more than 2 bytes left */
    if (c->last.used <= (c->r - 2))
    {
        /* one more block */
        if ((c->alg == SHAKE128) || (c->alg == SHAKE256)) /* XOFs */
        {
            c->last.buf[c->last.used] = SHA3_PADDING_XOF2_BEGIN;
        }
        else if ((c->alg == RAWSHAKE128) || (c->alg == RAWSHAKE256)) /* XOFs */
        {
            c->last.buf[c->last.used] = SHA3_PADDING_RAWXOF2_BEGIN;
        }
        else
        {
            c->last.buf[c->last.used] = SHA3_PADDING_STD2_BEGIN;
        }
        c->last.used++;

        memset(&c->last.buf[c->last.used], 0, (c->r - 1) - c->last.used);
        c->last.used = c->r - 1;

        if ((c->alg == SHAKE128) || (c->alg == SHAKE256)) /* XOFs */
        {
            c->last.buf[c->last.used] = SHA3_PADDING_XOF2_END;
        }
        else if ((c->alg == RAWSHAKE128) || (c->alg == RAWSHAKE256)) /* XOFs */
        {
            c->last.buf[c->last.used] = SHA3_PADDING_RAWXOF2_END;
        }
        else
        {
            c->last.buf[c->last.used] = SHA3_PADDING_STD2_END;
        }
        c->last.used++;
    }
    else /* if (c->last.used == (c->r - 1)) */ /* only 1 bytes left */
    {
        if ((c->alg == SHAKE128) || (c->alg == SHAKE256)) /* XOFs */
        {
            c->last.buf[c->last.used] = SHA3_PADDING_XOF1;
        }
        else if ((c->alg == RAWSHAKE128) || (c->alg == RAWSHAKE256)) /* XOFs */
        {
            c->last.buf[c->last.used] = SHA3_PADDING_RAWXOF1;
        }
        else
        {
            c->last.buf[c->last.used] = SHA3_PADDING_STD1;
        }
        c->last.used++;
    }

    SHA3_ProcessBlock(c, &c->last.buf);
    c->last.used = 0;

    /* Absorbing Phase End */
    c->absorbing = 0;

    dump_lane_buffer(c->lane);

    if (c->md_size <= c->r)
    {
        memcpy(md, &c->lane[0][0], c->md_size);
    }
    else
    {
        memcpy(md, &c->lane[0][0], c->r);
        md_size = c->r;

        /* squeeze */
        while (md_size < c->md_size)
        {
            SHA3_ProcessBlock(c, NULL);
            if (c->md_size - md_size > c->r)
            {
                memcpy(&md[md_size], &c->lane[0][0], c->r);
                md_size += c->r;
            }
            else
            {
                memcpy(&md[md_size], &c->lane[0][0], c->md_size - md_size);
                md_size = c->md_size;
            }
        }
    }

    return ERR_OK;
}

unsigned char *SHA3(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md)
{
    SHA3_CTX c;

    if ((NULL == data) || (NULL == md))
    {
        return NULL;
    }

    SHA3_Init(&c, alg);
    SHA3_Update(&c, data, n);
    SHA3_Final(md, &c);

    return md;
}

int SHA3_XOF_Init(SHA3_CTX *c, SHA3_ALG alg, uint32_t md_size)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    /* only for SHAKE128/SHAKE256 */
    if ((alg != SHAKE128) && (alg != SHAKE256) && (alg != RAWSHAKE128) && (alg != RAWSHAKE256))
    {
        return ERR_INV_PARAM;
    }

    /* using SHA3-512 as default */
    SHA3_Init(c, SHA3_512);

    c->alg = alg;

    /* update for SHAKE128/SHAKE256 */
    switch(alg)
    {
        case SHAKE128:  /* SHAKE128(M,d) = KECCAK[256](M||1111,d), FIPS-202, sec 6.2 */
            c->r = 168; /* 1344 bits */
            c->c = 32;  /*  256 bits */
            c->md_size = md_size;
            break;
        case SHAKE256:  /* SHAKE256(M,d) = KECCAK[512](M||1111,d), FIPS-202, sec 6.2 */
            c->r = 136; /* 1088 bits */
            c->c = 64;  /*  512 bits */
            c->md_size = md_size;
            break;
        case RAWSHAKE128:  /* SHAKE128(M,d) = KECCAK[256](M||1111,d), FIPS-202, sec 6.2 */
            c->r = 168; /* 1344 bits */
            c->c = 32;  /*  256 bits */
            c->md_size = md_size;
            break;
        case RAWSHAKE256:  /* SHAKE256(M,d) = KECCAK[512](M||1111,d), FIPS-202, sec 6.2 */
            c->r = 136; /* 1088 bits */
            c->c = 64;  /*  512 bits */
            c->md_size = md_size;
            break;
        default:;
    }

    return ERR_OK;
}

int SHA3_XOF_Update(SHA3_CTX *c, const void *data, size_t len)
{
    return SHA3_Update(c, data, len);
}

int SHA3_XOF_Final(unsigned char *md, SHA3_CTX *c)
{
    return SHA3_Final(md, c);
}

unsigned char *SHA3_XOF(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t md_size)
{
    SHA3_CTX c;

    if ((NULL == data) || (NULL == md))
    {
        return NULL;
    }

    /* only for SHAKE128/SHAKE256 */
    if ((alg != SHAKE128) && (alg != SHAKE256) && (alg != RAWSHAKE128) && (alg != RAWSHAKE256))
    {
        return NULL;
    }

    SHA3_XOF_Init(&c, alg, md_size);
    SHA3_XOF_Update(&c, data, n);
    SHA3_XOF_Final(md, &c);

    return md;
}

unsigned char *SHA3_SW_HMAC(unsigned char *key, int keylen, unsigned char *text, int textlen, unsigned char *hmac)
{

	unsigned char keypaded[136];
	unsigned char *p;
	int i;


//#1
	memset(keypaded, 0, sizeof(keypaded));
	if(keylen > 136)
	{
		SHA3(SHA3_256, key, keylen, keypaded);
	}
	else
	{
		memcpy(keypaded, key, keylen);
	}

//#2
  //  printk("!!!call kmalloc\n");
	//p = kmalloc(64 + textlen + 32,GFP_KERNEL);
	p = malloc(136 + textlen + 32);
//	printk("!!!end call kmalloc\n");
	if( NULL == p)
		return NULL;

	for(i = 0; i < 136; i++)
		p[i] = keypaded[i] ^ 0x36;
//#3

	memcpy(p + 136, text, textlen);

//#4
	SHA3(SHA3_256, p, 136 + textlen, hmac);

//#5
	for(i = 0; i < 136; i++)
		p[i] = keypaded[i] ^ 0x5C;

//#6
	memcpy(p + 136, hmac, 32);

//#7
	SHA3(SHA3_256, p, 136 + 32, hmac);


	/*kfree(p);*/
	free(p);

	return hmac;
}

unsigned char *SHA3_SW_PRF(unsigned char *key, int keylen, unsigned char *seed, int seedlen, unsigned char *out, int outlen)
{

    uint8_t a[256][256], out_tmp[32];
    int i;        

    SHA3_SW_HMAC(key, keylen, seed, seedlen, a[0]);
    
    for(i = 0; i <(outlen/32) ; i++){ 
        SHA3_SW_HMAC(key, keylen, a[i], 32, a[i+1]);  
        memcpy(a[i] + 32, seed, seedlen);
        SHA3_SW_HMAC(key, keylen, a[i], (32+seedlen), out_tmp);
        memcpy(out + 32*i, out_tmp, 32);
    }            

    return out;
}

#if 1
//---------------------sha3 padding------------------------------//
// void data_dump(const unsigned char* data, unsigned int data_len)
// {
//     int i;
//     for( i=0; i<data_len; i++) {
//         printf("0x%02x ",data[i]);
//         if(((i+1)%16) == 0)
//             printf("\n");
//     }
//     printf("\n");
// }

void swap4b(unsigned char *buff, int len) {
    int i = 0;
    unsigned char tmp = 0;
    /*
    for (start = len -1; start >= 0; start--) {
        if (0x0 != *(buff + start)) break;
    }
    */
    
    if (len % 4 != 0)
        return;

//    start = len -1;
//[1] [2] [3] [4]
    for (i = 0; i < len; i+=4) {
        tmp = *(buff + i);
        *(buff + i) = *(buff + (i + 3));
        *(buff + i + 3) = tmp;
        tmp = *(buff + i + 1);
        *(buff + i + 1) = *(buff + (i + 2));
        *(buff + i + 2) = tmp;
    };
}

uint8_t bit_reverse(uint8_t a)
{
    uint8_t out=0;
#if 1
    int i = 0;
    
    for(i=0;i<8;i++) {
        out = out*2+a%2;
        a /=2;
    }
#else
    out = ((a & 1 ) << 7) | ((a & 2 ) << 5) | ((a & 4 ) << 3) | ((a & 8 ) << 1) | ((a & 16 ) >> 1) | ((a & 32 ) >> 3) | ((a & 64 ) >> 5) | ((a & 128 ) >> 7);
#endif
    return out;
}

void sha3_padding(unsigned char *in , uint32_t in_len, unsigned char *out, uint32_t *out_len)
{
    int n=0,sblock=0,padding_begin = 0x06,padding_end = 0x80;
    uint8_t out_tmp[8192] = {0};
    unsigned char *p_in=in;
    unsigned char *p_out=out_tmp;
    
    sblock = 136;
    if (in_len < sblock) {
        n = 1;
    }
    else {
        n = in_len/sblock + 1;
    }

    memcpy(p_out, p_in, in_len);
    if(in_len%sblock == sblock-1)
        p_out[in_len] = padding_begin + padding_end;
    else{
        p_out[in_len] = padding_begin;
        p_out[sblock*n -1] = padding_end;
    }
    
    memcpy(out,p_out,sblock*n);
    *out_len = sblock*n - in_len;
    
//    printf("sha3_padding sblock=%d padding_len=%d in_len=%d\n",sblock, sblock*n - in_len, in_len);
//    data_dump(out, sblock*n);

}

#endif