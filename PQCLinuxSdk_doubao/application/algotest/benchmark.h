#ifndef __BENCHMARK_H__
#define __BENCHMARK_H__

#include <stdint.h>
#include <pthread.h>

typedef enum hx_cipher_algo_
{
    /* hash/ [0-8]*/
    HX_CIPHER_HASH_SM3=0,
    HX_CIPHER_HASH_SHA256,
    HX_CIPHER_HASH_SHA3,

    HX_CIPHER_HMAC_SM3,
    HX_CIPHER_HMAC_SHA256,
    HX_CIPHER_HMAC_SHA3,

    HX_CIPHER_PRF_SM3,
    HX_CIPHER_PRF_SHA256,
    HX_CIPHER_PRF_SHA3,

    /* cipher: aes [9-28]*/
    HX_CIPHER_AES_ECB_ENC,
    HX_CIPHER_AES_ECB_DEC,
    HX_CIPHER_AES_CBC_ENC,
    HX_CIPHER_AES_CBC_DEC,
    HX_CIPHER_AES_CFB_ENC,
    HX_CIPHER_AES_CFB_DEC,
    HX_CIPHER_AES_OFB_ENC,
    HX_CIPHER_AES_OFB_DEC,
    HX_CIPHER_AES_CTR_ENC,
    HX_CIPHER_AES_CTR_DEC,
    HX_CIPHER_AES_XTS_ENC,
    HX_CIPHER_AES_XTS_DEC,
    HX_CIPHER_AES_CCM_ENC,
    HX_CIPHER_AES_CCM_DEC,
    HX_CIPHER_AES_GCM_ENC,
    HX_CIPHER_AES_GCM_DEC,
    HX_CIPHER_AES_CMAC_ENC,
    HX_CIPHER_AES_CMAC_DEC,
    HX_CIPHER_AES_CBC_MAC_ENC,
    HX_CIPHER_AES_CBC_MAC_DEC, 

    /* cipher: sm4 [29-48]*/
    HX_CIPHER_SM4_ECB_ENC,
    HX_CIPHER_SM4_ECB_DEC,
    HX_CIPHER_SM4_CBC_ENC,
    HX_CIPHER_SM4_CBC_DEC,
    HX_CIPHER_SM4_CFB_ENC,
    HX_CIPHER_SM4_CFB_DEC,
    HX_CIPHER_SM4_OFB_ENC,
    HX_CIPHER_SM4_OFB_DEC,
    HX_CIPHER_SM4_CTR_ENC,
    HX_CIPHER_SM4_CTR_DEC,
    HX_CIPHER_SM4_XTS_ENC,
    HX_CIPHER_SM4_XTS_DEC,
    HX_CIPHER_SM4_CCM_ENC,
    HX_CIPHER_SM4_CCM_DEC,
    HX_CIPHER_SM4_GCM_ENC,
    HX_CIPHER_SM4_GCM_DEC,
    HX_CIPHER_SM4_CMAC_ENC,
    HX_CIPHER_SM4_CMAC_DEC,
    HX_CIPHER_SM4_CBC_MAC_ENC,
    HX_CIPHER_SM4_CBC_MAC_DEC,

    HX_CIPHER_ALL,
    HX_CIPHER_MAX,
} hx_cipher_algo_e;

struct hx_cipher_algo_param{
    int benchmark_id;
	char name[32];
    int algo_id;
    int algo_mode;
    int algo_dir;
    int keylen;
    int ivlen;
    int taglen;
};

typedef struct functional_
{
    int fd;
    int algo;
    int api_mode;
    uint8_t dev;
    uint8_t check_rst;
} functional_t;

typedef struct benchmark_
{
    int function;
    int fd;
    int algo;
    int api_mode;
    uint8_t step;/* 0: full pack 1: half pack */
    uint8_t dev;
    uint8_t check_rst;
    int process_num;
    int thread_num;
    int test_time; /* per minute*/
    uint32_t size;
    uint32_t mode;
    uint32_t loop;
    uint16_t step_len;
    uint8_t key_size;
} benchmark_t;

#endif 


