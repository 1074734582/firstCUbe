#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <assert.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <openssl/rand.h>
#include <dlfcn.h>

#include "api.h"
#include "benchmark.h"
#include "atomic.h"
#include "data.h"
#include "pqcdata/pqc_data.h"
#include "crypto_api.h"
#include "dev.h"

const char *hx_dev_name = "hx_dev_01";

uint8_t SM2_ALGO_NAME[5][20] = 
{
    "sm2 sign",
    "sm2 verify",
    "sm2 kp",
    "sm2 kg",
    "sm2 sign trng",
};

uint8_t ECC_ALGO_NAME[5][20] = 
{
    "ecc sign",
    "ecc verify",
    "ecc kp",
    "ecc kg",
    "ecc sign trng",
};

uint8_t RSA_ALGO_NAME[6][20] =
{
    "rsa sign 1024",
    "rsa sign 1024 crt",
    "rsa verify 1024",
    "rsa sign 2048",
    "rsa sign 2048 crt",
    "rsa verify 2048",
};

uint8_t PQC_ALGO_NAME[24][20] = 
{
    "kyber kg",
    "kyber enc",
    "kyber dec",
    "aigis kg",
    "aigis enc",
    "aigis dec",
    "lac kg",
    "lac enc",
    "lac dec",
    "sphincs kg",
    "sphincs enc",
    "sphincs dec",
    "hqc kg",
    "hqc enc",
    "hqc dec",
    "bike enc",
    "bike dec",
    "mceliece enc",
    "mceliece dec",
    "dili2 kg",
    "dili2 enc",
    "dili2 dec",
    "falcon enc",
    "falcon dec",
};

static inline uint64_t time_delta(struct timespec *start, struct timespec *end)
{
	uint64_t diff;

	if ((end->tv_nsec - start->tv_nsec) < 0) {
		diff = (uint64_t)(end->tv_sec - start->tv_sec - 1) * 1000000000;
		diff += 1000000000 + (uint64_t)(end->tv_nsec - start->tv_nsec);
	} else {
		diff = (uint64_t)(end->tv_sec - start->tv_sec) * 1000000000;
		diff += (uint64_t)(end->tv_nsec - start->tv_nsec);
	}
	return diff;
}

static inline uint64_t time_calculate(struct timespec *start, struct timespec *end, uint32_t size)
{
    uint64_t time_us = time_delta(start, end) / 1000;
    uint64_t bits = size * 8;

    float time_ms = (float)(time_us)/1000.0;
    float bps = (float)bits/time_ms*1000;
    float Mbps =  bps/1000/1000;

    uint64_t MBytes = size/1024/1024;
    uint64_t KBytes = size/1024;

    if(MBytes/10)
        printf("%-6f(ms), %lu(MBytes), %6.2f(Mbps)\n", time_ms, MBytes,  Mbps);
    else
        printf("%-6f(ms), %lu(KBytes), %6.2f(Mbps)\n", time_ms, KBytes,  Mbps);

    return 0;
}

static inline uint64_t loop_time_calculate(struct timespec *start, struct timespec *end, uint8_t mode, uint32_t loop)
{
    uint64_t time_us = time_delta(start, end) / 1000;
    float time_ms = (float)(time_us)/1000.0;
    float times = loop * 1000 / time_ms;

    printf("Run \033[0m\033[1;32m%s\033[0m, %d times need %-6f ms, %6.2f times per second\r\n", 
            PQC_ALGO_NAME[mode], loop, time_ms, times);
    return 0;
}

uint8_t *getrandom(uint32_t size, uint32_t id)
{
    static uint8_t random_data[512];
    uint32_t *data = (uint32_t *)random_data;
    uint32_t loop = size / sizeof(uint32_t);

    if(size > 512)
    {
        printf("getrandom exceed max size\r\n");
        return random_data;
    }

    srandom(time(NULL) ^ id);

    for(int i=0; i< loop; i++)
        data[i] = random();

    return random_data;
}

int crypto_sm2_gen_key(uint8_t algo, uint8_t *da, uint8_t *pa)
{
    if(algo == HX_SM2)
        crypto_sm2_gen_keypair(da, pa);
    else
        crypto_ecc_gen_keypair(da, pa);

    return 0;
}

int sm2_build_debug_data(hx_sm2_pkg_t *sm2_pkg, uint8_t algo, uint8_t mode, int i)
{
    if(mode == HX_SM2_SIGN)
    {
#if 1         
        memcpy(sm2_pkg->data[i].message, hash_value, HX_SM2_MESSAGE_LEN);
        memcpy(sm2_pkg->data[i].da, private_key, HX_SM2_DA_LEN);
        memcpy(sm2_pkg->data[i].pa, public_key, HX_SM2_PA_LEN);
        memcpy(sm2_pkg->data[i].random, random_k, HX_SM2_RANDOM_LEN); 
#else
        memcpy(sm2_pkg->data[i].message, &sm2_debug_data[i*96], HX_SM2_MESSAGE_LEN);
        memcpy(sm2_pkg->data[i].da, &sm2_debug_data[i*96+32], HX_SM2_DA_LEN);
        memcpy(sm2_pkg->data[i].random, &sm2_debug_data[i*96+32+32], HX_SM2_RANDOM_LEN);
#endif
    }
    else if(mode == HX_SM2_VERIFY)
    {
        memcpy(sm2_pkg->data[i].message, hash_value, HX_SM2_MESSAGE_LEN);
        memcpy(sm2_pkg->data[i].pa, public_key, HX_SM2_PA_LEN);
        memcpy(sm2_pkg->data[i].verify, verify_value, HX_SM2_VERIFY_LEN);           
    }
    else if(mode == HX_SM2_KG)
    {
        memcpy(sm2_pkg->data[i].da, private_key, HX_SM2_DA_LEN); 
    }

    return 0;
}

int sm2_build_random_data(hx_sm2_pkg_t *sm2_pkg, uint8_t algo, uint8_t mode, int i)
{
    if(mode == HX_SM2_SIGN)
    { 
        memcpy(sm2_pkg->data[i].message, getrandom(HX_SM2_MESSAGE_LEN, i), HX_SM2_MESSAGE_LEN);
        crypto_sm2_gen_key(algo, sm2_pkg->data[i].da, sm2_pkg->data[i].pa);
        memcpy(sm2_pkg->data[i].random, getrandom(HX_SM2_RANDOM_LEN, i+0x5F), HX_SM2_RANDOM_LEN);
    }
    else if(mode == HX_SM2_VERIFY)
    {
        memcpy(sm2_pkg->data[i].message, getrandom(HX_SM2_MESSAGE_LEN, i), HX_SM2_MESSAGE_LEN);
        crypto_sm2_gen_key(algo, sm2_pkg->data[i].da, sm2_pkg->data[i].pa);  
        if(algo == HX_SM2)
            crypto_sm2_sign(sm2_pkg->data[i].da, sm2_pkg->data[i].message, sm2_pkg->data[i].verify);       
        else
            crypto_ecc_sign(sm2_pkg->data[i].da, sm2_pkg->data[i].message, sm2_pkg->data[i].verify);    
    }
    else if(mode == HX_SM2_KP)
    {
        static uint8_t da[32], da_2[32];
        static uint8_t pa[64], pa_2[64];
        if(i == 0)
        {
            crypto_sm2_gen_key(algo, da, pa);
            crypto_sm2_gen_key(algo, da_2, pa_2);
            memcpy(sm2_pkg->data[i].da, da, HX_SM2_DA_LEN);
            memcpy(sm2_pkg->data[i].pa, pa_2, HX_SM2_PA_LEN);
        }
        else
        {
            memcpy(sm2_pkg->data[i].da, da_2, HX_SM2_DA_LEN);
            memcpy(sm2_pkg->data[i].pa, pa, HX_SM2_PA_LEN);
        }
    }
    else if(mode == HX_SM2_KG)
    {
        memcpy(sm2_pkg->data[i].da, getrandom(HX_SM2_DA_LEN, i), HX_SM2_DA_LEN);
    }
    else if(mode == HX_SM2_SIGN_TRNG)
    {
        memcpy(sm2_pkg->data[i].message, getrandom(HX_SM2_MESSAGE_LEN, i), HX_SM2_MESSAGE_LEN);
        crypto_sm2_gen_key(algo, sm2_pkg->data[i].da, sm2_pkg->data[i].pa);     
    }

    return 0;
}

int hx_pub_sm2_init_pkg(hx_sm2_pkg_t **sm2_pkg_t, uint8_t algo, uint8_t mode, uint32_t sm2_num, uint32_t *sm2_pkg_len)
{
    hx_sm2_pkg_t *sm2_pkg = NULL;

    *sm2_pkg_len = sizeof(hx_sm2_pkg_t) + sm2_num * sizeof(hx_sm2_data_t);
    sm2_pkg = malloc(*sm2_pkg_len);
    *sm2_pkg_t = sm2_pkg;
    sm2_pkg->size = sm2_num;
    sm2_pkg->addr = (uint64_t)sm2_pkg->data;

    for(int i=0; i<sm2_num; i++)
    {
        sm2_pkg->data[i].id = i;
#if DATA_DEBUG
        sm2_build_debug_data(sm2_pkg, algo, mode, i);   
#else
        sm2_build_random_data(sm2_pkg, algo, mode, i);
#endif
    }   

    return 0;
}

int hx_pub_sm2_init_res(hx_sm2_result_t **sm2_res_t, uint8_t algo, uint8_t mode, uint32_t sm2_num, uint32_t *sm2_res_len)
{
    hx_sm2_result_t *sm2_res = NULL;

    *sm2_res_len = sizeof(hx_sm2_result_t) + sm2_num * sizeof(hx_sm2_output_t);
    sm2_res = malloc(*sm2_res_len);
    *sm2_res_t = sm2_res;
    sm2_res->size = sm2_num;
    sm2_res->addr = (uint64_t)sm2_res->data;
    sm2_res->index = 0;

    return 0;
}

int hx_pub_sm2_compare(hx_sm2_pkg_t *sm2_pkg, hx_sm2_result_t *sm2_res, uint8_t algo, uint8_t mode, uint32_t sm2_num)
{
    int verify = 0;
    int i = 0, j = 0;
    hx_sm2_output_t temp;

    for(i=0; i<sm2_num-1; i++)
    {
        for(j=0; j<sm2_num-i-1; j++)
        {
            if(sm2_res->data[j].id > sm2_res->data[j+1].id)
            {
                memcpy(&temp, &sm2_res->data[j], sizeof(hx_sm2_output_t));
                memcpy(&sm2_res->data[j], &sm2_res->data[j+1], sizeof(hx_sm2_output_t));
                memcpy(&sm2_res->data[j+1], &temp, sizeof(hx_sm2_output_t));               
            }
        }
    }

    for(i=0; i<sm2_num; i++)
    {
        if(mode == HX_SM2_SIGN)
        {
            if(algo == HX_SM2)       
                verify = crypto_sm2_verify(sm2_pkg->data[i].pa, sm2_pkg->data[i].message, sm2_res->data[i].output); 
            else
                verify = crypto_ecc_verify(sm2_pkg->data[i].pa, sm2_pkg->data[i].message, sm2_res->data[i].output); 
            if(!verify)
            {
                printf("SM2 sign fail, i=%d\r\n", i);
                return 1;
            }
        }
        else if(mode == HX_SM2_VERIFY)
        {
            verify = sm2_res->data[i].output[0];
            if(!verify)
            {
                printf("SM2 verify fail, i=%d\r\n", i);
                return 1;
            }
        }
        else if(mode == HX_SM2_KP)
        {
            if(memcmp(sm2_res->data[0].output, sm2_res->data[i].output, sizeof(sm2_res->data[i].output)))
            {
                printf("SM2 kp fail, i=%d\r\n", i);
                return 1;
            }
        }
        else if(mode == HX_SM2_KG)
        {
            
        }
        else if(mode == HX_SM2_SIGN_TRNG)
        {
            if(algo == HX_SM2)       
                verify = crypto_sm2_verify(sm2_pkg->data[i].pa, sm2_pkg->data[i].message, sm2_res->data[i].output); 
            else
                verify = crypto_ecc_verify(sm2_pkg->data[i].pa, sm2_pkg->data[i].message, sm2_res->data[i].output); 
            if(!verify)
            {
                printf("SM2 sign fail, i=%d\r\n", i);
                return 1;
            }
        }
    }

    printf("SM2 compare with openssl success\r\n");

    return 0;
}

int hx_data_print(uint8_t *data, uint32_t size)
{
    for(int i=0; i<size; i++)
    {
        printf("0x%02x,", data[i]);
        if((i+1) % 16 == 0)
            printf("\r\n");
    } 

    return 0;
}

int hx_sm2_data_dump(hx_sm2_pkg_t *sm2_pkg, int mode, int loop)
{
    for(int i=0; i<loop; i++)
    {
        printf("//i=%d\r\n", i);
        if(mode == HX_SM2_SIGN)
        {
            hx_data_print(sm2_pkg->data[i].message, HX_SM2_MESSAGE_LEN);
            hx_data_print(sm2_pkg->data[i].da, HX_SM2_DA_LEN);
            hx_data_print(sm2_pkg->data[i].random, HX_SM2_RANDOM_LEN);
        }
        else if(mode == HX_SM2_VERIFY)
        {
            hx_data_print(sm2_pkg->data[i].message, HX_SM2_MESSAGE_LEN);
            hx_data_print(sm2_pkg->data[i].pa, HX_SM2_PA_LEN);
            hx_data_print(sm2_pkg->data[i].verify, HX_SM2_VERIFY_LEN);           
        }
        else if(mode == HX_SM2_KP)
        {
            hx_data_print(sm2_pkg->data[i].da, HX_SM2_DA_LEN);
            hx_data_print(sm2_pkg->data[i].pa, HX_SM2_PA_LEN);            
        }
        else if(mode == HX_SM2_KG)
        {
            hx_data_print(sm2_pkg->data[i].da, HX_SM2_DA_LEN);
        }
        else
        {
            hx_data_print(sm2_pkg->data[i].message, HX_SM2_MESSAGE_LEN);
            hx_data_print(sm2_pkg->data[i].da, HX_SM2_DA_LEN);            
        }
    }

    return 0;
}

int hx_rpu_pub_sm2(int fd, int algo, int mode, int loop)
{
    int ret = HX_RET_FAILED;
    uint32_t sm2_num = loop;

    hx_cipher_t *cipher = (hx_cipher_t *)malloc(sizeof(hx_cipher_t));
    hx_session_t sess;
    memset(cipher, 0, sizeof(hx_cipher_t));
    cipher->sess = &sess;
    cipher->sess->mode = HX_SYNC_MODE;
    cipher->fd = fd;
    cipher->algo = algo;
    cipher->mode = mode;

    hx_sm2_pkg_t *sm2_pkg = NULL;
    uint32_t sm2_pkg_len = 0;
    hx_pub_sm2_init_pkg(&sm2_pkg, algo, mode, sm2_num, &sm2_pkg_len);

    hx_sm2_result_t *sm2_res = NULL;
    uint32_t sm2_res_len = 0;
    hx_pub_sm2_init_res(&sm2_res, algo, mode, sm2_num, &sm2_res_len);

    cipher->src = (uint8_t *)sm2_pkg;
    cipher->srclen = sm2_pkg_len;
    cipher->dst = (uint8_t *)sm2_res;
    cipher->dstlen = sm2_res_len;    

    struct timespec start, stop;
    clock_gettime(CLOCK_REALTIME, &start);

    ret = hx_ioctl_pub_do(cipher);

    clock_gettime(CLOCK_REALTIME, &stop);
    uint64_t time_us = time_delta(&start, &stop) / 1000;
    float time_ms = (float)(time_us)/1000.0;
    float times = loop * 1000 / time_ms;

    if(algo == HX_SM2)
        printf("Run \033[0m\033[1;32m%s\033[0m, %d times need %-6f ms, %6.2f times per second\r\n", 
                SM2_ALGO_NAME[mode], loop, time_ms, times);
    else
        printf("Run \033[0m\033[1;32m%s\033[0m, %d times need %-6f ms, %6.2f times per second\r\n", 
                ECC_ALGO_NAME[mode], loop, time_ms, times);        

    if(ret)
        hx_sm2_data_dump(sm2_pkg, mode, loop);

    if(ret == HX_RET_SUCCESS)
        ret = hx_pub_sm2_compare(sm2_pkg, sm2_res, algo, mode, sm2_num);

    free(sm2_pkg);
    free(sm2_res);
    free(cipher);

    return ret;
}

int rsa_build_debug_data(hx_rsa_pkg_t *rsa_pkg, uint8_t mode, int i)
{
    if(mode == HX_RSA_SIGN_1024)
    { 
        memcpy(rsa_pkg->data[i].message, rsa_1024, HX_RSA_1024_LEN);
        memcpy(rsa_pkg->data[i].d, d_1024, HX_RSA_1024_LEN);
        memcpy(rsa_pkg->data[i].N, N_1024, HX_RSA_1024_LEN);
    }
    else if(mode == HX_RSA_SIGN_1024_CRT)
    {
        memcpy(rsa_pkg->data[i].message, rsa_1024, HX_RSA_1024_LEN);
        memcpy(rsa_pkg->data[i].dp, Dp_1024, HX_RSA_CRT_1024_LEN);
        memcpy(rsa_pkg->data[i].dq, Dq_1024, HX_RSA_CRT_1024_LEN);
        memcpy(rsa_pkg->data[i].p, P_1024, HX_RSA_CRT_1024_LEN);
        memcpy(rsa_pkg->data[i].q, Q_1024, HX_RSA_CRT_1024_LEN);
        memcpy(rsa_pkg->data[i].qinv, Qinv, HX_RSA_CRT_1024_LEN);            
    }
    else if(mode == HX_RSA_VERIFY_1024)
    {
        memcpy(rsa_pkg->data[i].message, sign_1024, HX_RSA_1024_LEN);
        memcpy(rsa_pkg->data[i].e, e_1024, HX_RSA_1024_LEN);
        memcpy(rsa_pkg->data[i].N, N_1024, HX_RSA_1024_LEN);           
    }
    else if(mode == HX_RSA_SIGN_2048)
    {
        memcpy(rsa_pkg->data[i].message, rsa_2048, HX_RSA_2048_LEN);
        memcpy(rsa_pkg->data[i].d, d_2048, HX_RSA_2048_LEN);
        memcpy(rsa_pkg->data[i].N, N_2048, HX_RSA_2048_LEN);        
    }
    else if(mode == HX_RSA_SIGN_2048_CRT)
    {
        memcpy(rsa_pkg->data[i].message, rsa_2048, HX_RSA_2048_LEN);
        memcpy(rsa_pkg->data[i].dp, Dp_2048, HX_RSA_CRT_2048_LEN);
        memcpy(rsa_pkg->data[i].dq, Dq_2048, HX_RSA_CRT_2048_LEN);
        memcpy(rsa_pkg->data[i].p, P_2048, HX_RSA_CRT_2048_LEN);
        memcpy(rsa_pkg->data[i].q, Q_2048, HX_RSA_CRT_2048_LEN);
        memcpy(rsa_pkg->data[i].qinv, Qinv_2048, HX_RSA_CRT_2048_LEN);        
    }
    else if(mode == HX_RSA_VERIFY_2048)
    {
        memcpy(rsa_pkg->data[i].message, sign_2048, HX_RSA_2048_LEN);
        memcpy(rsa_pkg->data[i].e, e_2048, HX_RSA_2048_LEN);
        memcpy(rsa_pkg->data[i].N, N_2048, HX_RSA_2048_LEN); 
    }
    else
        printf("rsa_build_debug_data not support, mode = %d\r\n", mode);

    return 0;
}

int rsa_crypto_gen_key(int key_size, uint8_t *d, uint8_t *e, uint8_t *N)
{
    crypto_rsa_key_t rsa_key;
    rsa_key.bits = key_size;

    crypto_rsa_gen_keypair(&rsa_key);

    memcpy(d, rsa_key.d, key_size/8);
    memcpy(e, rsa_key.e, key_size/8);
    memcpy(N, rsa_key.n, key_size/8);

    return 0;
}

int rsa_crypto_gen_crt_key(int key_size, uint8_t *e, uint8_t *N, uint8_t *dp, uint8_t *dq, 
                            uint8_t *p, uint8_t *q, uint8_t *qinv)
{
    crypto_rsa_key_t rsa_key;
    rsa_key.bits = key_size;

    crypto_rsa_gen_keypair(&rsa_key);

    memcpy(e, rsa_key.e, key_size/8);
    memcpy(N, rsa_key.n, key_size/8);

    memcpy(dp, rsa_key.dmp1, key_size/16);
    memcpy(dq, rsa_key.dmq1, key_size/16);
    memcpy(p, rsa_key.p, key_size/16);
    memcpy(q, rsa_key.q, key_size/16);
    memcpy(qinv, rsa_key.iqmp, key_size/16);

    return 0;
}

int rsa_crypto_sign(int key_size, uint8_t *d, uint8_t *e, uint8_t *N, uint8_t *in, uint8_t *out)
{
    crypto_rsa_key_t rsa_key;
    rsa_key.bits = key_size;

    memcpy(rsa_key.d, d, key_size/8);
    memcpy(rsa_key.e, e, key_size/8);
    memcpy(rsa_key.n, N, key_size/8);   

    crypto_rsa_priv_enc(&rsa_key, in, out);     

    return 0;
}

int rsa_crypto_verify(int key_size, uint8_t *d, uint8_t *e, uint8_t *N, uint8_t *in, uint8_t *out)
{
    crypto_rsa_key_t rsa_key;
    rsa_key.bits = key_size;

    memcpy(rsa_key.d, d, key_size/8);
    memcpy(rsa_key.e, e, key_size/8);
    memcpy(rsa_key.n, N, key_size/8);   

    crypto_rsa_pub_dec(&rsa_key, in, out);     

    return 0;
}

int rsa_build_random_data(hx_rsa_pkg_t *rsa_pkg, uint8_t mode, int i)
{
    if(mode == HX_RSA_SIGN_1024 || mode == HX_RSA_VERIFY_1024)
    { 
        memcpy(rsa_pkg->data[i].message, getrandom(HX_RSA_1024_LEN, i), HX_RSA_1024_LEN);
        rsa_crypto_gen_key(1024, rsa_pkg->data[i].d, rsa_pkg->data[i].e, rsa_pkg->data[i].N);
    }
    else if(mode == HX_RSA_SIGN_1024_CRT)
    {
        memcpy(rsa_pkg->data[i].message, getrandom(HX_RSA_1024_LEN, i), HX_RSA_1024_LEN);
        rsa_crypto_gen_crt_key(1024, rsa_pkg->data[i].e, rsa_pkg->data[i].N, rsa_pkg->data[i].dp, rsa_pkg->data[i].dq, 
                                rsa_pkg->data[i].p, rsa_pkg->data[i].q, rsa_pkg->data[i].qinv);           
    }
    else if(mode == HX_RSA_SIGN_2048 || mode == HX_RSA_VERIFY_2048)
    {
        memcpy(rsa_pkg->data[i].message, getrandom(HX_RSA_2048_LEN, i), HX_RSA_2048_LEN);
        rsa_crypto_gen_key(2048, rsa_pkg->data[i].d, rsa_pkg->data[i].e, rsa_pkg->data[i].N);     
    }
    else if(mode == HX_RSA_SIGN_2048_CRT)
    {
        memcpy(rsa_pkg->data[i].message, getrandom(HX_RSA_2048_LEN, i), HX_RSA_2048_LEN);
        rsa_crypto_gen_crt_key(2048, rsa_pkg->data[i].e, rsa_pkg->data[i].N, rsa_pkg->data[i].dp, rsa_pkg->data[i].dq, 
                                rsa_pkg->data[i].p, rsa_pkg->data[i].q, rsa_pkg->data[i].qinv);        
    }
    else
        printf("rsa_build_debug_data not support, mode = %d\r\n", mode);

    rsa_pkg->data[i].message[0] = 0x80;//openssl rsa bug

    return 0;
}

int hx_pub_rsa_init_pkg(hx_rsa_pkg_t **rsa_pkg_t, uint8_t algo, uint8_t mode, uint32_t rsa_num, uint32_t *rsa_pkg_len)
{
    hx_rsa_pkg_t *rsa_pkg = NULL;

    *rsa_pkg_len = sizeof(hx_rsa_pkg_t) + rsa_num * sizeof(hx_rsa_data_t);
    rsa_pkg = malloc(*rsa_pkg_len);
    *rsa_pkg_t = rsa_pkg;
    rsa_pkg->size = rsa_num;
    rsa_pkg->addr = (uint64_t)rsa_pkg->data;

    for(int i=0; i<rsa_num; i++)
    {
        rsa_pkg->data[i].id = i;
#if DATA_DEBUG
        rsa_build_debug_data(rsa_pkg, mode, i);
#else
        rsa_build_random_data(rsa_pkg, mode, i);
#endif          
    }   

    return 0;
}

int hx_pub_rsa_init_res(hx_rsa_result_t **rsa_res_t, uint8_t algo, uint8_t mode, uint32_t sm2_num, uint32_t *rsa_res_len)
{
    hx_rsa_result_t *rsa_res = NULL;

    *rsa_res_len = sizeof(hx_rsa_result_t) + sm2_num * sizeof(hx_rsa_output_t);
    rsa_res = malloc(*rsa_res_len);
    *rsa_res_t = rsa_res;
    rsa_res->size = sm2_num;
    rsa_res->addr = (uint64_t)rsa_res->data;
    rsa_res->index = 0;

    return 0;
}

int hx_pub_rsa_compare(hx_rsa_pkg_t *rsa_pkg, hx_rsa_result_t *rsa_res, uint8_t algo, uint8_t mode, uint32_t rsa_num)
{
    int i = 0, j = 0;
    hx_rsa_output_t temp;
    uint8_t rsa_output[HX_RSA_2048_LEN];

    for(i=0; i<rsa_num-1; i++)
    {
        for(j=0; j<rsa_num-i-1; j++)
        {
            if(rsa_res->data[j].id > rsa_res->data[j+1].id)
            {
                memcpy(&temp, &rsa_res->data[j], sizeof(hx_rsa_output_t));
                memcpy(&rsa_res->data[j], &rsa_res->data[j+1], sizeof(hx_rsa_output_t));
                memcpy(&rsa_res->data[j+1], &temp, sizeof(hx_rsa_output_t));               
            }
        }
    }

    for(i=0; i<rsa_num; i++)
    {
        if(mode == HX_RSA_SIGN_1024)
        {
            rsa_crypto_sign(1024, rsa_pkg->data[i].d, rsa_pkg->data[i].e, rsa_pkg->data[i].N, 
                                rsa_pkg->data[i].message, rsa_output);
            if(0 != memcmp(rsa_res->data[i].output, rsa_output, HX_RSA_1024_LEN))
            {
                printf("hx_pub_rsa_compare, rsa sign fail, i=%d\r\n", i);
                return 1;               
            }
        }
        else if (mode == HX_RSA_SIGN_1024_CRT)
        {
            rsa_crypto_verify(1024, rsa_pkg->data[i].d, rsa_pkg->data[i].e, rsa_pkg->data[i].N, 
                                rsa_res->data[i].output, rsa_output);
            if(0 != memcmp(rsa_pkg->data[i].message, rsa_output, HX_RSA_1024_LEN))
            {
                printf("hx_pub_rsa_compare, rsa verify fail, i=%d\r\n", i);
                return 1;               
            }
        }
        else if(mode == HX_RSA_VERIFY_1024)
        {
            rsa_crypto_verify(1024, rsa_pkg->data[i].d, rsa_pkg->data[i].e, rsa_pkg->data[i].N, 
                                rsa_pkg->data[i].message, rsa_output);
            if(0 != memcmp(rsa_res->data[i].output, rsa_output, HX_RSA_1024_LEN))
            {
                printf("hx_pub_rsa_compare, rsa verify fail, i=%d\r\n", i);
                return 1;               
            }                                         
        }
        else if(mode == HX_RSA_SIGN_2048)
        {
            rsa_crypto_sign(2048, rsa_pkg->data[i].d, rsa_pkg->data[i].e, rsa_pkg->data[i].N, 
                                rsa_pkg->data[i].message, rsa_output);
            if(0 != memcmp(rsa_res->data[i].output, rsa_output, HX_RSA_2048_LEN))
            {
                printf("hx_pub_rsa_compare, rsa sign fail, i=%d\r\n", i);
                return 1;               
            }          
        }
        else if(mode == HX_RSA_SIGN_2048_CRT)
        {
            rsa_crypto_verify(2048, rsa_pkg->data[i].d, rsa_pkg->data[i].e, rsa_pkg->data[i].N, 
                                rsa_res->data[i].output, rsa_output);
            if(0 != memcmp(rsa_pkg->data[i].message, rsa_output, HX_RSA_2048_LEN))
            {
                printf("hx_pub_rsa_compare, rsa verify fail, i=%d\r\n", i);
                return 1;               
            }   
        }
        else if(mode == HX_RSA_VERIFY_2048)
        {
            rsa_crypto_verify(2048, rsa_pkg->data[i].d, rsa_pkg->data[i].e, rsa_pkg->data[i].N, 
                                rsa_pkg->data[i].message, rsa_output);
            if(0 != memcmp(rsa_res->data[i].output, rsa_output, HX_RSA_2048_LEN))
            {
                printf("hx_pub_rsa_compare, rsa verify fail, i=%d\r\n", i);
                return 1;               
            }                                         
        }
        else
            hx_dump_buf("rsa:", rsa_res->data[i].output, HX_RSA_2048_LEN);
    }

    printf("rsa compare with openssl success\r\n");

    return 0;
}

int hx_rpu_pub_rsa(int fd, int algo, int mode, int loop)
{
    int ret = HX_RET_FAILED;
    uint32_t rsa_num = loop;

    hx_cipher_t *cipher = (hx_cipher_t *)malloc(sizeof(hx_cipher_t));
    hx_session_t sess;
    memset(cipher, 0, sizeof(hx_cipher_t));
    cipher->sess = &sess;
    cipher->sess->mode = HX_SYNC_MODE;
    cipher->fd = fd;
    cipher->algo = algo;
    cipher->mode = mode;

    hx_rsa_pkg_t *rsa_pkg = NULL;
    uint32_t rsa_pkg_len = 0;
    hx_pub_rsa_init_pkg(&rsa_pkg, algo, mode, rsa_num, &rsa_pkg_len);

    hx_rsa_result_t *rsa_res = NULL;
    uint32_t rsa_res_len = 0;
    hx_pub_rsa_init_res(&rsa_res, algo, mode, rsa_num, &rsa_res_len);

    cipher->src = (uint8_t *)rsa_pkg;
    cipher->srclen = rsa_pkg_len;
    cipher->dst = (uint8_t *)rsa_res;
    cipher->dstlen = rsa_res_len;    

    struct timespec start, stop;
    clock_gettime(CLOCK_REALTIME, &start);

    ret = hx_ioctl_pub_do(cipher);

    clock_gettime(CLOCK_REALTIME, &stop);
    uint64_t time_us = time_delta(&start, &stop) / 1000;
    float time_ms = (float)(time_us)/1000.0;
    float times = loop * 1000 / time_ms;

    printf("Run \033[0m\033[1;32m%s\033[0m, %d times need %-6f ms, %6.2f times per second\r\n", 
            RSA_ALGO_NAME[mode], loop, time_ms, times); 

    if(ret == HX_RET_SUCCESS)
        ret = hx_pub_rsa_compare(rsa_pkg, rsa_res, algo, mode, rsa_num);

    free(rsa_pkg);
    free(rsa_res);
    free(cipher);

    return ret;
}

int hx_rpu_pub_trng(int fd, int algo, int mode, int trng_num)
{
    int ret = HX_RET_SUCCESS;
    uint32_t trng_len = HX_TRNG_PKG_LEN * trng_num;

    hx_cipher_t *cipher = (hx_cipher_t *)malloc(sizeof(hx_cipher_t));
    hx_session_t sess;
    memset(cipher, 0, sizeof(hx_cipher_t));
    cipher->sess = &sess;
    cipher->sess->mode = HX_SYNC_MODE;
    cipher->fd = fd;
    cipher->algo = algo;
    cipher->mode = mode;

    if(trng_num > 255)
    {
        printf("pub trng max num is 255\r\n");
        return HX_RET_FAILED;
    }

    uint8_t *trng = malloc(trng_len);
    memset(trng, 0 ,sizeof(trng_len));

    cipher->src = NULL;
    cipher->srclen = 0;
    cipher->dst = trng;
    cipher->dstlen = trng_len;  

    struct timespec start, stop;
    clock_gettime(CLOCK_REALTIME, &start);

    ret = hx_ioctl_pub_do(cipher);

    clock_gettime(CLOCK_REALTIME, &stop);
    time_calculate(&start, &stop, trng_len);

    hx_dump_buf("trng", trng, 64);
    //hx_dump_data32("trng", trng, 1040);

    free(trng);
    free(cipher);

    return ret;
}

int get_pqc_req_len(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return DATA_64_ALIGN(KYBER512_SEED_LEN);
        case HX_KYBER512_SIGN:
            return DATA_64_ALIGN(KYBER512_SEED_LEN) + DATA_64_ALIGN(KYBER512_PK_LEN);
        case HX_KYBER512_VERIFY:
            return DATA_64_ALIGN(KYBER512_CT_LEN) + DATA_64_ALIGN(KYBER512_SK_LEN);
        case HX_AIGIS_KG:
            return DATA_64_ALIGN(AIGIS_SEED_LEN);
        case HX_AIGIS_SIGN:
            return DATA_64_ALIGN(AIGIS_SEED_LEN) + DATA_64_ALIGN(AIGIS_PK_LEN);
        case HX_AIGIS_VERIFY:
            return DATA_64_ALIGN(AIGIS_CT_LEN) + DATA_64_ALIGN(AIGIS_SK_LEN);
        case HX_LAC128_KG:
            return LAC_SEED_LEN; //must 32, 64 cause error
        case HX_LAC128_SIGN:
            return DATA_64_ALIGN(LAC_MSG_SEED_LEN) + DATA_64_ALIGN(LAC_PK_LEN);
        case HX_LAC128_VERIFY:
            return DATA_64_ALIGN((LAC_SK_LEN-LAC_PK_LEN)) + DATA_64_ALIGN(LAC_CT_LEN) + DATA_64_ALIGN(LAC_PK_LEN);
        case HX_SPHINCS_KG:
            return DATA_64_ALIGN(SPHINCS_SEED_LEN);
        case HX_SPHINCS_SIGN:
            return SPHINCS_SK_LEN + SPHINCS_SIGN_SEED_LEN + DATA_48_ALIGN(SPHINCS_MSG_LEN);
        case HX_SPHINCS_VERIFY:
            return DATA_64_ALIGN(SPHINCS_PK_LEN) + DATA_64_ALIGN(SPHINCS_MSG_LEN) + DATA_64_ALIGN(SPHINCS_SIGN_LEN*4);
        case HX_HQC_KG:
            return DATA_64_ALIGN(HQC_SEED_LEN/2) + DATA_64_ALIGN(HQC_SEED_LEN/2);
        case HX_HQC_SIGN:
            return DATA_64_ALIGN(HQC_M_LEN)+DATA_64_ALIGN(HQC_SAULT_LEN)+DATA_64_ALIGN(HQC_SEED_LEN/2)+DATA_64_ALIGN(HQC_PK_LEN-HQC_SEED_LEN/2);
        case HX_HQC_VERIFY:
            return DATA_64_ALIGN(HQC_SEED_LEN) + DATA_64_ALIGN(HQC_SK_LEN-HQC_SEED_LEN) + DATA_64_ALIGN(HQC_CT_LEN);
        case HX_BIKE_SIGN:
            return DATA_64_ALIGN(BIKE_PK_LEN) + BIKE_MSG_SEED_LEN;
        case HX_BIKE_VERIFY:
            return DATA_64_ALIGN(BIKE_PK_LEN)*3 + DATA_64_ALIGN(BIKE_CT_LEN-BIKE_PK_LEN) + DATA_64_ALIGN(BIKE_SK_LEN-BIKE_PK_LEN*2);
        case HX_MCELIECE_SIGN:
            return MCE_SEED_LEN + MCE_PK_LEN;
        case HX_MCELIECE_VERIFY:
            return MCE_CT_LEN + DATA_64_ALIGN(MCE_SK_LEN);
        case HX_DILI2_KG:
            return DATA_64_ALIGN(DILI2_SEED_LEN);
        case HX_DILI2_SIGN:
            return DATA_64_ALIGN(DILI2_MSG_LEN) + DATA_64_ALIGN(DILI2_SK_LEN);
        case HX_DILI2_VERIFY:
            return DATA_64_ALIGN(DILI2_MSG_LEN) + DATA_64_ALIGN(DILI2_PK_LEN) + DATA_64_ALIGN(DILI2_CT_LEN);
        case HX_FALCON_SIGN:
            return HX_PQC_FALCON_ENC_IN_LEN;
        case HX_FALCON_VERIFY:
            return HX_PQC_FALCON_DEC_IN_LEN;
        default:
            printf("get_pqc_req_len: pqc mode is not supported\n");
            return 1;
    }
}

int get_pqc_res_fifo_len(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return KYBER512_SK_LEN;
        case HX_KYBER512_SIGN:
            return KYBER512_CT_LEN + KYBER512_SS_LEN;
        case HX_KYBER512_VERIFY:
            return KYBER512_SS_LEN;
        case HX_AIGIS_KG:
            return AIGIS_SK_LEN;
        case HX_AIGIS_SIGN:
            return AIGIS_CT_LEN + AIGIS_SS_LEN;
        case HX_AIGIS_VERIFY:
            return AIGIS_SS_LEN;
        case HX_LAC128_KG:
            return LAC_SK_LEN;
        case HX_LAC128_SIGN:
            return DATA_64_ALIGN(LAC_CT_LEN) + DATA_64_ALIGN(LAC_SS_LEN);
        case HX_LAC128_VERIFY:
            return LAC_SS_LEN;
        case HX_SPHINCS_KG:
            return SPHINCS_KEY_LEN;
        case HX_SPHINCS_SIGN:
            return SPHINCS_SIGN_LEN*4;
        case HX_SPHINCS_VERIFY:
            return SPHINCS_VERIFY_LEN;
        case HX_HQC_KG:
            return DATA_64_ALIGN((HQC_SEED_LEN/2)) + DATA_64_ALIGN((HQC_SEED_LEN/2)) + DATA_64_ALIGN((HQC_SK_LEN-HQC_SEED_LEN));
        case HX_HQC_SIGN:
            return DATA_64_ALIGN(HQC_SS_LEN) + DATA_64_ALIGN(HQC_CT_LEN);
        case HX_HQC_VERIFY:
            return HQC_SS_LEN;
        case HX_BIKE_SIGN:
            return BIKE_SS_LEN + DATA_64_ALIGN(BIKE_PK_LEN) + DATA_64_ALIGN(BIKE_CT_LEN-BIKE_PK_LEN);
        case HX_BIKE_VERIFY:
            return BIKE_SS_LEN;
        case HX_MCELIECE_SIGN:
            return MCE_CT_LEN + MCE_SS_LEN;
        case HX_MCELIECE_VERIFY:
            return MCE_SS_LEN;
        case HX_DILI2_KG:
            return DATA_64_ALIGN(DILI2_PK_LEN) + DATA_64_ALIGN(DILI2_SK_LEN);
        case HX_DILI2_SIGN:
            return DATA_64_ALIGN(DILI2_CT_LEN);
        case HX_DILI2_VERIFY:
            return DILI2_SS_LEN;
        case HX_FALCON_SIGN:
            return HX_PQC_FALCON_ENC_OUT_LEN;
        case HX_FALCON_VERIFY:
            return HX_PQC_FALCON_DEC_OUT_LEN;
        default:
            printf("get_pqc_res_fifo_len: pqc mode is not supported\n");
            return 1;
    }
}

int get_pqc_res_axi_len(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return DATA_64_ALIGN(KYBER512_SK_LEN);
        case HX_KYBER512_SIGN:
            return DATA_64_ALIGN(KYBER512_CT_LEN) + DATA_64_ALIGN(KYBER512_SS_LEN);
        case HX_KYBER512_VERIFY:
            return DATA_64_ALIGN(KYBER512_SS_LEN);
        case HX_AIGIS_KG:
            return DATA_64_ALIGN(AIGIS_SK_LEN);
        case HX_AIGIS_SIGN:
            return DATA_64_ALIGN(AIGIS_CT_LEN) + DATA_64_ALIGN(AIGIS_SS_LEN);
        case HX_AIGIS_VERIFY:
            return DATA_64_ALIGN(AIGIS_SS_LEN);
        case HX_LAC128_KG:
            return DATA_64_ALIGN(LAC_SK_LEN);
        case HX_LAC128_SIGN:
            return DATA_64_ALIGN(LAC_CT_LEN) + DATA_64_ALIGN(LAC_SS_LEN);
        case HX_LAC128_VERIFY:
            return DATA_64_ALIGN(LAC_SS_LEN);
        case HX_SPHINCS_KG:
            return DATA_64_ALIGN(SPHINCS_KEY_LEN);
        case HX_SPHINCS_SIGN:
            return DATA_64_ALIGN((SPHINCS_SIGN_LEN*4));
        case HX_SPHINCS_VERIFY:
            return DATA_64_ALIGN(SPHINCS_VERIFY_LEN);
        case HX_HQC_KG:
            return DATA_64_ALIGN((HQC_SEED_LEN/2)) + DATA_64_ALIGN((HQC_SEED_LEN/2)) + DATA_64_ALIGN((HQC_SK_LEN-HQC_SEED_LEN));
        case HX_HQC_SIGN:
            return DATA_64_ALIGN(HQC_SS_LEN) + DATA_64_ALIGN(HQC_CT_LEN);
        case HX_HQC_VERIFY:
            return HQC_SS_LEN;
        case HX_BIKE_SIGN:
            return DATA_64_ALIGN(BIKE_SS_LEN) + DATA_64_ALIGN(BIKE_PK_LEN) + DATA_64_ALIGN(BIKE_CT_LEN-BIKE_PK_LEN);
        case HX_BIKE_VERIFY:
            return DATA_64_ALIGN(BIKE_SS_LEN);
        case HX_MCELIECE_SIGN:
            return MCE_CT_LEN + DATA_64_ALIGN(MCE_SS_LEN);
        case HX_MCELIECE_VERIFY:
            return DATA_64_ALIGN(MCE_SS_LEN);
        case HX_DILI2_KG:
            return DATA_64_ALIGN(DILI2_PK_LEN) + DATA_64_ALIGN(DILI2_SK_LEN);
        case HX_DILI2_SIGN:
            return DATA_64_ALIGN(DILI2_CT_LEN);
        case HX_DILI2_VERIFY:
            return DATA_64_ALIGN(DILI2_SS_LEN);
        case HX_FALCON_SIGN:
            return HX_PQC_FALCON_ENC_OUT_LEN;
        case HX_FALCON_VERIFY:
            return HX_PQC_FALCON_DEC_OUT_LEN;
        default:
            printf("get_pqc_res_axi_len: pqc mode is not supported\n");
            return 1;
    }
}

int *pqc_get_input_data(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return kyber_keygen_512_in_ref;
        case HX_KYBER512_SIGN:
            return kyber_enc_512_in_ref;
        case HX_KYBER512_VERIFY:
            return kyber_dec_512_in_ref;
        case HX_AIGIS_KG:
            return aigis_keygen_in_ref;
        case HX_AIGIS_SIGN:
            return aigis_enc_in_ref;
        case HX_AIGIS_VERIFY:
            return aigis_dec_in_ref;
        case HX_LAC128_KG:
            return lac128_keygen_in_ref;
        case HX_LAC128_SIGN:
            return lac128_enc_in_ref;
        case HX_LAC128_VERIFY:
            return lac128_dec_in_ref;  
        case HX_SPHINCS_KG:
            return sphincs_keygen_in_ref;       
        case HX_SPHINCS_SIGN:
            return sphincs_sign_in_ref;
        case HX_SPHINCS_VERIFY:
            return sphincs_verify_in_ref; 
        case HX_HQC_KG:
            return hqc_keygen_in_ref;   
        case HX_HQC_SIGN:
            return hqc_enc_in_ref;
        case HX_HQC_VERIFY:
            return hqc_dec_in_ref;
        case HX_BIKE_SIGN:
            return bike_enc_in_ref; 
        case HX_BIKE_VERIFY:
            return bike_dec_in_ref; 
        case HX_MCELIECE_SIGN:
            return mceliece_enc_in_ref; 
        case HX_MCELIECE_VERIFY:
            return mceliece_dec_in_ref; 
        case HX_DILI2_KG:
            return dili2_keygen_in_ref; 
        case HX_DILI2_SIGN:{
            static int dili2_sign_in_ref[DATA_64_ALIGN(DILI2_MSG_LEN) + DATA_64_ALIGN(DILI2_SK_LEN)];
#if PQC_AXI_BUS
            memcpy(dili2_sign_in_ref, dili2_sign_skin_ref, DILI2_SK_LEN);
            memcpy(&dili2_sign_in_ref[DATA_64_ALIGN(DILI2_SK_LEN)/4], dili2_sign_msgin_ref, DILI2_MSG_LEN);
#else         
            memcpy(dili2_sign_in_ref, dili2_sign_msgin_ref, DILI2_MSG_LEN);
            memcpy(&dili2_sign_in_ref[DATA_64_ALIGN(DILI2_MSG_LEN)/4], dili2_sign_skin_ref, DILI2_SK_LEN);
#endif
            return dili2_sign_in_ref;
        }
        case HX_DILI2_VERIFY:{
            static int dili2_verify_in_ref[DATA_64_ALIGN(DILI2_MSG_LEN) + DATA_64_ALIGN(DILI2_PK_LEN) + DATA_64_ALIGN(DILI2_CT_LEN)];
#if PQC_AXI_BUS
            memcpy(dili2_verify_in_ref, dili2_verify_pkin_ref, DILI2_PK_LEN);
            memcpy(&dili2_verify_in_ref[DATA_64_ALIGN(DILI2_PK_LEN)/4], dili2_verify_msgin_ref, DILI2_MSG_LEN);

#else            
            memcpy(dili2_verify_in_ref, dili2_verify_msgin_ref, DILI2_MSG_LEN);
            memcpy(&dili2_verify_in_ref[DATA_64_ALIGN(DILI2_MSG_LEN)/4], dili2_verify_pkin_ref, DILI2_PK_LEN); 
#endif
            memcpy(&dili2_verify_in_ref[DATA_64_ALIGN(DILI2_MSG_LEN)/4+DATA_64_ALIGN(DILI2_PK_LEN)/4], dili2_verify_sign_ref, DILI2_CT_LEN);
            return dili2_verify_in_ref;
        }
        case HX_FALCON_SIGN:{
            static int falcon_sign_in_ref[HX_PQC_FALCON_ENC_IN_LEN];
            memcpy(falcon_sign_in_ref, falcon_sign_sk, HX_PQC_FALCON_ENC_SK_IN_LEN);
            memcpy(&falcon_sign_in_ref[HX_PQC_FALCON_ENC_SK_IN_LEN/4], falcon_sign_seed, HX_PQC_FALCON_ENC_SEED_IN_LEN);
            memcpy(&falcon_sign_in_ref[(HX_PQC_FALCON_ENC_SK_IN_LEN + HX_PQC_FALCON_ENC_SEED_IN_LEN)/4], falcon_sign_nonce, HX_PQC_FALCON_ENC_NONCE_IN_LEN);
            memcpy(&falcon_sign_in_ref[(HX_PQC_FALCON_ENC_SK_IN_LEN + HX_PQC_FALCON_ENC_SEED_IN_LEN + HX_PQC_FALCON_ENC_NONCE_IN_LEN)/4], falcon_sign_msg, HX_PQC_FALCON_ENC_MSG_IN_LEN);
            return falcon_sign_in_ref;
        }
        case HX_FALCON_VERIFY:{
            static int falcon_verify_in_ref[HX_PQC_FALCON_DEC_IN_LEN];
            memcpy(falcon_verify_in_ref, falcon_verify_pk, HX_PQC_FALCON_DEC_PK_IN_LEN);
            memcpy(&falcon_verify_in_ref[HX_PQC_FALCON_DEC_PK_IN_LEN/4], falcon_verify_signature, HX_PQC_FALCON_DEC_SIGN_IN_LEN);
            memcpy(&falcon_verify_in_ref[(HX_PQC_FALCON_DEC_PK_IN_LEN + HX_PQC_FALCON_DEC_SIGN_IN_LEN)/4], falcon_verify_nonce_msg, HX_PQC_FALCON_DEC_NONCE_IN_LEN);
            return falcon_verify_in_ref;
        }
        default:
            printf("pqc_get_input_data: mode is not supported\n");
            return NULL;
    }
}

int *pqc_get_output_data(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return kyber_keygen_512_sk_out_ref;
        case HX_KYBER512_SIGN:
            return kyber_enc_512_out_ref;
        case HX_KYBER512_VERIFY:
            return kyber_dec_512_out_ref;
        case HX_AIGIS_KG:
            return aigis_keygen_out_ref;
        case HX_AIGIS_SIGN:
            return aigis_enc_out_ref;
        case HX_AIGIS_VERIFY:
            return aigis_dec_out_ref;
        case HX_LAC128_KG:
            return lac128_keygen_sk_out_ref;
        case HX_LAC128_SIGN:
            return lac128_enc_out_ref;
        case HX_LAC128_VERIFY:
            return lac128_dec_out_ref;    
        case HX_SPHINCS_KG:
            return sphincs_keygen_out_ref;       
        case HX_SPHINCS_SIGN:
            return sphincs_sign_out_ref;
        case HX_SPHINCS_VERIFY:
            return sphincs_verify_out_ref;  
        case HX_HQC_KG:
            return hqc_keygen_out_ref;   
        case HX_HQC_SIGN:
            return hqc_enc_out_ref; 
        case HX_HQC_VERIFY:
            return hqc_dec_out_ref;
        case HX_BIKE_SIGN:
            return bike_enc_out_ref; 
        case HX_BIKE_VERIFY:
            return bike_dec_out_ref; 
        case HX_MCELIECE_SIGN:
            return mceliece_enc_out_ref; 
        case HX_MCELIECE_VERIFY:
            return mceliece_dec_out_ref; 
        case HX_DILI2_KG:{
            static int dili2_keygen_out_ref[DATA_64_ALIGN(DILI2_PK_LEN) + DATA_64_ALIGN(DILI2_SK_LEN)];
            memcpy(dili2_keygen_out_ref, dili2_keygen_skout_ref, DILI2_SK_LEN);
            memcpy(&dili2_keygen_out_ref[DATA_64_ALIGN(DILI2_SK_LEN)/4], dili2_keygen_pkout_ref, DILI2_PK_LEN);
            return dili2_keygen_out_ref;
        }
        case HX_DILI2_SIGN:
            return dili2_sign_out_ref; 
        case HX_DILI2_VERIFY:
            return dili2_verify_out_ref;
        case HX_FALCON_SIGN:
            return falcon_sign_out_ref;
        case HX_FALCON_VERIFY:
            return falcon_verify_out_ref;
        default:
            printf("pqc_get_output_data: mode is not supported\n");
            return NULL;
    }
}

int pqc_build_debug_data(uint8_t *req, uint8_t mode)
{
    if(pqc_get_input_data(mode) == NULL)
        return -1;

    memcpy(req, pqc_get_input_data(mode), get_pqc_req_len(mode));

    return 0;
}

int pqc_compare_data(char *info, int *pqc_result, int *out_ref, uint32_t len)
{
    int i ;

    if(memcmp(pqc_result, out_ref, len) == 0)
    {
        //printf("pqc %s compare success\r\n", info);
    }  
    else
    {
        for(i=0; i< (len/4); i++)
        {
            if(pqc_result[i] != out_ref[i])
            {
                printf("i = %d\r\n", i);
                hx_dump_buf("pqc_result:", (uint8_t*)&pqc_result[i], 64);
                hx_dump_buf("out_ref:", (uint8_t*)&out_ref[i], 64);
                return 1;
            }
        }
    }

    return 0;
}

int pqc_kyber_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;

    if(HX_KYBER512_KG == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        memcpy(req, pqc->seed, sizeof(pqc->seed));

        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);
    }
    else if(HX_KYBER512_SIGN == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);
        
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->signFunc(pqc->seed, pqc->pk, pqc->ss, pqc->ct);

        memcpy(req, pqc->seed, sizeof(pqc->seed));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->seed))], pqc->pk, sizeof(pqc->pk));
    }
    else if(HX_KYBER512_VERIFY == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->signFunc(pqc->seed, pqc->pk, pqc->ss, pqc->ct);

        memcpy(req, pqc->ct, sizeof(pqc->ct));
        memcpy(&req[sizeof(pqc->ct)], pqc->sk, KYBER512_SK_LEN);
    }

    return 0;
} 

int pqc_kyber_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
    int ret = HX_RET_SUCCESS;

    if(HX_KYBER512_KG == mode)
    {
        if(pqc_compare_data("kyber kg sk", pqc->sk, resp, KYBER512_SK_LEN) 
            || pqc_compare_data("kyber kg pk", pqc->pk, &resp[KYBER512_PK_START_LEN], KYBER512_PK_LEN))
        {
            ret = HX_RET_FAILED;
            hx_dump_data("seed", pqc->seed, sizeof(pqc->seed));
        }  
    }
    else if(HX_KYBER512_SIGN == mode)
    {
        if(pqc_compare_data("kyber sign ct", pqc->ct, resp, sizeof(pqc->ct)) 
            || pqc_compare_data("kyber sign ss", pqc->ss, &resp[sizeof(pqc->ct)], sizeof(pqc->ss)))
        {
            ret = HX_RET_FAILED;
            hx_dump_data("seed", pqc->seed, sizeof(pqc->seed));
            hx_dump_data("pk", pqc->pk, sizeof(pqc->pk));
        }
            
    }
    else if(HX_KYBER512_VERIFY == mode)
    {
        if(pqc_compare_data("kyber verify ss", pqc->ss, resp, sizeof(pqc->ss)))
        {
            ret = HX_RET_FAILED;
            hx_dump_data("ct", pqc->ct, sizeof(pqc->ct));
            hx_dump_data("sk", pqc->sk, KYBER512_SK_LEN);
        }           
    }

    return ret;
}

int pqc_aigis_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_aigis_t *pqc = (hx_aigis_t *)pqc_data;

    if(HX_AIGIS_KG == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->pk, pqc->sk, pqc->seed);    

        memcpy(req, pqc->seed, sizeof(pqc->seed));
    }
    else if(HX_AIGIS_SIGN == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->pk, pqc->sk, pqc->seed);
        RAND_bytes(pqc->seed, sizeof(pqc->seed));

        memcpy(req, pqc->seed, sizeof(pqc->seed));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->seed))], pqc->pk, sizeof(pqc->pk));
    }
    else if(HX_AIGIS_VERIFY == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->pk, pqc->sk, pqc->seed);

        pqc->signFunc(pqc->ct, pqc->ss, pqc->pk, pqc->seed);

        memcpy(req, pqc->ct, sizeof(pqc->ct));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->ct))], pqc->sk, sizeof(pqc->sk));
    }

    return 0;
}

int pqc_aigis_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    hx_aigis_t *pqc = (hx_aigis_t *)pqc_data;
    int ret = HX_RET_SUCCESS;

    if(HX_AIGIS_KG == mode)
    {
        if(pqc_compare_data("aigis kg sk", pqc->sk, resp, sizeof(pqc->sk))
            || pqc_compare_data("aigis kg pk", pqc->pk, &resp[AIGIS_PK_START_LEN], sizeof(pqc->pk)))
        {
            ret = HX_RET_FAILED; 
            hx_dump_data("seed", pqc->seed, sizeof(pqc->seed));
        }           
    }
    else if(HX_AIGIS_SIGN == mode)
    {
        memcpy(pqc->ct, resp, sizeof(pqc->ct));
        pqc->verifyFunc(pqc->ss, pqc->ct, pqc->sk);
#if PQC_AXI_BUS
        if(pqc_compare_data("aigis sign", pqc->ss, &resp[DATA_64_ALIGN(sizeof(pqc->ct))], sizeof(pqc->ss)))
#else
        if(pqc_compare_data("aigis sign", pqc->ss, &resp[sizeof(pqc->ct)], sizeof(pqc->ss)))
#endif
        {
            ret = HX_RET_FAILED; 
            hx_dump_data("seed", pqc->seed, sizeof(pqc->seed));
            hx_dump_data("pk", pqc->pk, sizeof(pqc->pk));
        }      
    }
    else if(HX_AIGIS_VERIFY == mode)
    {
        if(pqc_compare_data("aigis verify", pqc->ss, resp, sizeof(pqc->ss)))
        {
            ret = HX_RET_FAILED; 
            hx_dump_data("ct", pqc->ct, sizeof(pqc->ct));
            hx_dump_data("sk", pqc->sk, sizeof(pqc->sk));
        }    
    }

    return ret;
}

int pqc_lac_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_lac_t *pqc = (hx_lac_t *)pqc_data;

    if(HX_LAC128_KG == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        memcpy(req, pqc->seed, sizeof(pqc->seed));
    }
    else if(HX_LAC128_SIGN == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        RAND_bytes(pqc->msgseed, sizeof(pqc->msgseed));

        memcpy(req, pqc->msgseed, sizeof(pqc->msgseed));
        memcpy(&req[sizeof(pqc->msgseed)], pqc->pk, sizeof(pqc->pk)); 

    }
    else if(HX_LAC128_VERIFY == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);
        pqc->signFunc(pqc->pk, pqc->ct, pqc->ss);

        memcpy(req, pqc->sk, LAC_SK_LEN-LAC_PK_LEN); //lac sk[1056] include sk[512] and pk[544]
        memcpy(&req[LAC_SK_LEN-LAC_PK_LEN], pqc->ct, sizeof(pqc->ct));
        memcpy(&req[LAC_SK_LEN-LAC_PK_LEN + DATA_64_ALIGN(sizeof(pqc->ct))], pqc->pk, sizeof(pqc->pk));
    }

    return 0;
}

int pqc_lac_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    hx_lac_t *pqc = (hx_lac_t *)pqc_data;
    int ret = HX_RET_SUCCESS;

    if(HX_LAC128_KG == mode)
    {
        if(pqc_compare_data("lac kg sk", pqc->sk, resp, sizeof(pqc->sk)))
        {
            ret = HX_RET_FAILED; 
            hx_dump_data("seed", pqc->seed, sizeof(pqc->seed));
        }            
    }
    else if(HX_LAC128_SIGN == mode)
    {
        memcpy(pqc->ct, resp, sizeof(pqc->ct));
        pqc->verifyFunc(pqc->sk, pqc->ct, pqc->ss);

        if(pqc_compare_data("lac sign", pqc->ss, &resp[DATA_64_ALIGN(sizeof(pqc->ct))], sizeof(pqc->ss)))
            ret = HX_RET_FAILED;
    }
    else if(HX_LAC128_VERIFY == mode)
    {
        if(pqc_compare_data("lac verify", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED;
    }

    return ret;
}

int pqc_sphincs_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_sphincs_t *pqc = (hx_sphincs_t *)pqc_data;
    uint64_t signlen = 0;

    if(HX_SPHINCS_KG == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        memcpy(req, pqc->seed, sizeof(pqc->seed));

        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);
    }
    else if(HX_SPHINCS_SIGN == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        RAND_bytes(pqc->msg, sizeof(pqc->msg));
        RAND_bytes(pqc->seed, SPHINCS_SIGN_SEED_LEN);
        pqc->signFunc(pqc->seed, pqc->msg, sizeof(pqc->msg), pqc->sk, pqc->sign, &signlen);

        memcpy(req, pqc->sk, sizeof(pqc->sk));
        memcpy(&req[sizeof(pqc->sk)], pqc->seed, SPHINCS_SIGN_SEED_LEN);
        memcpy(&req[sizeof(pqc->sk) + SPHINCS_SIGN_SEED_LEN], pqc->msg, sizeof(pqc->msg));
    }   
    else if(HX_SPHINCS_VERIFY == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        RAND_bytes(pqc->msg, sizeof(pqc->msg));
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->signFunc(pqc->seed, pqc->msg, sizeof(pqc->msg), pqc->sk, pqc->sign, &signlen);

        memcpy(req, pqc->pk, sizeof(pqc->pk));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->pk))], pqc->msg, sizeof(pqc->msg));
        for(int i=0; i< signlen/16; i++)
        {
            memcpy(&req[DATA_64_ALIGN(sizeof(pqc->pk))+DATA_64_ALIGN(sizeof(pqc->msg))+64*i], &pqc->sign[16*i], 16);
        }
    }

    return 0;
}

int pqc_sphincs_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    hx_sphincs_t *pqc = (hx_sphincs_t *)pqc_data;
    int ret = HX_RET_SUCCESS;

    if(HX_SPHINCS_KG == mode)
    {  
        uint8_t pk[SPHINCS_PK_LEN];
        uint8_t sk[SPHINCS_SK_LEN];

        memcpy(pk, &pqc->seed[32], 16);
        memcpy(&pk[16], resp, SPHINCS_KEY_LEN);
        memcpy(sk, pqc->seed, SPHINCS_SEED_LEN);
        memcpy(&sk[SPHINCS_SEED_LEN], resp, SPHINCS_KEY_LEN);

        if((memcmp(pk, pqc->pk, sizeof(pqc->pk)) == 0)  && (memcmp(sk, pqc->sk, sizeof(pqc->sk)) == 0))
            printf("sphincs kg success\r\n");
        else
            printf("sphincs kg fail\r\n");
    }
    else if(HX_SPHINCS_SIGN == mode)
    {
        static uint8_t sign[SPHINCS_SIGN_LEN];

        memset(sign, 0, sizeof(sign));
        for(int i=0; i< sizeof(sign)/16; i++)
        {
            memcpy(&sign[16*i], &resp[64*i], 16);
        }

        if(pqc_compare_data("sphincs sign", sign, pqc->sign, sizeof(sign)))
            ret = HX_RET_FAILED;
    }  
    else if(HX_SPHINCS_VERIFY == mode)
    {
        if(memcmp(&pqc->pk[16], resp, SPHINCS_VERIFY_LEN) == 0)
            printf("sphincs verify success\r\n");
        else
            printf("sphincs verify fail\r\n");
    }

    return ret;
}

int pqc_hqc_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_hqc_t *pqc = (hx_hqc_t *)pqc_data;

    if(HX_HQC_KG == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        memcpy(req, pqc->seed, sizeof(pqc->seed)/2);
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->seed)/2)], &pqc->seed[sizeof(pqc->seed)/2], sizeof(pqc->seed)/2);
    }
    else if(HX_HQC_SIGN == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        RAND_bytes(pqc->m, sizeof(pqc->m));
        RAND_bytes(pqc->salt, sizeof(pqc->salt));

        memcpy(req, pqc->m, sizeof(pqc->m));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->m))], pqc->salt, sizeof(pqc->salt));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->m))+DATA_64_ALIGN(sizeof(pqc->salt))], pqc->pk, HQC_SEED_LEN/2);
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->m))+DATA_64_ALIGN(sizeof(pqc->salt))+DATA_64_ALIGN((HQC_SEED_LEN/2))], 
                &pqc->pk[HQC_SEED_LEN/2], sizeof(pqc->pk)-HQC_SEED_LEN/2);
    }
    else if(HX_HQC_VERIFY == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);
        pqc->signFunc(pqc->pk, pqc->ct, pqc->ss);

        memcpy(req, pqc->sk, HQC_SEED_LEN/2);
        memcpy(&req[DATA_64_ALIGN(HQC_SEED_LEN/2)], &pqc->sk[HQC_SEED_LEN/2], HQC_SEED_LEN/2);
        memcpy(&req[DATA_64_ALIGN(HQC_SEED_LEN)], &pqc->sk[HQC_SEED_LEN], sizeof(pqc->sk)-HQC_SEED_LEN);
        memcpy(&req[DATA_64_ALIGN(HQC_SEED_LEN)+DATA_64_ALIGN(sizeof(pqc->sk)-HQC_SEED_LEN)], pqc->ct, sizeof(pqc->ct));
    }

    return 0;
}

int pqc_hqc_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    hx_hqc_t *pqc = (hx_hqc_t *)pqc_data;
    int ret = HX_RET_SUCCESS;

    if(HX_HQC_KG == mode)
    {
        static uint8_t sk[HQC_SK_LEN];
        memcpy(sk, resp, HQC_SEED_LEN/2);
        memcpy(&sk[HQC_SEED_LEN/2], &resp[DATA_64_ALIGN((HQC_SEED_LEN/2))], HQC_SEED_LEN/2);
        memcpy(&sk[HQC_SEED_LEN], &resp[DATA_64_ALIGN((HQC_SEED_LEN/2))+DATA_64_ALIGN((HQC_SEED_LEN/2))], 
                HQC_SK_LEN-HQC_SEED_LEN);

        if(pqc_compare_data("hqc kg", pqc->sk, sk, sizeof(pqc->sk)))
            ret = HX_RET_FAILED;       
    }
    else if(HX_HQC_SIGN == mode)
    {
        memcpy(pqc->ct, &resp[sizeof(pqc->ss)], sizeof(pqc->ct));

        pqc->verifyFunc(pqc->sk, pqc->ct, pqc->ss);

        if(pqc_compare_data("hqc sign", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED; 
    }
    else if(HX_HQC_VERIFY == mode)
    {
        if(pqc_compare_data("hqc verify", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED;        
    }

    return ret;
}

int pqc_bike_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_bike_t *pqc = (hx_bike_t *)pqc_data;

    if(HX_BIKE_SIGN == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        RAND_bytes(pqc->msgseed, sizeof(pqc->msgseed));

        memcpy(req, pqc->pk, sizeof(pqc->pk));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->pk))], pqc->msgseed, sizeof(pqc->msgseed));
    }
    else if(HX_BIKE_VERIFY == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);
        pqc->signFunc(pqc->ct, pqc->ss, pqc->pk);

        memcpy(req, pqc->sk, BIKE_PK_LEN); //sk0
        memcpy(&req[DATA_64_ALIGN(BIKE_PK_LEN)], &pqc->sk[BIKE_PK_LEN], BIKE_PK_LEN); //sk1
        memcpy(&req[DATA_64_ALIGN(BIKE_PK_LEN)*2], pqc->ct, BIKE_PK_LEN); //ct0
        memcpy(&req[DATA_64_ALIGN(BIKE_PK_LEN)*3], &pqc->ct[BIKE_PK_LEN], BIKE_CT_LEN-BIKE_PK_LEN); //ct1
        memcpy(&req[DATA_64_ALIGN(BIKE_PK_LEN)*3+DATA_64_ALIGN(BIKE_CT_LEN-BIKE_PK_LEN)], &pqc->sk[BIKE_PK_LEN*2], BIKE_SK_LEN-BIKE_PK_LEN*2); //sigma
    }

    return 0;
}

int pqc_bike_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    hx_bike_t *pqc = (hx_bike_t *)pqc_data;
    int ret = HX_RET_SUCCESS;

    if(HX_BIKE_SIGN == mode)
    {
#if PQC_AXI_BUS
        memcpy(pqc->ct, &resp[DATA_64_ALIGN(BIKE_SS_LEN)], BIKE_PK_LEN); //ct0
        memcpy(&pqc->ct[BIKE_PK_LEN], &resp[DATA_64_ALIGN(BIKE_SS_LEN)+DATA_64_ALIGN(BIKE_PK_LEN)], BIKE_CT_LEN-BIKE_PK_LEN); //ct1
#else
        memcpy(pqc->ct, &resp[BIKE_SS_LEN], BIKE_PK_LEN); //ct0
        memcpy(&pqc->ct[BIKE_PK_LEN], &resp[BIKE_SS_LEN+DATA_64_ALIGN(BIKE_PK_LEN)], BIKE_CT_LEN-BIKE_PK_LEN); //ct1
#endif
        pqc->verifyFunc(pqc->ss, pqc->ct, pqc->sk);

        if(pqc_compare_data("bike sign", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED;
    }
    else if(HX_BIKE_VERIFY == mode)
    {
        if(pqc_compare_data("bike verify", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED;
    }

    return ret;
}

int pqc_mce_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_mceliece_t *pqc = (hx_mceliece_t *)pqc_data;

    if(HX_MCELIECE_SIGN == mode)
    {
        pqc->keygenFunc(pqc->pk, pqc->sk);

        RAND_bytes(pqc->seed, sizeof(pqc->seed));

        memcpy(req, pqc->seed, sizeof(pqc->seed));
        memcpy(&req[sizeof(pqc->seed)], pqc->pk, sizeof(pqc->pk));
    }
    else if(HX_MCELIECE_VERIFY == mode)
    {
        pqc->keygenFunc(pqc->pk, pqc->sk);
        pqc->signFunc(pqc->pk, pqc->ct, pqc->ss);

        memcpy(req, pqc->ct, sizeof(pqc->ct));
        memcpy(&req[sizeof(pqc->ct)], pqc->sk, sizeof(pqc->sk));
    }

    return 0;
}

int pqc_mce_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    hx_mceliece_t *pqc = (hx_mceliece_t *)pqc_data;
    int ret = HX_RET_SUCCESS;

    if(HX_MCELIECE_SIGN == mode)
    {
        memcpy(pqc->ct, resp, sizeof(pqc->ct));

        pqc->verifyFunc(pqc->ss, pqc->ct, pqc->sk);  

        if(pqc_compare_data("mce sign", pqc->ss, &resp[sizeof(pqc->ct)], sizeof(pqc->ss)))
            ret = HX_RET_FAILED;              
    }
    else if(HX_MCELIECE_VERIFY == mode)
    {
        if(pqc_compare_data("mce verify", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED;        
    }
    return ret;
}

int pqc_dili2_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_dili2_t *pqc = (hx_dili2_t *)pqc_data;
    uint64_t signlen = 0;

    if(HX_DILI2_KG == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        memcpy(req, pqc->seed, sizeof(pqc->seed));

        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);   
    }
    else if(HX_DILI2_SIGN == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        RAND_bytes(pqc->msg, sizeof(pqc->msg));
        pqc->signFunc(pqc->msg, sizeof(pqc->msg), pqc->sk, pqc->sign, &signlen);

#if PQC_AXI_BUS
        memcpy(req, pqc->sk, sizeof(pqc->sk));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->sk))], pqc->msg, sizeof(pqc->msg));
#else
        memcpy(req, pqc->msg, sizeof(pqc->msg));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->msg))], pqc->sk, sizeof(pqc->sk));
#endif

    }
    else if(HX_DILI2_VERIFY == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        RAND_bytes(pqc->msg, sizeof(pqc->msg));
        pqc->signFunc(pqc->msg, sizeof(pqc->msg), pqc->sk, pqc->sign, &signlen);

#if PQC_AXI_BUS
        memcpy(req, pqc->pk, sizeof(pqc->pk));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->pk))], pqc->msg, sizeof(pqc->msg));
#else
        memcpy(req, pqc->msg, sizeof(pqc->msg));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->msg))], pqc->pk, sizeof(pqc->pk));
#endif
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->msg))+DATA_64_ALIGN(sizeof(pqc->pk))], pqc->sign, sizeof(pqc->sign));
    }
    
    return 0;
}

int pqc_dili2_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    hx_dili2_t *pqc = (hx_dili2_t *)pqc_data;
    int ret = HX_RET_SUCCESS;

    if(HX_DILI2_KG == mode)
    {
        if(pqc_compare_data("dili2 kg sk", pqc->sk, resp, sizeof(pqc->sk))
            || pqc_compare_data("dili2 kg pk", pqc->pk, &resp[DATA_64_ALIGN(sizeof(pqc->sk))], sizeof(pqc->pk)))
            ret = HX_RET_FAILED;
    }
    else if(HX_DILI2_SIGN == mode)
    {
        if(pqc_compare_data("dili2 sign", pqc->sign, resp, sizeof(pqc->sign)))
            ret = HX_RET_FAILED;
    }
    else if(HX_DILI2_VERIFY == mode)
    {
        if(pqc_compare_data("dili2 verify", dili2_verify_out_ref, resp, DILI2_SS_LEN))
            ret = HX_RET_FAILED;        
    }

    return ret;
}

int pqc_falcon_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    hx_falcon_t *pqc = (hx_falcon_t *)pqc_data;
    uint64_t signlen = 0;

    if(HX_FALCON_SIGN == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);
    }
    else if(HX_FALCON_VERIFY == mode)
    {
        RAND_bytes(pqc->seed, sizeof(pqc->seed));
        pqc->keygenFunc(pqc->seed, pqc->pk, pqc->sk);

        pqc->msglen = 33;
        RAND_bytes(pqc->msg, pqc->msglen);
        pqc->signFunc(pqc->msg, pqc->msglen, pqc->sk, pqc->sign, &signlen);

        printf("signlen = %d\r\n", signlen);

        memcpy(req, pqc->pk, sizeof(pqc->pk));
        memcpy(&req[HX_PQC_FALCON_DEC_PK_IN_LEN], pqc->sign, signlen);
        memcpy(&req[HX_PQC_FALCON_DEC_PK_IN_LEN+HX_PQC_FALCON_DEC_SIGN_IN_LEN], pqc->msg, pqc->msglen);
    }

    return 0;
}

int pqc_falcon_compare_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    int ret = HX_RET_SUCCESS;

    return ret;
}

int pqc_build_random_data(uint8_t *req, uint32_t req_len, uint8_t *pqc_data, uint8_t mode)
{
    switch (mode) {
        case HX_KYBER512_KG:
        case HX_KYBER512_SIGN:
        case HX_KYBER512_VERIFY:
            pqc_kyber_build_data(req, pqc_data, mode);
            break;
        case HX_AIGIS_KG:
        case HX_AIGIS_SIGN:
        case HX_AIGIS_VERIFY:
            pqc_aigis_build_data(req, pqc_data, mode);
            break;
        case HX_LAC128_KG:
        case HX_LAC128_SIGN:
        case HX_LAC128_VERIFY:
            pqc_lac_build_data(req, pqc_data, mode);
            break;
        case HX_SPHINCS_KG:
        case HX_SPHINCS_SIGN:
        case HX_SPHINCS_VERIFY:
            pqc_sphincs_build_data(req, pqc_data, mode);
            break;
        case HX_HQC_KG:
        case HX_HQC_SIGN:
        case HX_HQC_VERIFY:
            pqc_hqc_build_data(req, pqc_data, mode);
            break;
        case HX_BIKE_SIGN:
        case HX_BIKE_VERIFY:
            pqc_bike_build_data(req, pqc_data, mode);
            break;
        case HX_MCELIECE_SIGN:
        case HX_MCELIECE_VERIFY:
            pqc_mce_build_data(req, pqc_data, mode);
            break;
        case HX_DILI2_KG:
        case HX_DILI2_SIGN:
        case HX_DILI2_VERIFY:
            pqc_dili2_build_data(req, pqc_data, mode);
            break;
        case HX_FALCON_SIGN:
        case HX_FALCON_VERIFY:
            pqc_falcon_build_data(req, pqc_data, mode);
            break;
        default:
            printf("pqc_build_random_data: pqc mode is not supported\n");
            return 1;
    }

    return 0;
}

int pqc_compare_random_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    int ret = HX_RET_SUCCESS;

    switch (mode) {
        case HX_KYBER512_KG:
        case HX_KYBER512_SIGN:
        case HX_KYBER512_VERIFY:
            ret = pqc_kyber_compare_data(resp, pqc_data, mode);
            break;
        case HX_AIGIS_KG:
        case HX_AIGIS_SIGN:
        case HX_AIGIS_VERIFY:
            ret = pqc_aigis_compare_data(resp, pqc_data, mode);
            break;
        case HX_LAC128_KG:
        case HX_LAC128_SIGN:
        case HX_LAC128_VERIFY:
            ret = pqc_lac_compare_data(resp, pqc_data, mode);
            break;
        case HX_SPHINCS_KG:
        case HX_SPHINCS_SIGN:
        case HX_SPHINCS_VERIFY:
            ret = pqc_sphincs_compare_data(resp, pqc_data, mode);
            break;
        case HX_HQC_KG:
        case HX_HQC_SIGN:
        case HX_HQC_VERIFY:
            ret = pqc_hqc_compare_data(resp, pqc_data, mode);
            break;
        case HX_BIKE_SIGN:
        case HX_BIKE_VERIFY:
            ret = pqc_bike_compare_data(resp, pqc_data, mode);
            break;
        case HX_MCELIECE_SIGN:
        case HX_MCELIECE_VERIFY:
            ret = pqc_mce_compare_data(resp, pqc_data, mode);
            break;
        case HX_DILI2_KG:
        case HX_DILI2_SIGN:
        case HX_DILI2_VERIFY:
            ret = pqc_dili2_compare_data(resp, pqc_data, mode);
            break;
        case HX_FALCON_SIGN:
        case HX_FALCON_VERIFY:
            ret = pqc_falcon_compare_data(resp, pqc_data, mode);
            break;
        default:
            printf("pqc_compare_random_data: pqc mode is not supported\n");
            ret = HX_RET_FAILED;
            break;
    }
    
    return ret;
}

int pqc_build_data(uint8_t *req, uint8_t *pqc_data, uint8_t mode)
{
    int ret = HX_RET_SUCCESS;

    //kyber
    if(HX_KYBER512_KG == mode)
    {
        hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
        memcpy(req, pqc->seed, sizeof(pqc->seed));
    }
    else if(HX_KYBER512_SIGN == mode)
    {
        hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
        memcpy(req, pqc->seed, sizeof(pqc->seed));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->seed))], pqc->pk, sizeof(pqc->pk));
    }
    else if(HX_KYBER512_VERIFY == mode)
    {
        hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
        memcpy(req, pqc->ct, sizeof(pqc->ct));
        memcpy(&req[sizeof(pqc->ct)], pqc->sk, KYBER512_SK_LEN);        
    }
    //aigis
    else if(HX_AIGIS_KG == mode)
    {
        hx_aigis_t *pqc = (hx_aigis_t *)pqc_data;
        memcpy(req, pqc->seed, sizeof(pqc->seed));
    }
    else if(HX_AIGIS_SIGN == mode)
    {
        hx_aigis_t *pqc = (hx_aigis_t *)pqc_data; 
        memcpy(req, pqc->seed, sizeof(pqc->seed));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->seed))], pqc->pk, sizeof(pqc->pk));
    }
    else if(HX_AIGIS_VERIFY == mode)
    {
        hx_aigis_t *pqc = (hx_aigis_t *)pqc_data; 
        memcpy(req, pqc->ct, sizeof(pqc->ct));
        memcpy(&req[DATA_64_ALIGN(sizeof(pqc->ct))], pqc->sk, sizeof(pqc->sk));        
    }
    //lac
    else if(HX_LAC128_KG == mode)
    {
        hx_lac_t *pqc = (hx_lac_t *)pqc_data;
        memcpy(req, pqc->seed, sizeof(pqc->seed));
    }
    else if(HX_LAC128_SIGN == mode)
    {
        hx_lac_t *pqc = (hx_lac_t *)pqc_data; 
        memcpy(req, pqc->msgseed, sizeof(pqc->msgseed));
        memcpy(&req[sizeof(pqc->msgseed)], pqc->pk, sizeof(pqc->pk));
    }
    else if(HX_LAC128_VERIFY == mode)
    {
        hx_lac_t *pqc = (hx_lac_t *)pqc_data; 
        memcpy(req, pqc->sk, LAC_SK_LEN-LAC_PK_LEN); //lac sk[1056] include sk[512] and pk[544]
        memcpy(&req[LAC_SK_LEN-LAC_PK_LEN], pqc->ct, sizeof(pqc->ct));
        memcpy(&req[LAC_SK_LEN-LAC_PK_LEN + DATA_64_ALIGN(sizeof(pqc->ct))], pqc->pk, sizeof(pqc->pk));       
    }

    return ret;
}

int pqc_get_data(uint8_t *resp, uint8_t *pqc_data, uint8_t mode)
{
    int ret = HX_RET_SUCCESS;

    //kyber
    if(HX_KYBER512_KG == mode)
    {
        printf("kyber kg\r\n");
        hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
        memcpy(pqc->sk, resp, KYBER512_SK_LEN);
        memcpy(pqc->pk, &resp[KYBER512_PK_START_LEN], KYBER512_PK_LEN);
    }
    else if(HX_KYBER512_SIGN == mode)
    {
        printf("kyber sign\r\n");
        hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
        memcpy(pqc->ct, resp, sizeof(pqc->ct));
        memcpy(pqc->ss, &resp[sizeof(pqc->ct)], sizeof(pqc->ss));
    }
    else if(HX_KYBER512_VERIFY == mode)
    {
        printf("kyber verify\r\n");
        hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
        if(pqc_compare_data("kyber verify", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED;
    }
    //aigis
    else if(HX_AIGIS_KG == mode)
    {
        printf("aigis kg\r\n");
        hx_aigis_t *pqc = (hx_aigis_t *)pqc_data;
        memcpy(pqc->sk, resp, sizeof(pqc->sk));
        memcpy(pqc->pk, &resp[AIGIS_PK_START_LEN], sizeof(pqc->pk));
    }
    else if(HX_AIGIS_SIGN == mode)
    {
        printf("aigis sign\r\n");
        hx_aigis_t *pqc = (hx_aigis_t *)pqc_data; 
        memcpy(pqc->ct, resp, sizeof(pqc->ct));
#if PQC_AXI_BUS
        memcpy(pqc->ss, &resp[DATA_64_ALIGN(sizeof(pqc->ct))], sizeof(pqc->ss));
#else
        memcpy(pqc->ss, &resp[sizeof(pqc->ct)], sizeof(pqc->ss));
#endif
    }
    else if(HX_AIGIS_VERIFY == mode)
    {
        printf("aigis verify\r\n");
        hx_aigis_t *pqc = (hx_aigis_t *)pqc_data; 
        if(pqc_compare_data("aigis verify", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED;
    }
    //lac
    else if(HX_LAC128_KG == mode)
    {
        printf("lac kg\r\n");
        hx_lac_t *pqc = (hx_lac_t *)pqc_data;
        memcpy(pqc->sk, resp, sizeof(pqc->sk));
        memcpy(pqc->pk, &pqc->sk[LAC_SK_LEN-LAC_PK_LEN], sizeof(pqc->pk));
    }
    else if(HX_LAC128_SIGN == mode)
    {
        printf("lac sign\r\n");
        hx_lac_t *pqc = (hx_lac_t *)pqc_data;
        memcpy(pqc->ct, resp, sizeof(pqc->ct));
        memcpy(pqc->ss, &resp[DATA_64_ALIGN(sizeof(pqc->ct))], sizeof(pqc->ss));
    }
    else if(HX_LAC128_VERIFY == mode)
    {
        printf("lac verify\r\n");
        hx_lac_t *pqc = (hx_lac_t *)pqc_data; 
        if(pqc_compare_data("lac verify", pqc->ss, resp, sizeof(pqc->ss)))
            ret = HX_RET_FAILED;    
    }

    return ret;
}

int hx_pqc_kyber_dlopen(hx_kyber512_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/kyber/libpqc_kyber.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (KYBER_KEYGEN)dlsym(pqc->handle, "crypto_kyber_keygen");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (KYBER_SIGN)dlsym(pqc->handle, "crypto_kyber_sign");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->verifyFunc = (KYBER_VERIFY)dlsym(pqc->handle, "crypto_kyber_verify");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_kyber_dlopen success\r\n");

    return 0;
}

int hx_pqc_aigis_dlopen(hx_aigis_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/aigis/libpqc_aigis.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (AIGIS_KEYGEN)dlsym(pqc->handle, "crypto_aigis_keygen");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (AIGIS_SIGN)dlsym(pqc->handle, "crypto_aigis_enc");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->verifyFunc = (AIGIS_VERIFY)dlsym(pqc->handle, "crypto_aigis_dec");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_aigis_dlopen success\r\n");

    return 0;
}


int hx_pqc_lac_dlopen(hx_lac_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/lac/libpqc_lac.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (LAC_KEYGEN)dlsym(pqc->handle, "crypto_lac_keygen");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (LAC_SIGN)dlsym(pqc->handle, "crypto_lac_enc");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->verifyFunc = (LAC_VERIFY)dlsym(pqc->handle, "crypto_lac_dec");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_lac_dlopen success\r\n");

    return 0;
}

int hx_pqc_sphincs_dlopen(hx_sphincs_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/sphincs/libpqc_sphinc.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (SPHINCS_KEYGEN)dlsym(pqc->handle, "crypto_sphinc_keygen");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (SPHINCS_SIGN)dlsym(pqc->handle, "crypto_sphinc_sign");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }    

    pqc->verifyFunc = (SPHINCS_VERIFY)dlsym(pqc->handle, "crypto_sphinc_verify");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_sphincs_dlopen success\r\n");

    return 0;
}

int hx_pqc_hqc_dlopen(hx_hqc_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/hqc/libpqc_hqc.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (HQC_KEYGEN)dlsym(pqc->handle, "crypto_hqc128_keygen");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (HQC_SIGN)dlsym(pqc->handle, "crypto_hqc128_enc");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }    

    pqc->verifyFunc = (HQC_VERIFY)dlsym(pqc->handle, "crypto_hqc128_dec");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_hqc_dlopen success\r\n");

    return 0;
}

int hx_pqc_bike_dlopen(hx_bike_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/bike/libpqc_bike.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (BIKE_KEYGEN)dlsym(pqc->handle, "crypto_kem_keypair");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (BIKE_SIGN)dlsym(pqc->handle, "crypto_kem_enc");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }    

    pqc->verifyFunc = (BIKE_VERIFY)dlsym(pqc->handle, "crypto_kem_dec");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_bike_dlopen success\r\n");

    return 0;
}

int hx_pqc_mce_dlopen(hx_mceliece_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/mceliece/libpqc_mceliece.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (MCE_KEYGEN)dlsym(pqc->handle, "crypto_mceliece_keygen");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (MCE_SIGN)dlsym(pqc->handle, "crypto_mceliece_enc");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }    

    pqc->verifyFunc = (MCE_VERIFY)dlsym(pqc->handle, "crypto_mceliece_dec");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_mce_dlopen success\r\n");

    return 0;
}

int hx_pqc_dili2_dlopen(hx_dili2_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/dili2/libpqc_dili2.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (DILI2_KEYGEN)dlsym(pqc->handle, "crypto_dili_keygen");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (DILI2_SIGN)dlsym(pqc->handle, "crypto_dili_sign");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->verifyFunc = (DILI2_VERIFY)dlsym(pqc->handle, "crypto_dili_verify");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_dili2_dlopen success\r\n");

    return 0;
}

int hx_pqc_falcon_dlopen(hx_falcon_t *pqc)
{
    const char* error = NULL;

    pqc->handle = dlopen("$ORIGIN/library/falcon/libpqc_falcon.so", RTLD_LAZY | RTLD_LOCAL);
    if (!pqc->handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    pqc->keygenFunc = (FALCON_KEYGEN)dlsym(pqc->handle, "crypto_falcon_keygen");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym keygen failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->signFunc = (FALCON_SIGN)dlsym(pqc->handle, "crypto_falcon_sign");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym sign failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    pqc->verifyFunc = (FALCON_VERIFY)dlsym(pqc->handle, "crypto_falcon_verify");
    if ((error = dlerror())) {
        fprintf(stderr, "dlsym verify failed: %s\n", error);
        dlclose(pqc->handle);
        return 1;
    }

    printf("hx_pqc_falcon_dlopen success\r\n");

    return 0;
}

int hx_pqc_dlopen(void *pqc_data, uint8_t mode)
{
    switch (mode) {
        case HX_KYBER512_KG:
        case HX_KYBER512_SIGN:
        case HX_KYBER512_VERIFY:{
            hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
            hx_pqc_kyber_dlopen(pqc);
            break;
        }
        case HX_AIGIS_KG:
        case HX_AIGIS_SIGN:
        case HX_AIGIS_VERIFY:{
            hx_aigis_t *pqc = (hx_aigis_t *)pqc_data;
            hx_pqc_aigis_dlopen(pqc);
            break;
        }
        case HX_LAC128_KG:
        case HX_LAC128_SIGN:
        case HX_LAC128_VERIFY:{
            hx_lac_t *pqc = (hx_lac_t *)pqc_data;
            hx_pqc_lac_dlopen(pqc);
            break;
        }
        case HX_SPHINCS_KG:
        case HX_SPHINCS_SIGN:
        case HX_SPHINCS_VERIFY:{
            hx_sphincs_t *pqc = (hx_sphincs_t *)pqc_data;
            hx_pqc_sphincs_dlopen(pqc);
            break;
        }
        case HX_HQC_KG:
        case HX_HQC_SIGN:
        case HX_HQC_VERIFY:{
            hx_hqc_t *pqc = (hx_hqc_t *)pqc_data;
            hx_pqc_hqc_dlopen(pqc);
            break;
        }
        case HX_BIKE_SIGN:
        case HX_BIKE_VERIFY:{
            hx_bike_t *pqc = (hx_bike_t *)pqc_data;
            hx_pqc_bike_dlopen(pqc);
            break;
        }
        case HX_MCELIECE_SIGN:
        case HX_MCELIECE_VERIFY:{
            hx_mceliece_t *pqc = (hx_mceliece_t *)pqc_data;
            hx_pqc_mce_dlopen(pqc);
            break;
        }
        case HX_DILI2_KG:
        case HX_DILI2_SIGN:
        case HX_DILI2_VERIFY:{
            hx_dili2_t *pqc = (hx_dili2_t *)pqc_data;
            hx_pqc_dili2_dlopen(pqc);
            break;
        }
        case HX_FALCON_SIGN:
        case HX_FALCON_VERIFY:{
            hx_falcon_t *pqc = (hx_falcon_t *)pqc_data;
            hx_pqc_falcon_dlopen(pqc);
            break;
        }
        default:
            printf("hx_pqc_dlopen: pqc mode is not supported\n");
            return 1;
    }

    return 0;
}

int hx_pqc_dlcopy(void *pqc_src, void *pqc_dst, uint8_t mode)
{
    switch (mode) {
        case HX_KYBER512_KG:
        case HX_KYBER512_SIGN:
        case HX_KYBER512_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_kyber512_t));
            break;
        }
        case HX_AIGIS_KG:
        case HX_AIGIS_SIGN:
        case HX_AIGIS_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_aigis_t));
            break;
        }
        case HX_LAC128_KG:
        case HX_LAC128_SIGN:
        case HX_LAC128_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_lac_t));
            break;
        }
        case HX_SPHINCS_KG:
        case HX_SPHINCS_SIGN:
        case HX_SPHINCS_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_sphincs_t));
            break;
        }
        case HX_HQC_KG:
        case HX_HQC_SIGN:
        case HX_HQC_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_hqc_t));
            break;
        }
        case HX_BIKE_SIGN:
        case HX_BIKE_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_bike_t));
            break;
        }
        case HX_MCELIECE_SIGN:
        case HX_MCELIECE_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_mceliece_t));
            break;
        }
        case HX_DILI2_KG:
        case HX_DILI2_SIGN:
        case HX_DILI2_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_dili2_t));
            break;
        }
        case HX_FALCON_SIGN:
        case HX_FALCON_VERIFY:{
            memcpy(pqc_dst, pqc_src, sizeof(hx_falcon_t));
            break;
        }
        default:
            printf("hx_pqc_dlcopy: pqc mode is not supported\n");
            return 1;
    }

    return 0;
}

int hx_pqc_dlclose(void *pqc_data, uint8_t mode)
{
    switch (mode) {
        case HX_KYBER512_KG:
        case HX_KYBER512_SIGN:
        case HX_KYBER512_VERIFY:{
            hx_kyber512_t *pqc = (hx_kyber512_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        case HX_AIGIS_KG:
        case HX_AIGIS_SIGN:
        case HX_AIGIS_VERIFY:{
            hx_aigis_t *pqc = (hx_aigis_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        case HX_LAC128_KG:
        case HX_LAC128_SIGN:
        case HX_LAC128_VERIFY:{
            hx_lac_t *pqc = (hx_lac_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        case HX_SPHINCS_KG:
        case HX_SPHINCS_SIGN:
        case HX_SPHINCS_VERIFY:{
            hx_sphincs_t *pqc = (hx_sphincs_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        case HX_HQC_KG:
        case HX_HQC_SIGN:
        case HX_HQC_VERIFY:{
            hx_hqc_t *pqc = (hx_hqc_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        case HX_BIKE_SIGN:
        case HX_BIKE_VERIFY:{
            hx_bike_t *pqc = (hx_bike_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        case HX_MCELIECE_SIGN:
        case HX_MCELIECE_VERIFY:{
            hx_mceliece_t *pqc = (hx_mceliece_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        case HX_DILI2_KG:
        case HX_DILI2_SIGN:
        case HX_DILI2_VERIFY:{
            hx_dili2_t *pqc = (hx_dili2_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        case HX_FALCON_SIGN:
        case HX_FALCON_VERIFY:{
            hx_falcon_t *pqc = (hx_falcon_t *)pqc_data;
            dlclose(pqc->handle);
            break;
        }
        default:
            printf("hx_pqc_dlclose: pqc mode is not supported\n");
            return 1;
    }

    return 0;
}

int hx_pqc_init_data(void **pqc_data, uint8_t mode)
{
    switch (mode) {
        case HX_KYBER512_KG:
        case HX_KYBER512_SIGN:
        case HX_KYBER512_VERIFY:{
            hx_kyber512_t *pqc = malloc(sizeof(hx_kyber512_t));
            memset(pqc, 0, sizeof(hx_kyber512_t));
            *pqc_data = (void *)pqc;
            break;
        }
        case HX_AIGIS_KG:
        case HX_AIGIS_SIGN:
        case HX_AIGIS_VERIFY:{
            hx_aigis_t *pqc = malloc(sizeof(hx_aigis_t));
            memset(pqc, 0, sizeof(hx_aigis_t));
            *pqc_data = (void *)pqc;
            break;
        }
        case HX_LAC128_KG:
        case HX_LAC128_SIGN:
        case HX_LAC128_VERIFY:{
            hx_lac_t *pqc = malloc(sizeof(hx_lac_t));
            memset(pqc, 0, sizeof(hx_lac_t));
            *pqc_data = (void *)pqc;
            break;
        }
        case HX_SPHINCS_KG:
        case HX_SPHINCS_SIGN:
        case HX_SPHINCS_VERIFY:{
            hx_sphincs_t *pqc = malloc(sizeof(hx_sphincs_t));
            memset(pqc, 0, sizeof(hx_sphincs_t));
            *pqc_data = (void *)pqc;
            break;
        }
        case HX_HQC_KG:
        case HX_HQC_SIGN:
        case HX_HQC_VERIFY:{
            hx_hqc_t *pqc = malloc(sizeof(hx_hqc_t));
            memset(pqc, 0, sizeof(hx_hqc_t));
            *pqc_data = (void *)pqc;
            break;
        }
        case HX_BIKE_SIGN:
        case HX_BIKE_VERIFY:{
            hx_bike_t *pqc = malloc(sizeof(hx_bike_t));
            memset(pqc, 0, sizeof(hx_bike_t));
            *pqc_data = (void *)pqc;
            break;
        }
        case HX_MCELIECE_SIGN:
        case HX_MCELIECE_VERIFY:{
            hx_mceliece_t *pqc = malloc(sizeof(hx_mceliece_t));
            memset(pqc, 0, sizeof(hx_mceliece_t));
            *pqc_data = (void *)pqc;
            break;
        }
        case HX_DILI2_KG:
        case HX_DILI2_SIGN:
        case HX_DILI2_VERIFY:{
            hx_dili2_t *pqc = malloc(sizeof(hx_dili2_t));
            memset(pqc, 0, sizeof(hx_kyber512_t));
            *pqc_data = (void *)pqc;
            break;
        }
        case HX_FALCON_SIGN:
        case HX_FALCON_VERIFY:{
            hx_falcon_t *pqc = malloc(sizeof(hx_falcon_t));
            memset(pqc, 0, sizeof(hx_falcon_t));
            *pqc_data = (void *)pqc;
            break;
        }
        default:
            printf("hx_pqc_init_data: pqc mode is not supported\n");
            return 1;
    }

    return 0;
}

int hx_rpu_pqc(int fd, int algo, int mode, int loop)
{
    int ret = HX_RET_FAILED;
    
    hx_cipher_t *cipher = (hx_cipher_t *)malloc(sizeof(hx_cipher_t));
    hx_session_t sess;
    memset(cipher, 0, sizeof(hx_cipher_t));
    cipher->sess = &sess;
    cipher->sess->mode = HX_SYNC_MODE;
    cipher->fd = fd;
    cipher->algo = algo;
    cipher->mode = mode;

    uint32_t pqc_req_len = get_pqc_req_len(mode);
    uint8_t *pqc_req = malloc(pqc_req_len);
    memset(pqc_req, 0, pqc_req_len);

#if PQC_AXI_BUS
    uint32_t pqc_res_len = get_pqc_res_axi_len(mode);
    cipher->bus = HX_AXI_RING_BUS;
#else    
    uint32_t pqc_res_len = get_pqc_res_fifo_len(mode);
    cipher->bus = HX_FIFO_RING_BUS;
#endif
    uint8_t *pqc_res = malloc(pqc_res_len);
    memset(pqc_res, 0, pqc_res_len);

#if DATA_DEBUG
    pqc_build_debug_data(pqc_req, mode);
#else
    uint8_t *pqc_data = NULL;
    hx_pqc_init_data(&pqc_data, mode);
    hx_pqc_dlopen(pqc_data, mode);
    pqc_build_random_data(pqc_req, pqc_req_len, pqc_data, mode);
#endif

    cipher->src = (uint8_t *)pqc_req;
    cipher->srclen = pqc_req_len;
    cipher->dst = (uint8_t *)pqc_res;
    cipher->dstlen = pqc_res_len;    

#if PQC_PERFORMANCE
        struct timespec start, stop;
        clock_gettime(CLOCK_REALTIME, &start);
        
        int i;
        for(i =0; i< loop; i++)
        {
            ret = hx_ioctl_pub_do(cipher);
            if(ret != HX_RET_SUCCESS)
                break;
        }

        clock_gettime(CLOCK_REALTIME, &stop);
        uint64_t time_us = time_delta(&start, &stop) / 1000;
        float time_ms = (float)(time_us)/1000.0;
        float times = loop * 1000 / time_ms;

        printf("Run \033[0m\033[1;32m%s\033[0m, %d times need %-6f ms, %6.2f times per second\r\n", 
                PQC_ALGO_NAME[mode], loop, time_ms, times);    
#else
    ret = hx_ioctl_pub_do(cipher);
#endif

#if DATA_DEBUG
    if(pqc_get_output_data(mode))
       ret = pqc_compare_data("debug", (int*)pqc_res, pqc_get_output_data(mode), pqc_res_len); 
#else
    ret = pqc_compare_random_data(pqc_res, pqc_data, mode);
    hx_pqc_dlclose(pqc_data, mode);
    if(pqc_data)
        free(pqc_data);
#endif

    free(pqc_req);
    free(pqc_res);
    free(cipher);

    return ret;
}

int hx_rpu_pqc_send(hx_cipher_t *cipher, uint8_t *pqc_data, int mode)
{
    int ret = HX_RET_FAILED;

    uint32_t pqc_req_len = get_pqc_req_len(mode);
    uint8_t *pqc_req = malloc(pqc_req_len);
    memset(pqc_req, 0, pqc_req_len);

#if PQC_AXI_BUS
    uint32_t pqc_res_len = get_pqc_res_axi_len(mode);
    cipher->bus = HX_AXI_RING_BUS;
#else    
    uint32_t pqc_res_len = get_pqc_res_fifo_len(mode);
    cipher->bus = HX_FIFO_RING_BUS;
#endif
    uint8_t *pqc_res = malloc(pqc_res_len);
    memset(pqc_res, 0, pqc_res_len);

    pqc_build_data(pqc_req, pqc_data, mode);

    cipher->mode = mode;
    cipher->src = (uint8_t *)pqc_req;
    cipher->srclen = pqc_req_len;
    cipher->dst = (uint8_t *)pqc_res;
    cipher->dstlen = pqc_res_len;  

    ret = hx_ioctl_pub_do(cipher);

    pqc_get_data(pqc_res, pqc_data, mode);

    free(pqc_req);
    free(pqc_res);

    return ret;
}

int hx_rpu_pqc_kyber(hx_cipher_t *cipher)
{
    int ret = HX_RET_FAILED;

    hx_kyber512_t *pqc = malloc(sizeof(hx_kyber512_t));
    memset(pqc, 0, sizeof(hx_kyber512_t));

    RAND_bytes(pqc->seed, sizeof(pqc->seed));
    //memcpy(pqc->seed, seed, sizeof(pqc->seed));

    hx_rpu_pqc_send(cipher, pqc, HX_KYBER512_KG);

    hx_rpu_pqc_send(cipher, pqc, HX_KYBER512_SIGN);

    hx_rpu_pqc_send(cipher, pqc, HX_KYBER512_VERIFY);

    return ret;
}

int hx_rpu_pqc_aigis(hx_cipher_t *cipher)
{
    int ret = HX_RET_FAILED;

    hx_aigis_t *pqc = malloc(sizeof(hx_aigis_t));
    memset(pqc, 0, sizeof(hx_aigis_t));

    RAND_bytes(pqc->seed, sizeof(pqc->seed));
    //memcpy(pqc->seed, seed, sizeof(pqc->seed));

    hx_rpu_pqc_send(cipher, pqc, HX_AIGIS_KG);

    hx_rpu_pqc_send(cipher, pqc, HX_AIGIS_SIGN);

    hx_rpu_pqc_send(cipher, pqc, HX_AIGIS_VERIFY);

    return ret;
}

int hx_rpu_pqc_lac(hx_cipher_t *cipher)
{
    int ret = HX_RET_FAILED;

    hx_lac_t *pqc = malloc(sizeof(hx_lac_t));
    memset(pqc, 0, sizeof(hx_lac_t));

    RAND_bytes(pqc->seed, sizeof(pqc->seed));
    //memcpy(pqc->seed, seed, sizeof(pqc->seed));
    RAND_bytes(pqc->msgseed, sizeof(pqc->msgseed));

    hx_rpu_pqc_send(cipher, pqc, HX_LAC128_KG);

    hx_rpu_pqc_send(cipher, pqc, HX_LAC128_SIGN);

    hx_rpu_pqc_send(cipher, pqc, HX_LAC128_VERIFY);

    return ret;
}

int hx_rpu_pqc_stream(int fd, int algo, int mode, int loop)
{
    int ret = HX_RET_FAILED;
    struct timespec start, stop;
    uint32_t pqc_req_len = 0, pqc_res_len = 0;
    uint8_t *pqc_req = NULL, *pqc_res = NULL;
    uint8_t *req_ptr = NULL, *res_ptr = NULL;
    int **pqc_data = NULL;

    hx_cipher_t *cipher = (hx_cipher_t *)malloc(sizeof(hx_cipher_t));
    hx_session_t sess;
    memset(cipher, 0, sizeof(hx_cipher_t));
    cipher->sess = &sess;
    cipher->sess->mode = HX_ASYNC_POLLING_MODE;
    cipher->sess->state = HX_RET_FAILED;
    cipher->fd = fd;
    cipher->algo = algo;
    cipher->mode = mode;
    cipher->bus = HX_FIFO_RING_BUS;

    pqc_req_len = get_pqc_req_len(mode);
    pqc_req = malloc(pqc_req_len * loop);
    req_ptr = pqc_req;
    memset(pqc_req, 0, pqc_req_len * loop);

    pqc_res_len = get_pqc_res_fifo_len(mode);
    pqc_res = malloc(pqc_res_len * loop);
    res_ptr = pqc_res;
    memset(pqc_res, 0, pqc_res_len * loop);

    pqc_data = (int **)malloc(loop * sizeof(int *));

    for(int i=0; i<loop; i++)
    {
        hx_pqc_init_data(&pqc_data[i], mode);

        if(i == 0)
            hx_pqc_dlopen(pqc_data[0], mode);
        else
            hx_pqc_dlcopy(pqc_data[0], pqc_data[i], mode);

        pqc_build_random_data(req_ptr, pqc_req_len, pqc_data[i], mode);
        req_ptr += pqc_req_len;
    }

    req_ptr = pqc_req;
    res_ptr = pqc_res;
    cipher->srclen = pqc_req_len;
    cipher->dstlen = pqc_res_len;

    hx_pub_init(cipher);

    clock_gettime(CLOCK_REALTIME, &start);

    for(int i=0; i<loop; i++)
    {
        cipher->src = req_ptr;
        cipher->dst = res_ptr;
        cipher->pack_id = i+1;
        if(i == loop -1)
            cipher->final = 1;

        while((ret = hx_ioctl_pub_do(cipher)) != HX_RET_SUCCESS)
        {
            if(ret == HX_RET_TIMEOUT)
            {
                printf("pub do timeout\r\n");
                break;
            }
            //Add delay to avoid allocing failed s_cookie
            usleep(1000*100);
        }

        req_ptr += pqc_req_len;
        res_ptr += pqc_res_len;
    }

    while(cipher->sess->pack_id < loop)
    {
        if(hx_pub_status(cipher) == HX_RET_TIMEOUT)
        {
            printf("pub status timeout\r\n");
            ret = HX_RET_TIMEOUT;
            break;
        }       
        usleep(10);
    }

    if(ret != HX_RET_TIMEOUT)
        hx_pub_cleanup(cipher);

    clock_gettime(CLOCK_REALTIME, &stop);
    loop_time_calculate(&start, &stop, mode, loop);

    res_ptr = pqc_res;
    for(int i=0; i<loop; i++)
    {
        ret = pqc_compare_random_data(res_ptr, pqc_data[i], mode);
        res_ptr += pqc_res_len;
    }     

    hx_pqc_dlclose(pqc_data[0], mode);
    for(int i=0; i<loop; i++)
        free(pqc_data[i]);
    free(pqc_data);
    free(pqc_req);
    free(pqc_res);

    return ret;
}

int hx_rpu_pub_benchmark(int fd, int algo, int mode, int loop)
{
    int ret = HX_RET_FAILED;

    if(algo == HX_SM2 || algo == HX_ECC)
        ret = hx_rpu_pub_sm2(fd, algo, mode, loop);
    else if(algo == HX_RSA)
        ret = hx_rpu_pub_rsa(fd, algo, mode, loop);
    else if(algo == HX_TRNG)
        ret = hx_rpu_pub_trng(fd, algo, mode, loop);
    else if(algo == HX_PQC)
        ret = hx_rpu_pqc(fd, algo, mode, loop);
    else
        printf("hx_rpu_pub_benchmark algo not support %d\r\n", algo);

    return ret;
}

int hx_rpu_pqc_algo(int fd, int algo, int mode, int loop)
{
    int ret = HX_RET_FAILED;
    hx_rpu_ctx_t rpu_ctx;
    hx_cipher_t cipher;
    memset(&cipher, 0, sizeof(hx_cipher_t));
    cipher.sess = &rpu_ctx.sess;
    cipher.sess->mode = HX_SYNC_MODE;
    cipher.fd = fd;
    cipher.algo = algo;

    //hx_rpu_pqc_kyber(&cipher);
    //hx_rpu_pqc_aigis(&cipher);
    hx_rpu_pqc_lac(&cipher);

    return ret;
}

int performance_hard_test(benchmark_t *benchmark)
{
    int fd, ret = HX_RET_FAILED;
    ioctl_performance_test_t perf_param;

    fd = hx_open_dev(hx_dev_name, NULL);
    if ((fd == HX_RET_NO_DEVICE) || (fd == HX_RET_FAILED)) {
        printf("Device Open Filed.\n");
        return ret;
    }

    memset(&perf_param, 0x0, sizeof(ioctl_performance_test_t));
    perf_param.algo_id = benchmark->algo;
    perf_param.alg_mode = benchmark->mode;
    perf_param.packet_num = benchmark->loop;

    ret = ioctl(fd, IOCTL_PERGORMANCE_HARDWARE, &perf_param);
    if(ret == -1){
        printf("performance_test error\n");
        return -errno;
    }

    float time_ms = (float)(perf_param.used_time_us)/1000.0;
    float times_second = (float)(benchmark->loop * 1000);
    times_second = times_second / time_ms;

    printf("%-6f(ms), %d(times), %6.2f(per second)\n", time_ms, benchmark->loop,  times_second);

    hx_close_dev(fd, NULL);
    return 0;
}

int encrypt_read_file(char *filename, uint8_t **filedata, uint32_t *filesize, int algo_id, int algo_mode)
{
    uint32_t size = 0;

    FILE *fp = fopen(filename,"rb");
    if(fp == NULL)
    {
        printf("%s: %s file not find.\n", __func__, filename);
        return -1;
    }

    fseek(fp, 0L, SEEK_END);      
    size = ftell(fp);

    if(algo_id <= HX_ALGO_AES && algo_mode <= HX_CIPHER_CTR && size % 16)
        *filesize = size + (16 - size % 16);
    else
        *filesize = size;

    if((*filedata = (uint8_t *)malloc(*filesize)) == NULL)
    {
        printf("No enough memory!\n");
        return -1;
    }

    fseek(fp, 0L, SEEK_SET);        
    fread(*filedata, *filesize, 1, fp);

    fclose(fp);

    return 0;    
}

int encrypt_write_file(char *filename, char *algoname, uint8_t *filedata, uint32_t filesize, int algo_id, int algo_mode)
{
    char name[100];
    sprintf(name, "%s_%s", filename, algoname);

    FILE *fp = fopen(name,"wb+");
    if(fp == NULL)
    {
        printf("%s: %s file not find.\n", __func__, filename);
        return -1;
    }

    if(algo_mode == HX_CIPHER_CMAC || algo_mode == HX_CIPHER_CBC_MAC)
        filesize = HX_AES_MAC_OUT_SIZE;

    fwrite(filedata, filesize, 1, fp);

    fclose(fp);

    return 0;    
}

int main(int argc, char const *argv[])
{
    showTaskTid(__FUNCTION__);
    attach_cpu(HX_SEND_BIND);

    pthread_t ptid;
    int fd, ret = HX_RET_FAILED;

    benchmark_t g_benchmark;
    memset(&g_benchmark, 0, sizeof(benchmark_t));

    g_benchmark.function = atoi(argv[1]);
 
    if(g_benchmark.function == 1)
    {
        g_benchmark.algo        = atoi(argv[2]);
        g_benchmark.mode        = atoi(argv[3]);
        g_benchmark.loop        = atoi(argv[4]);

        fd = hx_open_dev(hx_dev_name, &ptid);
        if ((fd == HX_RET_NO_DEVICE) || (fd == HX_RET_FAILED)) {
            printf("Device Open Filed.\n");
            return ret;
        }

        hx_rpu_pub_benchmark(fd, g_benchmark.algo, g_benchmark.mode, g_benchmark.loop);

        hx_close_dev(fd, &ptid);

        return EXIT_SUCCESS;
    }
    else if(g_benchmark.function == 2)
    {
        g_benchmark.algo = atoi(argv[2]);
        g_benchmark.mode = atoi(argv[3]);
        g_benchmark.loop = atoi(argv[4]);

        fd = hx_open_dev(hx_dev_name, &ptid);
        if ((fd == HX_RET_NO_DEVICE) || (fd == HX_RET_FAILED)) {
            printf("Device Open Filed.\n");
            return ret;
        } 

        int i;
        for(i =0; i< g_benchmark.loop; i++)
        {
            printf("%d times\r\n", i);
            ret = hx_rpu_pub_benchmark(fd, g_benchmark.algo , g_benchmark.mode, 1);
            if(ret != HX_RET_SUCCESS)
                break;
        }

        hx_close_dev(fd, &ptid);

        return EXIT_SUCCESS;
    }
    else if(g_benchmark.function == 3)
    {
        fd = hx_open_dev(hx_dev_name, &ptid);
        if ((fd == HX_RET_NO_DEVICE) || (fd == HX_RET_FAILED)) {
            printf("Device Open Filed.\n");
            return ret;
        } 

        int i;
        for(i =0; i<= HX_DILI2_VERIFY; i++)
        {
            printf("mode = %d\r\n", i);
            ret = hx_rpu_pub_benchmark(fd, 4, i, 1000);
            if(ret != HX_RET_SUCCESS)
                break;
            printf("\r\n");
        }
        
        hx_close_dev(fd, &ptid);

        return EXIT_SUCCESS;
    }
    else if(g_benchmark.function == 4)
    {
        fd = hx_open_dev(hx_dev_name, &ptid);
        if ((fd == HX_RET_NO_DEVICE) || (fd == HX_RET_FAILED)) {
            printf("Device Open Filed.\n");
            return ret;
        }

        hx_rpu_pqc_algo(fd, 4, 3, 1);

        hx_close_dev(fd, &ptid);

        return EXIT_SUCCESS;
    }
    else if(g_benchmark.function == 5)
    {
        g_benchmark.algo = atoi(argv[2]);
        g_benchmark.mode = atoi(argv[3]);
        g_benchmark.loop = atoi(argv[4]);

        fd = hx_open_dev(hx_dev_name, &ptid);
        if ((fd == HX_RET_NO_DEVICE) || (fd == HX_RET_FAILED)) {
            printf("Device Open Filed.\n");
            return ret;
        }

        if(g_benchmark.mode == HX_SPHINCS_SIGN || g_benchmark.mode == HX_SPHINCS_VERIFY 
            || g_benchmark.mode == HX_MCELIECE_SIGN)
            printf("mode is not support, mode = %d\r\n", g_benchmark.mode);
        else
            hx_rpu_pqc_stream(fd, g_benchmark.algo, g_benchmark.mode, g_benchmark.loop);

        hx_close_dev(fd, &ptid);

        return EXIT_SUCCESS;
    }
    else if(g_benchmark.function == 6)
    {
        fd = hx_open_dev(hx_dev_name, &ptid);
        if ((fd == HX_RET_NO_DEVICE) || (fd == HX_RET_FAILED)) {
            printf("Device Open Filed.\n");
            return ret;
        } 

        int i;
        for(i =0; i<= HX_DILI2_VERIFY; i++)
        {
            if(i == HX_SPHINCS_SIGN || i == HX_SPHINCS_VERIFY || i == HX_MCELIECE_SIGN)
                continue;
            printf("mode = %d\r\n", i);
            ret = hx_rpu_pqc_stream(fd, 4, i, 1);
            if(ret != HX_RET_SUCCESS)
                break;
            printf("\r\n");
        }
        
        hx_close_dev(fd, &ptid);

        return EXIT_SUCCESS;
    }
    else
        printf("function id do not support\r\n");

    return EXIT_FAILURE;
}
