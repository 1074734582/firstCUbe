
#ifndef __API_H_
#define __API_H_

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define PQC_AXI_BUS 0

#define PQC_PERFORMANCE 1

#define DATA_DEBUG 0

#define ESRAM_DEBUG 0

#define HX_MAX_KEY_LENGTH              (512)

#define HX_MAX_IV_LENGTH               (16)

#define HX_MAX_TAG_LENGTH              (16)

#define HX_MAX_AAD_LENGTH              (16)

#define HX_MAX_HMAC_KEY_SIZE           (128)

#define HX_MAX_PRF_SEC_SIZE            (128)

#define HX_MAX_PRF_SEED_SIZE           (208)

#define HX_MAX_PRF_OUT_SIZE            (192)

#define HX_MAX_HMAC_PRF_KEY_SIZE       (160)

#define HX_MAX_HASH_HMAC_IV_SIZE       (224)

#define HX_SM3_SHA2_STEP_SIZE          (64*64)

#define HX_SHA3_256_STEP_SIZE          (136*30)

#define HX_AES_SM4_STEP_SIZE           (4096)

#define HX_MAX_STEP_SIZE               (8064)

#define HX_HASH_HMAC_OUT_SIZE          (32)

#define HX_AES_MAC_OUT_SIZE            (16)

#define HX_PRF_SEED_MAX_SIZE           (208)

//sm2
#define HX_SM2_MESSAGE_LEN             (32)

#define HX_SM2_DA_LEN                  (32)

#define HX_SM2_PA_LEN                  (64)

#define HX_SM2_RANDOM_LEN              (32) 

#define HX_SM2_VERIFY_LEN              (64)

#if ESRAM_DEBUG
#define HX_SM2_OUTPUT_LEN              (96)
#else
#define HX_SM2_OUTPUT_LEN              (64)
#endif

//rsa
#define HX_RSA_1024_LEN                (128)

#define HX_RSA_2048_LEN                (256)

#define HX_RSA_CRT_1024_LEN            (64)

#define HX_RSA_CRT_2048_LEN            (128)

//trng
#define HX_TRNG_PKG_LEN                 (2000)

//pqc
#define  DATA_64_ALIGN(len)     ((len) % 64 == 0 ? (len) :  (len) - (len) % 64 + 64)
#define  DATA_48_ALIGN(len)     ((len) % 48 == 0 ? (len) :  (len) - (len) % 48 + 48)

//kyber
#define KYBER512_SEED_LEN               (32)
#define KYBER512_SK_LEN                 (1600)
#define KYBER512_PK_LEN                 (800)
#define KYBER512_PK_START_LEN           (768)
#define KYBER512_CT_LEN                 (768)
#define KYBER512_SS_LEN                 (32)

//aigis
#define AIGIS_SEED_LEN                  (32)
#define AIGIS_PK_LEN                    (672)
#define AIGIS_PK_START_LEN              (832)
#define AIGIS_SK_LEN                    (1536)
#define AIGIS_CT_LEN                    (736)
#define AIGIS_SS_LEN                    (32)

//lac
#define LAC_SEED_LEN                    (32)
#define LAC_PK_LEN                      (544)
#define LAC_SK_LEN                      (1056)
#define LAC_MSG_SEED_LEN                (128)
#define LAC_CT_LEN                      (712)
#define LAC_SS_LEN                      (32)

//sphincs
#define SPHINCS_SEED_LEN                (48)
#define SPHINCS_KEY_LEN                 (16)
#define SPHINCS_PK_LEN                  (32)
#define SPHINCS_SK_LEN                  (64)
#define SPHINCS_SIGN_SEED_LEN           (16)
#define SPHINCS_MSG_LEN                 (33)
#define SPHINCS_SIGN_LEN                (17088)
#define SPHINCS_VERIFY_LEN              (16)

//hqc
#define HQC_SEED_LEN                    (80)
#define HQC_PK_LEN                      (2249)
#define HQC_SK_LEN                      (2289)
#define HQC_SIGN_SEED_LEN               (32)
#define HQC_CT_LEN                      (4497)
#define HQC_SS_LEN                      (64)
#define HQC_M_LEN                       (16)
#define HQC_SAULT_LEN                   (16)

//bike
#define BIKE_SEED_LEN                   (64)
#define BIKE_PK_LEN                     (1541)
#define BIKE_SK_LEN                     (3114)
#define BIKE_MSG_SEED_LEN               (128)
#define BIKE_CT_LEN                     (1573)
#define BIKE_SS_LEN                     (32)

//mceliece
#define MCE_PK_LEN                      (261120)
#define MCE_SK_LEN                      (6492)
#define MCE_SEED_LEN                    (128)
#define MCE_CT_LEN                      (128)
#define MCE_SS_LEN                      (32)

//dili2
#define DILI2_SEED_LEN                  (32)
#define DILI2_PK_LEN                    (1312)
#define DILI2_SK_LEN                    (2544)
#define DILI2_CT_LEN                    (2420)
#define DILI2_SS_LEN                    (16)
#define DILI2_MSG_LEN                   (33)

//falcon
#define HX_PQC_FALCON_ENC_SK_IN_LEN     (57344)
#define HX_PQC_FALCON_ENC_SEED_IN_LEN   (64)
#define HX_PQC_FALCON_ENC_NONCE_IN_LEN  (64)
#define HX_PQC_FALCON_ENC_MSG_IN_LEN    (128)
#define HX_PQC_FALCON_ENC_IN_LEN        (HX_PQC_FALCON_ENC_SK_IN_LEN + HX_PQC_FALCON_ENC_SEED_IN_LEN + HX_PQC_FALCON_ENC_NONCE_IN_LEN + HX_PQC_FALCON_ENC_MSG_IN_LEN)
#define HX_PQC_FALCON_ENC_OUT_LEN       (640)

#define HX_PQC_FALCON_DEC_PK_IN_LEN     (960)
#define HX_PQC_FALCON_DEC_SIGN_IN_LEN   (704)
#define HX_PQC_FALCON_DEC_NONCE_IN_LEN  (128)
#define HX_PQC_FALCON_DEC_IN_LEN        (HX_PQC_FALCON_DEC_PK_IN_LEN + HX_PQC_FALCON_DEC_SIGN_IN_LEN + HX_PQC_FALCON_DEC_NONCE_IN_LEN)
#define HX_PQC_FALCON_DEC_OUT_LEN       (64)

typedef struct poll_thread_param_
{
    int fd;
    uint32_t poll_wait_us;
    uint8_t poll_thread_flag;
} poll_thread_param_t;

typedef enum hx_ret_code_
{
    HX_RET_SUCCESS        = 0,     
    HX_RET_FAILED         = -1,   
    HX_RET_NO_DEVICE      = -2,   
    HX_RET_DEVICE_BUSY    = -3,    
    HX_RET_NO_MEM         = -4,   
    HX_RET_ARG_ADDR_ERROR = -5,   
    HX_RET_ARG_CMD_ERROR  = -6,   
    HX_RET_CTX_ERROR      = -7,   
    HX_RET_PARAM_ERROR    = -8,   
    HX_RET_LEN_ERROR      = -10,  
    HX_RET_KEY_ERROR      = -11,  
    HX_RET_TIMEOUT        = -12,   
    HX_RET_UNSUPPORT_ALGO = -13,  
    HX_RET_NO_DEV_RIGHT   = -14,  
    HX_RET_NO_KEY_RIGHT   = -15,  

} hx_ret_code_t;

typedef enum hx_algo_ {
    HX_ALGO_SM2 = 0,
    HX_ALGO_ECC = 1,
    HX_ALGO_RSA = 2,

    HX_ALGO_SM4 = 8,
    HX_ALGO_AES = 9,
    HX_ALGO_SM3 = 10,
    HX_ALGO_SHA256 = 11,
    HX_ALGO_SHA3_256 = 12,
} hx_algo_e;

typedef enum hx_aes_mode_
{
    HX_CIPHER_ECB,
    HX_CIPHER_CBC,
    HX_CIPHER_CFB,
    HX_CIPHER_OFB,
    HX_CIPHER_CTR,
    HX_CIPHER_XTS,
    HX_CIPHER_CMAC,
    HX_CIPHER_CBC_MAC,
    HX_CIPHER_CCM,
    HX_CIPHER_GCM,
} hx_aes_mode_e;

typedef enum hx_service_type_ {
    HX_PUB = 0,
    HX_PQC_RPU = 1,
} hx_service_type_e;

typedef enum hx_func_id_ {
    HX_SM2 = 0,
    HX_ECC = 1,
    HX_RSA = 2,
    HX_TRNG = 3,
    HX_PQC = 4,
} hx_func_id_e;

typedef enum hx_sm2_mode_ {
    HX_SM2_SIGN = 0,
    HX_SM2_VERIFY = 1,
    HX_SM2_KP = 2,
    HX_SM2_KG = 3,
    HX_SM2_SIGN_TRNG = 4,
} hx_sm2_mode_e;

typedef enum hx_rsa_mode_ {
    HX_RSA_SIGN_1024 = 0,
    HX_RSA_SIGN_1024_CRT = 1,
    HX_RSA_VERIFY_1024 = 2,
    HX_RSA_SIGN_2048 = 3,
    HX_RSA_SIGN_2048_CRT = 4,
    HX_RSA_VERIFY_2048 = 5,
} hx_rsa_mode_e;

typedef enum hx_pqc_mode_ {
    HX_KYBER512_KG      = 0,
    HX_KYBER512_SIGN    = 1,
    HX_KYBER512_VERIFY  = 2,
    HX_AIGIS_KG         = 3,
    HX_AIGIS_SIGN       = 4,
    HX_AIGIS_VERIFY     = 5,
    HX_LAC128_KG        = 6,
    HX_LAC128_SIGN      = 7,
    HX_LAC128_VERIFY    = 8,
    HX_SPHINCS_KG       = 9,
    HX_SPHINCS_SIGN     = 10,
    HX_SPHINCS_VERIFY   = 11,
    HX_HQC_KG           = 12,
    HX_HQC_SIGN         = 13,
    HX_HQC_VERIFY       = 14,
    HX_BIKE_SIGN        = 15,
    HX_BIKE_VERIFY      = 16,
    HX_MCELIECE_SIGN    = 17,
    HX_MCELIECE_VERIFY  = 18,
    HX_DILI2_KG         = 19,
    HX_DILI2_SIGN       = 20,
    HX_DILI2_VERIFY     = 21,
    HX_FALCON_SIGN      = 22,
    HX_FALCON_VERIFY    = 23,
} hx_pqc_mode_e;

typedef enum hx_bus_type_ {
    HX_FIFO_REG_BUS = 0,
    HX_FIFO_RING_BUS = 1,
    HX_AXI_REG_BUS = 2,
    HX_AXI_RING_BUS = 3,
} hx_bus_type_e;

typedef enum hx_cipher_encrypt_
{
    HX_CIPHER_ENCRYPT,
    HX_CIPHER_DECRYPT,
} hx_cipher_encrypt_e;

typedef enum hx_hash_mode_
{
    HX_HASH_MODE,
    HX_GCM_J0_MODE,
    HX_HMAC_MODE,
    HX_PRF_MODE,
} hx_hash_mode_e;

typedef enum hx_sess_mode_
{
    HX_SYNC_MODE,               
    HX_ASYNC_POLLING_MODE,     
	HX_ASYNC_CALLBACK_MODE,     
} hx_sess_mode_e;

typedef enum hx_package_type_
{
    HX_PACKAGE_START = 1,
    HX_PACKAGE_MIDDLE = 2,     
    HX_PACKAGE_END =4,    
    HX_PACKAGE_COMPLETE = 5,  
} hx_package_type_e;

typedef enum hx_sess_package_
{
    HX_FULL_PACKAGE = 1,
    HX_INDEPENDENT_PACKAGE = 2,
} hx_sess_package_e;

typedef enum hx_cipher_mode_
{
    HX_CIPHER_ONCE = 0,
    HX_CIPHER_PACKAGE = 1,
    HX_CIPHER_STREAM = 2,
} hx_cipher_mode_e;

typedef void (*hx_cb_func)(void *cb_param);

typedef struct hx_sess_
{
    uint64_t pid;           
    uint64_t pack_id;      
    uint64_t state;        
    uint64_t pack_count;
    void *cb_param;         
    hx_cb_func cb;          
    hx_sess_mode_e mode;    
    int flag;               
    void *sess_ptr;         
} hx_session_t;

typedef struct hx_cipher_
{   
    int fd;                             
    int key_index;                      
    hx_session_t *sess;                 
    hx_algo_e algo;            
    hx_aes_mode_e mode;             
    hx_cipher_encrypt_e enc;           
    hx_package_type_e pkg_mode;

    uint8_t key[HX_MAX_KEY_LENGTH];    
    int key_len;                        
    uint8_t iv[HX_MAX_IV_LENGTH];    
    int iv_len;                        
    uint8_t aad[HX_MAX_AAD_LENGTH];  
    int aad_len;                      
    uint8_t tag[HX_MAX_TAG_LENGTH];   
    int tag_len;                       
    uint8_t final;
    uint16_t total_len;

    uint8_t *src;
    uint32_t srclen;
    uint8_t *dst;
    uint32_t dstlen;

    uint32_t bus;
    uint64_t pack_id; 

    uint64_t drv_ctx;
    int L, M;
    int iv_gen;
    int iv_set;
    int key_set;
    int tag_set;
    int len_set;
    int force_update;
    uint8_t *private;
} hx_cipher_t;

typedef struct hx_md_
{
    int fd;
    hx_session_t *sess;
    hx_algo_e algo;
    hx_hash_mode_e mode;
    hx_package_type_e pkg_mode;

    uint8_t key[HX_MAX_HMAC_PRF_KEY_SIZE];    
    int key_len;                       
    uint8_t iv[HX_MAX_HASH_HMAC_IV_SIZE];     
    int iv_len;                         

    uint8_t *src;
    uint32_t srclen;
    uint8_t *dst;
    uint32_t dstlen;

    uint8_t digest[64];
    uint8_t block[256];
    uint32_t num;
    uint32_t total_len;
    uint64_t drv_ctx;
    uint8_t *private;

    uint32_t final;
} hx_md_t;

typedef struct hx_md_ctx_
{
    int fd;             
    hx_session_t sess;   
    hx_sess_package_e package;
    uint8_t *digest;
    uint8_t *private;
    uint8_t *md;
} __attribute__ ((packed)) hx_md_ctx_t;

typedef struct hx_rpu_ctx_
{   
    int fd;
    int algo;
    int api_mode;
    hx_cipher_mode_e cipher_mode;
    uint8_t key_size;

    int algo_id;
    int algo_mode;
    int algo_dir;    
    hx_session_t sess;                            
    uint8_t *cipher;

    uint8_t *key;    
    uint32_t keylen;                        
    uint8_t *iv;    
    uint32_t ivlen;                        
    uint8_t *aad;  
    uint32_t aadlen;                      
    uint8_t *tag;   
    uint32_t taglen;                       

    uint8_t *src;
    uint32_t srclen;
    uint8_t *dst;
    uint32_t dstlen;
    uint32_t steplen;

    uint8_t *opssl_out;
} hx_rpu_ctx_t;

typedef struct hx_sm2_data_
{
    uint32_t id;
    uint8_t message[32];
    uint8_t da[32];
    uint8_t pa[64];
    uint8_t random[32];
    uint8_t verify[64];
} hx_sm2_data_t;

typedef struct hx_sm2_pkg_
{
    uint32_t size;
    uint64_t addr;
    uint32_t index;
    hx_sm2_data_t data[];
} hx_sm2_pkg_t;

typedef struct hx_sm2_output_
{
    uint32_t id;
    uint8_t output[HX_SM2_OUTPUT_LEN];
} hx_sm2_output_t;

typedef struct hx_sm2_result_
{
    uint32_t size;
    uint64_t addr;
    uint32_t index;
    hx_sm2_output_t data[];
} hx_sm2_result_t;

typedef struct hx_rsa_data_
{
    uint32_t id;
    uint8_t message[256];
    uint8_t d[256];
    uint8_t e[256];
    uint8_t N[256];
    uint8_t dp[128];
    uint8_t dq[128];
    uint8_t p[128];
    uint8_t q[128];
    uint8_t qinv[128];
} hx_rsa_data_t;

typedef struct hx_rsa_pkg_
{
    uint32_t size;
    uint64_t addr;
    uint32_t index;
    hx_rsa_data_t data[];
} hx_rsa_pkg_t;

typedef struct hx_rsa_output_
{
    uint32_t id;
    uint8_t output[HX_RSA_2048_LEN];
} hx_rsa_output_t;

typedef struct hx_rsa_result_
{
    uint32_t size;
    uint64_t addr;
    uint32_t index;
    hx_rsa_output_t data[];
} hx_rsa_result_t;

typedef int (*KYBER_KEYGEN)(unsigned char *, unsigned char *,unsigned char *);
typedef int (*KYBER_SIGN)(unsigned char *, unsigned char *,unsigned char *,unsigned char *);
typedef int (*KYBER_VERIFY)(unsigned char *, unsigned char *,unsigned char *);
typedef struct hx_kyber512_
{
    void *handle;
    KYBER_KEYGEN keygenFunc;
    KYBER_SIGN signFunc;
    KYBER_VERIFY verifyFunc;
    uint8_t seed[KYBER512_SEED_LEN];
    uint8_t pk[KYBER512_PK_LEN];
    uint8_t sk[KYBER512_SK_LEN + 32]; //dl need 1632 bytes
    uint8_t ct[KYBER512_CT_LEN];
    uint8_t ss[KYBER512_SS_LEN];
} hx_kyber512_t;

typedef int (*AIGIS_KEYGEN)(unsigned char *, unsigned char *,unsigned char *);
typedef int (*AIGIS_SIGN)(unsigned char *, unsigned char *,unsigned char *, unsigned char *);
typedef int (*AIGIS_VERIFY)(unsigned char *, unsigned char *,unsigned char *);
typedef struct hx_aigis_
{
    void *handle;
    AIGIS_KEYGEN keygenFunc;
    AIGIS_SIGN signFunc;
    AIGIS_VERIFY verifyFunc;
    uint8_t seed[AIGIS_SEED_LEN];
    uint8_t pk[AIGIS_PK_LEN];
    uint8_t sk[AIGIS_SK_LEN];
    uint8_t ct[AIGIS_CT_LEN];
    uint8_t ss[AIGIS_SS_LEN];     
} hx_aigis_t;

typedef int (*LAC_KEYGEN)(unsigned char *, unsigned char *,unsigned char *);
typedef int (*LAC_SIGN)(uint8_t *pk, uint8_t *ct, uint8_t *ss);
typedef int (*LAC_VERIFY)(unsigned char *sk, unsigned char *ct, unsigned char *ss1);
typedef struct hx_lac_
{
    void *handle;
    LAC_KEYGEN keygenFunc;
    LAC_SIGN signFunc;
    LAC_VERIFY verifyFunc;
    uint8_t seed[LAC_SEED_LEN];
    uint8_t pk[LAC_PK_LEN];
    uint8_t sk[LAC_SK_LEN];
    uint8_t ct[LAC_CT_LEN];
    uint8_t ss[LAC_SS_LEN];
    uint8_t msgseed[LAC_MSG_SEED_LEN];
} hx_lac_t;

typedef int (*SPHINCS_KEYGEN)(unsigned char *, unsigned char *,unsigned char *);
typedef int (*SPHINCS_SIGN)(uint8_t *seed, uint8_t *msg, uint32_t msglen, uint8_t *sk, uint8_t *sign, uint32_t *signlen);
typedef int (*SPHINCS_VERIFY)(uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk, uint8_t *verify);
typedef struct hx_sphincs_
{
    void *handle;
    SPHINCS_KEYGEN keygenFunc;
    SPHINCS_SIGN signFunc;
    SPHINCS_VERIFY verifyFunc;
    uint8_t seed[SPHINCS_SEED_LEN];
    uint8_t pk[SPHINCS_PK_LEN];
    uint8_t sk[SPHINCS_SK_LEN];
    uint8_t msg[SPHINCS_MSG_LEN];
    uint8_t sign[SPHINCS_SIGN_LEN];
} hx_sphincs_t;

typedef int (*HQC_KEYGEN)(uint8_t *seed, uint8_t *pk, uint8_t *sk);
typedef int (*HQC_SIGN)(uint8_t *pk, uint8_t *ct, uint8_t *ss);
typedef int (*HQC_VERIFY)(unsigned char *sk, unsigned char *ct, unsigned char *ss1);
typedef struct hx_hqc_
{
    void *handle;
    HQC_KEYGEN keygenFunc;
    HQC_SIGN signFunc;
    HQC_VERIFY verifyFunc;
    uint8_t seed[HQC_SEED_LEN];
    uint8_t pk[HQC_PK_LEN];
    uint8_t sk[HQC_SK_LEN];
    uint8_t ct[HQC_CT_LEN];
    uint8_t ss[HQC_SS_LEN];
    uint8_t m[HQC_M_LEN];
    uint8_t salt[HQC_SAULT_LEN];
} hx_hqc_t;

typedef int (*BIKE_KEYGEN)(unsigned char *, unsigned char *, unsigned char *);
typedef int (*BIKE_SIGN)(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
typedef int (*BIKE_VERIFY)(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
typedef struct hx_bike_
{
    void *handle;
    BIKE_KEYGEN keygenFunc;
    BIKE_SIGN signFunc;
    BIKE_VERIFY verifyFunc;
    uint8_t seed[BIKE_SEED_LEN];
    uint8_t pk[BIKE_PK_LEN];
    uint8_t sk[BIKE_SK_LEN];
    uint8_t ct[BIKE_CT_LEN];
    uint8_t ss[BIKE_SS_LEN];
    uint8_t msgseed[BIKE_MSG_SEED_LEN];
} hx_bike_t;

typedef int (*MCE_KEYGEN)(uint8_t *pk,  uint8_t *sk);
typedef int (*MCE_SIGN)(uint8_t *pk,  uint8_t *ct, uint8_t *ss);
typedef int (*MCE_VERIFY)(uint8_t *ss1,  uint8_t *ct, uint8_t *sk);
typedef struct hx_mceliece_
{
    void *handle;
    MCE_KEYGEN keygenFunc;
    MCE_SIGN signFunc;
    MCE_VERIFY verifyFunc;
    uint8_t seed[MCE_SEED_LEN];
    uint8_t pk[MCE_PK_LEN];
    uint8_t sk[MCE_SK_LEN];
    uint8_t ct[MCE_CT_LEN];
    uint8_t ss[MCE_SS_LEN];
} hx_mceliece_t;

typedef int (*DILI2_KEYGEN)(unsigned char *, unsigned char *,unsigned char *);
typedef int (*DILI2_SIGN)(uint8_t *, uint32_t , uint8_t *, uint8_t *, uint32_t *);
typedef int (*DILI2_VERIFY)(uint8_t *sig, size_t siglen,  uint8_t *msg, size_t mlen,  uint8_t *pk, uint8_t *verify);
typedef struct hx_dili2_
{
    void *handle;
    DILI2_KEYGEN keygenFunc;
    DILI2_SIGN signFunc;
    DILI2_VERIFY verifyFunc;
    uint8_t seed[DILI2_SEED_LEN];
    uint8_t pk[DILI2_PK_LEN];
    uint8_t sk[DILI2_SK_LEN];
    uint8_t msg[DILI2_MSG_LEN];
    uint8_t sign[DILI2_CT_LEN];
    uint8_t verify[DILI2_SS_LEN];
} hx_dili2_t;

typedef int (*FALCON_KEYGEN)(uint8_t *seed, uint8_t *pk, uint8_t *sk);
typedef int (*FALCON_SIGN)(uint8_t *msg, uint32_t msglen, uint8_t *sk, uint8_t *sign, uint32_t *signlen);
typedef int (*FALCON_VERIFY)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk, uint8_t *verify1);
typedef struct hx_falcon_
{
    void *handle;
    FALCON_KEYGEN keygenFunc;
    FALCON_SIGN signFunc;
    FALCON_VERIFY verifyFunc;
    uint8_t seed[48];
    uint8_t pk[897];
    uint8_t sk[1281];
    uint8_t msg[64];
    uint32_t msglen;
    uint8_t sign[704];
    uint8_t verify[64];
} hx_falcon_t;

int hx_open_dev( const char *dev, pthread_t *ptid);

int hx_close_dev(int fd, pthread_t *ptid);

int hx_cipher_init(hx_rpu_ctx_t *ctx);

int hx_cipher_update(hx_rpu_ctx_t *ctx, uint8_t *in, uint32_t inlen, uint8_t *out, uint8_t final, 
    hx_sess_package_e package, uint64_t pack_id);

int hx_cipher_cleanup(hx_rpu_ctx_t *ctx);

int hx_cipher_onetime(hx_rpu_ctx_t *ctx);

int hx_md_init(hx_rpu_ctx_t *ctx);

int hx_md_update(hx_rpu_ctx_t *ctx, uint8_t *in, uint32_t in_len, uint8_t *out, uint8_t final, 
    hx_sess_package_e package, uint64_t pack_id);

int hx_md_cleanup(hx_rpu_ctx_t *ctx);

int hx_md_onetime(hx_rpu_ctx_t *ctx);

int hx_rpu_md_once(hx_rpu_ctx_t *rpu_ctx);

int hx_rpu_md_package(hx_rpu_ctx_t *ctx);

int hx_rpu_cipher_once(hx_rpu_ctx_t *ctx);

int hx_rpu_cipher_stream(hx_rpu_ctx_t *ctx);

int hx_rpu_cipher_package(hx_rpu_ctx_t *ctx);

int hx_rpu_cipher(hx_rpu_ctx_t *rpu_ctx);

int hx_pub_init(hx_cipher_t *ctx);

int hx_pub_cleanup(hx_cipher_t *ctx);

int hx_pub_status(hx_cipher_t *ctx);

int hx_ioctl_pub_do(hx_cipher_t *ctx);

void *hx_poll_pthread(void *poll_thread_param);

void hx_dump_buf(char *info, uint8_t *buf, uint32_t len);

void hx_dump_data(char *info, uint8_t *buf, uint32_t len);

void hx_dump_data32(char *info, uint32_t *buf, uint32_t len);

int attach_cpu(int cpu_index);

void showTaskTid(const char *s);

#endif

