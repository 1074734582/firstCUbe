#ifndef _ALGO_H_
#define _ALGO_H_

#include <linux/init.h>
#include <linux/mutex.h>

#include "ring.h"

#define UPIF_CMD_REQ 1

#define ESRAM_DEBUG 0

#define REQUEST_TYPE_CIPHER 0
#define REQUEST_TYPE_HASH   1
#define REQUEST_TYPE_PKE    2

#define HX_USER_PKG   0
#define HX_KERNEL_PKG 1

#define PRF_MAX_SEC_LEN    128
#define PRF_MAX_KEYOUT_LEN 256

#define CIPHER_OP 0
#define HASH_OP   1
#define HMAC_OP   2
#define PRF_OP    3
#define PUB_OP    4

#define KERNEL_DATA     0
#define USER_DATA       1

//upif
#define UPIF_PKG_LEN            2048
#define MEMORY_PKG_LEN          4096

//pub
#define PUB_HEAD_LEN                16
#define PUB_DATA_LEN                16
#define PUB_MAX_PKG_NUM             256

//trng
#define TRNG_PKG_LEN            2000

//sm2
#define SM2_MESSAGE_LEN             32
#define SM2_DA_LEN                  32
#define SM2_PA_LEN                  64
#define SM2_RANDOM_LEN              32         
#define SM2_VERIFY_LEN              64
#if ESRAM_DEBUG
#define SM2_OUTPUT_LEN              96
#else
#define SM2_OUTPUT_LEN              64
#endif

#define SM2_SIGN_REQ_LEN            112 
#define SM2_SIGN_RES_LEN            80 
#define SM2_SIGN_REQ_HEAD_LEN       6
#define SM2_SIGN_RES_HEAD_LEN       4

#define SM2_VERIFY_REQ_LEN          176 
#define SM2_VERIFY_RES_LEN          32 
#define SM2_VERIFY_REQ_HEAD_LEN     10
#define SM2_VERIFY_RES_HEAD_LEN     1

#define SM2_KP_REQ_LEN              112 
#define SM2_KP_RES_LEN              80 
#define SM2_KP_REQ_HEAD_LEN         6
#define SM2_KP_RES_HEAD_LEN         4

#define SM2_KG_REQ_LEN              48 
#define SM2_KG_RES_LEN              80 
#define SM2_KG_REQ_HEAD_LEN         2
#define SM2_KG_RES_HEAD_LEN         4

#define SM2_SIGN_TRNG_REQ_LEN       80 
#define SM2_SIGN_TRNG_RES_LEN       80 
#define SM2_SIGN_TRNG_REQ_HEAD_LEN  4
#define SM2_SIGN_TRNG_RES_HEAD_LEN  4

//rsa
#define RSA_SIGN_1024_REQ_LEN              400
#define RSA_SIGN_1024_RES_LEN              144 
#define RSA_SIGN_1024_REQ_HEAD_LEN         24
#define RSA_SIGN_1024_RES_HEAD_LEN         8

#define RSA_SIGN_1024_CRT_REQ_LEN          464
#define RSA_SIGN_1024_CRT_RES_LEN          144 
#define RSA_SIGN_1024_CRT_REQ_HEAD_LEN     28
#define RSA_SIGN_1024_CRT_RES_HEAD_LEN     8

#define RSA_VERIFY_1024_REQ_LEN            400
#define RSA_VERIFY_1024_RES_LEN            144 
#define RSA_VERIFY_1024_REQ_HEAD_LEN       24
#define RSA_VERIFY_1024_RES_HEAD_LEN       8

#define RSA_SIGN_2048_REQ_LEN              784
#define RSA_SIGN_2048_RES_LEN              272
#define RSA_SIGN_2048_REQ_HEAD_LEN         48
#define RSA_SIGN_2048_RES_HEAD_LEN         16

#define RSA_SIGN_2048_CRT_REQ_LEN          912
#define RSA_SIGN_2048_CRT_RES_LEN          272
#define RSA_SIGN_2048_CRT_REQ_HEAD_LEN     56
#define RSA_SIGN_2048_CRT_RES_HEAD_LEN     16

#define RSA_VERIFY_2048_REQ_LEN            784
#define RSA_VERIFY_2048_RES_LEN            272
#define RSA_VERIFY_2048_REQ_HEAD_LEN       48
#define RSA_VERIFY_2048_RES_HEAD_LEN       16

#define RSA_1024_LEN       128
#define RSA_2048_LEN       256
#define RSA_CRT_1024_LEN   64
#define RSA_CRT_2048_LEN   128
#define RSA_OUTPUT_LEN     256

//pqc
#define PQC_HEAD_LEN                    16

#define PQC_MAGIC_NUM                0xEB90

#define PQC_KYBER512_SEED_LEN           32
#define PQC_KYBER512_PK_LEN             800
#define PQC_KYBER512_SK_LEN             1600
#define PQC_KYBER512_KEY_LEN            2400

#define PQC_KYBER512_KG_SK_OUT_LEN   (1600)
#define PQC_KYBER512_KG_PK_OUT_LEN   (800)

#define PQC_KYBER512_SIGN_IN_LEN        896
#define PQC_KYBER512_SIGN_OUT_LEN       832
#define PQC_KYBER512_VERIFY_OUT_LEN     64

#define PQC_AIGIS_KG_OUT_LEN            1792           
#define PQC_AIGIS_SIGN_OUT_LEN          832  
#define PQC_AIGIS_VERIFY_OUT_LEN        64

#define PQC_LAC_KG_PK_OUT_LEN        (576)
#define PQC_LAC_KG_SK_OUT_LEN        (1088)

#define PQC_DILI2_KG_SK_OUT_LEN      (2560)
#define PQC_DILI2_KG_PK_OUT_LEN      (1344)
#define PQC_DILI2_KG_OUT_LEN         (PQC_DILI2_KG_SK_OUT_LEN + PQC_DILI2_KG_PK_OUT_LEN)

#define PQC_DILI2_ENC_SK_IN_LEN      (2560)
#define PQC_DILI2_ENC_MSG_IN_LEN     (64)
#define PQC_DILI2_ENC_IN_LEN         (HX_PQC_DILI2_ENC_SK_IN_LEN + HX_PQC_DILI2_ENC_MSG_IN_LEN)

#define PQC_DILI2_DEC_PK_IN_LEN      (1344)
#define PQC_DILI2_DEC_MSG_IN_LEN     (64)
#define PQC_DILI2_DEC_SIGN_IN_LEN    (2432)

#define PQC_FALCON_ENC_SK_IN_LEN     (57344)
#define PQC_FALCON_ENC_SEED_IN_LEN   (64)
#define PQC_FALCON_ENC_NONCE_IN_LEN  (64)
#define PQC_FALCON_ENC_MSG_IN_LEN    (128)

#define PQC_FALCON_DEC_PK_IN_LEN     (960)
#define PQC_FALCON_DEC_SIGN_IN_LEN   (704)
#define PQC_FALCON_DEC_NONCE_IN_LEN  (128)

typedef struct request_node_s {
    int request_type;
    void *req_handle;
    void *cd_vir;
    struct request_node_s *next;
    int update_session_iv_on_send;
    int update_session_tag_on_send;

    int update_session_hash_on_send;
    int update_session_hmac_on_send;
    void *src_vir;
} request_node_t;

typedef struct session_s {
    uint32_t algo;
    uint32_t mode;
    uint32_t dir;

    uint32_t actual_src_len;
    uint32_t actual_dst_len;

    uint32_t key_len;
    uint32_t actual_key_len;
    uint8_t key[64];

    uint32_t iv_len;
    uint32_t actual_iv_len;
    uint8_t iv[32];

    uint32_t aad_len;
    uint32_t actual_aad_len;
    uint8_t aad[128];

    uint32_t tag_len;
    uint32_t actual_tag_len;
    uint32_t mid_tag_len;
    uint32_t actual_mid_tag_len;
    uint8_t mid_tag[16];
    uint8_t tag[16];

    // uint8_t hash_update[256];
    uint8_t hash_midval[256]; // sha3
    int actual_hash_mid_len;
    int hash_len_update;
    int hash_dgst_len;
    int hash_block_len;

    uint8_t hash_key[160]; //
    int hash_key_len;

    request_node_t *request_queue_head;
    request_node_t *request_queue_tail;

    struct mutex request_queue_lock;
    // spinlock_t        request_queue_spin_lock;
    uint32_t partial_ops_in_progress;
    hx_ring_handle_t *ring_handle;
    int status;
    int internal;
    uint16_t total_len;
    uint32_t total_pos;
    uint8_t split_flag;
    uint8_t pkg_mode;
    uint8_t padding;
    uint64_t pkg_count;
} session_t;

typedef struct cb_data_s {

    session_t *ctx;

    uint32_t src_len;
    void *src_virt;
    uint64_t src_phy;

    uint32_t dst_data_len;
    uint32_t dst_len;
    void *dst_virt;
    uint64_t dst_phy;

    uint32_t key_len;
    void *key_virt;
    uint64_t key_phy;

    uint32_t tag_len;

    uint64_t pkg_id;

    uint32_t pub_in_hold_len;
    void *pub_in_hold_virt;
    uint64_t pub_in_hold_phy;

    // uint32_t pub_out_hold_len;
    // void    *pub_out_hold_virt;
    // uint64_t pub_out_hold_phy;
    uint64_t user_sess;
    uint64_t user_sess_page_info;
    uint32_t user_sess_page_num;
    uint64_t user_sess_cb;
    uint64_t user_sess_cb_param;
    uint64_t user_src;
    uint64_t user_dst;
    uint32_t user_dst_page_num;
    uint64_t user_tag;
    uint32_t user_tag_page_num;

    struct page **pages;
    void *kernel_dst;
    void *vmap_dst;
    uint32_t nr_pages;
    uint32_t msg_num;
    uint32_t msg_index;
    uint32_t dst_index;

    int algo;
    int mode;
    int dir;

    int state;
    //    uint64_t efd_ctx;
    int pid;
    int sess_mode; // sync async
    int pkg_mode;
    int update_final;

    hx_ring_handle_t *ring_handle;
    int op_type;

    uint64_t jiffies_64;
    uint64_t sync_wait;
    int pkg_from;
    void *src_cookie;
    void *dst_cookie;
    void *hold_cookie;

    void *mark_pos;
    uint32_t mark_len;
    uint8_t mark_data[16];

} cb_data_t;

typedef struct hx_page_info_s {
    uint64_t addr;
    uint32_t offset;
    uint32_t size;
    void *page;
} hx_page_info_t;

int rpu_cipher(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from,
               void *src, uint32_t src_len,
               void *dst, uint32_t dst_len,
               void *key, uint32_t key_len,
               void *tag, uint32_t tag_len,
               uint64_t pkg_id, ioctl_item_t *item, void *sync_wait, uint8_t final);

int rpu_hash(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from,
             void *src, uint32_t src_len,
             void *dst, uint32_t dst_len,
             uint32_t iv_len, uint64_t pkg_id, ioctl_item_t *item,
             void *sync_wait, int hash_final);

int rpu_hmac(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from,
             void *src, uint32_t src_len,
             void *dst, uint32_t dst_len,
             uint32_t iv_len, uint64_t pkg_id, ioctl_item_t *item,
             void *sync_wait, int hash_final);

int rpu_prf(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from,
            void *src, uint32_t src_len,
            void *dst, uint32_t dst_len,
            uint32_t aad_len, uint64_t pkg_id, ioctl_item_t *item,
            void *sync_wait, int hash_final);

int rpu_pub(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from, uint32_t bus, uint32_t algo, uint32_t mode,
               void *src, uint32_t src_len, void *dst, uint32_t dst_len,
               uint64_t pkg_id, ioctl_item_t *item, void *sync_wait, uint8_t final);

int user_to_kernel(uint64_t user_virt, uint32_t len, uint32_t page_num, hx_page_info_t *k_virt);
int get_page_nums(uint64_t user_virt, uint32_t len);

ssize_t hx_performance_main(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle, ioctl_performance_test_t *algo_item);

typedef enum hx_algo_ {
    HX_ALGO_SM2 = 0,
    HX_ALGO_ECC = 1,
    HX_ALGO_RSA = 2,
    HX_ALGO_TRNG = 3,
    HX_ALGO_PQC = 4,

    HX_ALGO_SM4 = 8,
    HX_ALGO_AES = 9,
    HX_ALGO_SM3 = 10,
    HX_ALGO_SHA256 = 11,
    HX_ALGO_SHA3_256 = 12,
} hx_algo_e;

typedef enum hx_hash_mode_ {
    HASH_MODE = 0,
    GCM_J0 = 1,
    HMAC_MODE = 2,
    PRF_MODE = 3,
} hx_hash_mode_e;

typedef enum hx_aes_mode_ {
    HX_CIPHER_ECB = 0,
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

typedef enum hx_bus_type_ {
    HX_FIFO_REG_BUS = 0,
    HX_FIFO_RING_BUS = 1,
    HX_AXI_REG_BUS = 2,
    HX_AXI_RING_BUS = 3,
} hx_bus_type_e;

typedef enum hx_burst_type_ {
    HX_FIFO = 0,
    HX_MEMORY = 1,
} hx_burst_type_e;

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

typedef enum hx_trng_mode_ {
    HX_TRNG_MODE_0 = 0,
    HX_TRNG_MODE_1 = 1,
} hx_trng_mode_e;

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

enum{
    LLP_KYBER512_KEYGEN = 0,
    LLP_SPHINCS_KEYGEN,
    LLP_AIGIS_KEYGEN,
    LLP_AIGIS_ENC,
    LLP_AIGIS_DEC,
    LLP_KYBER512_ENC = 5,
    LLP_KYBER512_DEC,
    LLP_DILI2_SIGN,
    LLP_FALCON512_SIGN,
    LLP_LAC128_KEYGEN,
    LLP_MCELIECE_ENC = 10,
    LLP_BIKE1_ENC,
    LLP_SPHINCS_SIGN,
    LLP_SPHINCS_VERIFY,
    LLP_FALCON_VERIFY,
    LLP_LAC128_ENC = 15,
    LLP_HQC_KEYGEN,
    LLP_LAC128_DEC,
    LLP_DILI2_KEYGEN,
    LLP_MCELIECE_DEC,
    LLP_HQC_ENC = 20,
    LLP_DILI2_VERIFY,
    LLP_BIKE1_DEC,
    LLP_DILI2_SIGN_SW,
    LLP_HQC_DEC,
};

typedef enum hx_cipher_encrypt_ {
    HX_CIPHER_ENCRYPT,
    HX_CIPHER_DECRYPT,
} hx_cipher_encrypt_e;

typedef enum hx_package_type_ {
    HX_PACKAGE_START = 1,
    HX_PACKAGE_MIDDLE = 2,
    HX_PACKAGE_END = 4,
    HX_PACKAGE_COMPLETE = 5,
} hx_package_type_e;

typedef enum hx_sess_mode_ {
    HX_SYNC_MODE,
    HX_ASYNC_POLLING_MODE,
    HX_ASYNC_CALLBACK_MODE,
} hx_sess_mode_e;

#endif //_ALGO_H_
