#ifndef _COMMON_H_
#define _COMMON_H_
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/jiffies.h>

#include "algo.h"
#include "reg.h"

#define PCIE_ENABLE 1

#define CPA_LOG_PRINTF_SEL  CPA_LOG_LEVEL_INFO
#define CPA_LOG_LEVEL_DUMP  0
#define CPA_LOG_LEVEL_DEBUG 1
#define CPA_LOG_LEVEL_INFO  2
#define CPA_LOG_LEVEL_WARN  3
#define CPA_LOG_LEVEL_ERROR 4

extern int cpa_log_level;
extern char *log_prefix[5];

#define LOG_PRINT(level, format, args...)          \
    if (level >= cpa_log_level) {                  \
        printk(KERN_CONT "%s", log_prefix[level]); \
        printk(KERN_CONT format, ##args);          \
    }

#define LOG_DUMP(format, args...)  LOG_PRINT(CPA_LOG_LEVEL_DUMP, format, ##args)
#define LOG_DEBUG(format, args...) LOG_PRINT(CPA_LOG_LEVEL_DEBUG, format, ##args)
#define LOG_INFO(format, args...)  LOG_PRINT(CPA_LOG_LEVEL_INFO, format, ##args)
#define LOG_WARN(format, args...)  LOG_PRINT(CPA_LOG_LEVEL_WARN, format, ##args)
#define LOG_ERROR(format, args...) LOG_PRINT(CPA_LOG_LEVEL_ERROR, format, ##args)

void dump_buf(char *info, uint8_t *buf, uint32_t len);
void data_dump(const unsigned char *data, unsigned int data_len);
void xor_calculate(uint8_t *output, uint8_t *input1, uint8_t *input2, uint8_t len);

typedef enum hx_ret_code_ {
    HX_RET_SUCCESS = 0,
    HX_RET_FAILED = -1,
    HX_RET_NO_DEVICE = -2,
    HX_RET_DEVICE_BUSY = -3,
    HX_RET_NO_MEM = -4,
    HX_RET_ARG_ADDR_ERROR = -5,
    HX_RET_ARG_CMD_ERROR = -6,
    HX_RET_CTX_ERROR = -7,
    HX_RET_PARAM_ERROR = -8,
    HX_RET_LEN_ERROR = -10,
    HX_RET_KEY_ERROR = -11,

    HX_RET_TIMEOUT = -12,

    HX_RET_UNSUPPORT_ALGO = -13,
    HX_RET_NO_DEV_RIGHT = -14,
    HX_RET_NO_KEY_RIGHT = -15,

    HX_INVALID_PACKET = -16,
} hx_ret_code_t;

struct cipher_req_st {
    // WORD 0
    uint8_t resrvd0;
    uint8_t service_cmd_id;
    uint8_t service_type;
    uint8_t hdr_flags;
    // WORD 1
    uint16_t resrvd1;
    uint8_t key_length;
    uint8_t iv_length;
    // WORD 2
    uint8_t resrvd2;
    uint8_t padding;
    uint8_t resrvd4;
    uint8_t tag_lenth;
    // WORD 3-4
    uint32_t opaque_data_l;
    uint32_t opaque_data_h;
    // WORD 5-6
    uint32_t src_addr_l;
    uint32_t src_addr_h;
    // WORD 7-8
    uint32_t dst_addr_l;
    uint32_t dst_addr_h;
    // WORD 9
    uint32_t src_len;
    // WORD 10
    uint32_t dst_len;
    // WORD 11
    uint32_t total_len;
    // WORD 12-13
    uint32_t res_addr_l;
    uint32_t res_addr_h;
    // WORD 14-15
    uint32_t aad_lenth;
    uint32_t cur_pkg_byte_pos;
} __attribute__((packed));

struct cipher_resp_st {
    // WORD 0
    uint8_t resrvd0;
    uint8_t service_cmd_id;
    uint8_t service_type;
    uint8_t hdr_flags;
    // WORD 1-2
    uint16_t resrvd1;
    uint8_t resrvd2;
    uint8_t resrvd3;
    uint32_t resrvd4;
    // WORD 3-4
    uint32_t operate_data_l;
    uint32_t operate_data_h;
    // WORD 5-6
    uint32_t dst_addr_l;
    uint32_t dst_addr_h;
    // WORD 7
    uint32_t dst_len;
} __attribute__((packed));

struct pub_head_st {
    // WORD 0
    uint32_t soft_id;
    // WORD 1
    uint32_t operate_data_l;
    // WORD 2
    uint32_t operate_data_h;
    // WORD 3
    uint8_t resrvd1;
    uint8_t dest_length;
    uint8_t src_length;
    uint8_t mode:3;
    uint8_t func_id:2;
    uint8_t service_type:1;
    uint8_t direction:1;
    uint8_t hdr_flags:1;
} __attribute__((packed));

struct sm2_sign_st {
    struct pub_head_st head;
    uint8_t message[32];
    uint8_t da[32];
    uint8_t random[32];
} __attribute__((packed));

struct sm2_verify_st {
    struct pub_head_st head;
    uint8_t message[32];
    uint8_t pa[64];
    uint8_t verify[64];
} __attribute__((packed));

struct sm2_kp_st {
    struct pub_head_st head;
    uint8_t da[32];
    uint8_t pa[64];
} __attribute__((packed));

struct sm2_kg_st {
    struct pub_head_st head;
    uint8_t da[32];
} __attribute__((packed));

struct sm2_sign_trng_st {
    struct pub_head_st head;
    uint8_t message[32];
    uint8_t da[32];
} __attribute__((packed));

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
    uint8_t output[SM2_OUTPUT_LEN];
} hx_sm2_output_t;

typedef struct hx_sm2_result_
{
    uint32_t size;
    uint64_t addr;
    uint32_t index;
    hx_sm2_output_t data[];
} hx_sm2_result_t;

struct rsa_sign_1024_st {
    struct pub_head_st head;
    uint8_t message[128];
    uint8_t d[128];
    uint8_t N[128];
} __attribute__((packed));

struct rsa_sign_1024_crt_st {
    struct pub_head_st head;
    uint8_t message[128];
    uint8_t dp[64];
    uint8_t dq[64];
    uint8_t p[64];
    uint8_t q[64];
    uint8_t qinv[64];
} __attribute__((packed));

struct rsa_verify_1024_st {
    struct pub_head_st head;
    uint8_t message[128];
    uint8_t e[128];
    uint8_t N[128];
} __attribute__((packed));

struct rsa_sign_2048_st {
    struct pub_head_st head;
    uint8_t message[256];
    uint8_t d[256];
    uint8_t N[256];
} __attribute__((packed));

struct rsa_sign_2048_crt_st {
    struct pub_head_st head;
    uint8_t message[256];
    uint8_t dp[128];
    uint8_t dq[128];
    uint8_t p[128];
    uint8_t q[128];
    uint8_t qinv[128];
} __attribute__((packed));

struct rsa_verify_2048_st {
    struct pub_head_st head;
    uint8_t message[256];
    uint8_t e[256];
    uint8_t N[256];
} __attribute__((packed));

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
    uint8_t output[RSA_OUTPUT_LEN];
} hx_rsa_output_t;

typedef struct hx_rsa_result_
{
    uint32_t size;
    uint64_t addr;
    uint32_t index;
    hx_rsa_output_t data[];
} hx_rsa_result_t;

struct pqc_config_st {
    // WORD 0-1
    uint16_t head;
    uint8_t src_length[3];
    uint8_t dst_length[3];
    // WORD 2
    uint8_t direction:1;        
	uint8_t pkg_mode:2;       
	uint8_t reserve0:5;
    uint8_t reserve1[3];
    // WORD 3
    uint32_t dst_address;
} __attribute__((packed));

struct pqc_request_st {
    // WORD 0-1
    uint16_t head;
    uint8_t src_length[3];
    uint8_t dst_length[3];
    // WORD 2
    uint8_t direction:1;        
	uint8_t pkg_mode:2;
    uint8_t dp_bank_en:1;
    uint8_t variable_en:1; 
	uint8_t reserve0:3;
    uint16_t pkg_number;
    uint8_t algo_id;
    // WORD 3
    uint32_t mlen;
} __attribute__((packed));

typedef struct hx_kyber512_kg_req_
{
    uint8_t input[64];
} hx_kyber512_kg_req_t;

typedef struct hx_kyber512_kg_res_
{
    uint8_t output[2400];
} hx_kyber512_kg_res_t;

typedef struct hx_kyber512_enc_req_
{
    uint8_t input[896];
} hx_kyber512_enc_req_t;

typedef struct hx_kyber512_enc_res_
{
    uint8_t output[832];
} hx_kyber512_enc_res_t;

struct upif_cmd_resp_st {
    uint64_t command;
    uint32_t response;
    uint16_t pkg_size:12;
    uint16_t resrvd0:4;
    uint16_t pkg_num:12;
    uint16_t resrvd1:4;
} __attribute__((packed));

typedef struct param_s {
    uint64_t len;
    uint64_t phy;
} __attribute__((packed)) param_t;
typedef struct hx_wait_s {
    wait_queue_head_t wq;
    int condition;
    int state;
} hx_wait_t;

// sync to fw
struct sec_zone_data {
    uint8_t mode; // safe or unsafe
    uint8_t login_user_cnt;
    uint32_t init_status;
    struct priv_right {
        uint8_t key;
        uint8_t right;
    } right[0];
} __attribute__((packed));

#define hx_cpu_to_be32(v) ((((v) >> 24) & 0x000000FF) | (((v) >> 8) & 0x0000ff00) | (((v) << 8) & 0x00ff0000) | ((v) << 24 & 0xFF000000))
#define hx_cpu_to_be16(v) ((((v) >> 8) & 0x00FF) | (((v) << 8) & 0xff00))
#define hx_cpu_to_le32(v) (v)
#define hx_cpu_to_le64(v) (v)

int build_cipher_req_msg(struct cipher_req_st *req,
                         uint64_t src_phy, uint32_t src_len,
                         uint64_t dst_phy, uint32_t dst_len,
                         uint32_t key_len, uint32_t iv_len,
                         uint32_t add_len, uint32_t tag_len, uint32_t total_src_len,
                         void *cb, uint8_t algo_id, uint8_t mode, uint8_t dir, uint8_t padding, uint32_t pkg_pos, uint32_t partial);

int build_hash_req_msg(struct cipher_req_st *req,
                       uint64_t src_phy, uint32_t src_len,
                       uint64_t dst_phy, uint32_t dst_len,
                       uint32_t key_len, uint32_t iv_len, uint32_t aad_len, uint32_t total_src_len,
                       void *cb, uint8_t algo_id, uint8_t hash_mode, uint8_t padding, uint32_t partial);

int build_prf_req_msg(struct cipher_req_st *req,
                      uint64_t src_phy, uint32_t src_len,
                      uint64_t dst_phy, uint32_t dst_len,
                      uint64_t cd_phy, void *cd_vir,
                      uint8_t algo, void *cb, uint32_t kek, uint32_t key_index);

int build_pub_head_msg(struct pub_head_st *head, uint8_t service_type, uint8_t func_id, uint8_t mode, 
                        uint8_t src_length, uint8_t dest_length, uint32_t soft_id, uint64_t opaque_data);

int build_pub_sm2_msg(void *req_addr, uint8_t func_id, uint8_t sm2_mode, uint32_t soft_id, uint64_t opaque_data, 
                    uint8_t *message, uint8_t *da, uint8_t *pa, uint8_t* verify, uint8_t *random);

int build_pub_rsa_msg(void *req_addr, uint8_t rsa_mode, uint32_t soft_id, uint64_t opaque_data, uint8_t *message, 
                    uint8_t *d, uint8_t *e, uint8_t *N, uint8_t *dp, uint8_t *dq, uint8_t *p, uint8_t *q, 
                    uint8_t *qinv);

int build_pub_request(hx_ring_handle_t *ring_handle, void *cb, uint32_t algo, uint32_t mode, 
                    uint64_t src, uint32_t src_len, uint64_t dst, uint32_t dst_len);

int build_trng_request(hx_ring_handle_t *ring_handle, void *cb, uint32_t dst_len);

int build_pqc_request(hx_ring_handle_t *ring_handle, void *cb, uint8_t bus, uint32_t mode, 
                    uint64_t src, uint32_t src_len, uint64_t dst, uint32_t dst_len);

void upif_axi_cmd_set(void *base, unsigned char rw_burst, unsigned char rw_mode, unsigned int dut_addr, unsigned int pkg_num, 
                        unsigned int pkg_size, unsigned char rd_mode);

void  upif_fifo_cmd_set(void *base, unsigned int pkg_num, unsigned int write_pkg_size, unsigned int read_pkg_size);

void pqc_fifo_cmd_set(void *base, unsigned int write_pkg_num, unsigned int write_pkg_size, 
                        unsigned int read_pkg_num, unsigned int read_pkg_size);

void upif_fifo_write(void *base, uint32_t *para_ptr, int para_size);

void upif_axi_ring_request(ring_handle_t *ring, void *base, int64_t req_phy_addr, 
                            unsigned char rw_burst, unsigned char rw_mode, unsigned int dut_addr, 
                            unsigned int pkg_num, unsigned int pkg_size, unsigned char rd_mode);

void upif_axi_ring_send(ring_handle_t *ring, void *base, uint32_t addr, uint8_t *data, uint32_t data_len);

int get_sm2_req_len(uint8_t sm2_mode);
int get_sm2_res_len(uint8_t sm2_mode);
int get_sm2_max_msg_num(uint8_t sm2_mode);
int get_rsa_req_len(uint8_t rsa_mode);
int get_rsa_res_len(uint8_t rsa_mode);
int get_rsa_max_msg_num(uint8_t rsa_mode);
int get_pub_req_len(uint8_t algo, uint8_t mode);
int get_pub_res_len(uint8_t algo, uint8_t mode);
int get_pub_max_msg_num(uint8_t algo, uint8_t mode);
int get_pqc_req_len(uint8_t pqc_mode);
int get_pqc_res_len(uint8_t pqc_mode);
int get_pqc_mem_out_address(uint8_t pqc_mode);
uint8_t get_pqc_request_algo_id(uint8_t pqc_mode);

int build_pqc_config_msg(struct pqc_config_st *config, uint32_t src_length, uint32_t dst_address);
int build_pqc_request_msg(struct pqc_request_st *config, uint32_t src_length, uint32_t dst_length,
                        uint8_t bank_mode, uint8_t len_mode, uint16_t pkg_num, uint8_t algo_id, uint32_t real_len);
int pqc_fifo_send(void *base, uint8_t *data, uint32_t data_len);
int pqc_axi_fifo_send(void *base, uint32_t addr, uint8_t *data, uint32_t data_len);
int pqc_fifo_request_send(ring_handle_t *ring, void *base, uint8_t user_space, uint8_t *data, uint32_t data_len);
int pqc_axi_mem_send(ring_handle_t *ring, void *base, uint32_t addr, uint8_t *data, uint32_t data_len);
int pqc_fifo_read_cmd_send(void *base, uint32_t read_len);
int init_pqc_data(ring_handle_t *ring, void *base, uint8_t bus, uint8_t mode, uint8_t *const_data, uint32_t const_len, 
                    uint8_t *task_data, uint32_t task_len);
int pqc_config_data_init(ring_handle_t *ring, void *base, uint8_t bus, uint8_t mode);
int pqc_fifo_response_transmit(ring_handle_t *ring, void *base, uint32_t dst_len);
int pqc_fifo_request_transmit(ring_handle_t *ring, void *base, uint8_t mode, uint8_t src_space, uint64_t src, uint32_t src_len, uint32_t dst_len);
int pqc_fifo_write_send(void *base, uint8_t *src_data, uint32_t src_length, uint32_t dst_length);
int pqc_axi_fifo_start(void *base);
int pqc_axi_mem_start(ring_handle_t *ring, void *base);
int pqc_axi_reset(ring_handle_t *ring, void *base);

void data_swap(unsigned char *buff, int len);
int hash_padding(uint8_t *data, int data_size, int block_size, int total_len);
void init_id(void);
uint64_t get_id(void);
void *get_opdata_from_req(void *req, int ring_type);
void *get_opdata_from_resp(struct pub_head_st *head);
void hx_ctx_dup_ctx(void *ctx_t, void *ctx_f);
uint8_t *hx_get_init(int algo);
uint8_t hx_get_init_len(int algo);

int hx_init_cipher_ctx(void *ctx, uint32_t algo, uint32_t mode, uint32_t dir, int force_update, int pkg_from, int pkg_mode,
                       uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *tag, uint32_t tag_len, uint32_t total_len);
int hx_init_hash_ctx(void *ctx, uint32_t algo, uint32_t pkg_mode, uint8_t *key, uint32_t key_len, uint8_t padding);
int hx_init_prf_ctx(void *ctx, uint32_t algo, uint32_t mode, uint32_t dir,
                    uint8_t *seed, uint32_t seed_len);

int hx_get_dgst_len(uint32_t algo);
int hx_get_block_len(uint32_t algo);
int hx_get_hmac_len(uint32_t algo);

int build_cipher_src_data(void *ctx, uint8_t *src_vir, uint8_t *src, uint32_t src_len);
int build_hash_src_data(void *ctx, uint8_t *src_vir, uint8_t *src, uint32_t src_len);
int build_hmac_src_data(void *ctx, uint8_t *src_vir, uint8_t *src, uint32_t src_len);
int build_prf_src_data(void *ctx, uint8_t *src_vir, uint8_t *src, uint32_t src_len);

void *hx_dma_alloc_consistent(void *pdev, size_t size, dma_addr_t *dma_handle);
void hx_dma_free_consistent(void *pdev, size_t size, void *cpu_addr, dma_addr_t dma_addr);
int hx_copy_from(void *dst, void *src, int len, int type);

#define __wait_condition_timeout(condition, ret)           \
    do {                                                   \
        for (;;) {                                         \
            if (condition)                                 \
                break;                                     \
            if (ret <= 0)                                  \
                break;                                     \
            ret--;                                         \
            usleep_range(50, 50); /*schedule_timeout(1);*/ \
        }                                                  \
    } while (0)

#define wait_condition_timeout(condition, timeout)      \
    ({                                                  \
        long __ret = 20000;                             \
        if (!(condition))                               \
            __wait_condition_timeout(condition, __ret); \
        __ret;                                          \
    })

#endif //_COMMON_H_
