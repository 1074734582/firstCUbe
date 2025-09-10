#ifndef __IOCTL_CMDS_H__
#define __IOCTL_CMDS_H__

#ifndef __KERNEL__
#include <stdint.h>
#include <sys/ioctl.h>
#else
#include <linux/ioctl.h>
#endif

#define HX_MAX_POLL_ITEMS 512

typedef struct ioctl_item_ {
    int state;
    int pid;
    int mode;
    uint64_t pack_id;
    uint64_t sess;
    uint64_t cb;
    uint64_t cb_param;
} ioctl_item_t;

typedef struct ioctl_param_s {
    uint64_t ctx; // ctx ptr alloc in drv
    uint32_t len;
    uint64_t data;
    uint32_t key_len;
    uint32_t iv_len;
    uint32_t aad_len;
    uint64_t key;
    uint64_t iv;
    uint64_t aad;

    uint32_t algo;
    uint32_t mode;
    uint32_t dir;
    uint32_t kek;
    uint32_t key_index;
    uint32_t endian;
    uint32_t bus;

    uint64_t src;
    uint32_t src_len;
    uint64_t dst;
    uint32_t dst_len;
    uint64_t tag;
    uint32_t tag_len;
    int force_update;
    uint8_t split_flag;
    uint16_t total_len;
    uint8_t final;
    uint8_t pkg_mode;
    uint8_t padding;

    ioctl_item_t item;
} __attribute__((packed)) ioctl_param_t;

typedef struct poll_param_s {
    int pid;
    uint64_t item_addr;
} __attribute__((packed)) poll_param_t;

typedef struct dev_name_s {
    uint8_t dev_name[128];
    int id;
} dev_name_t;

typedef struct firmware_info_s {
    uint64_t data;
    uint32_t len;
    uint32_t devnum;
} firmware_info_t;

typedef struct gen_key_param_s {
    uint8_t algo;
    uint8_t endian;
    uint8_t *dst;
    uint32_t dst_len;
    uint32_t kek;
    uint32_t key_index;
    ioctl_item_t item;
} __attribute__((packed)) gen_key_param_t;

typedef struct ring_info_ {
    uint32_t ring_id;
    uint32_t size;
    uint32_t in_flight;
    uint64_t enq;
    uint64_t deq;
    uint64_t enq_size;
    uint64_t deq_size;
} ring_info_t;
typedef struct ioctl_ring_info_ {
    uint8_t dev_name[128];
    uint32_t rpu_ring_num;
    uint32_t bulk_ring_num;
    uint32_t pub_ring_num;
    uint64_t rpu_addr;
    uint64_t bulk_addr;
    uint64_t pub_addr;
} ioctl_ring_info_t;

typedef struct ioctl_dev_info_ {
    int dev_num;
    uint64_t dev_name_addr; // dev_name_t
} ioctl_dev_info_t;

typedef struct ioctl_common_ {
    char dev_name[128];
    uint32_t size;
    uint64_t user_addr;
} ioctl_common_t;

typedef struct ioctl_reg_s {
    char dev_name[128];
    uint32_t bar;
    uint32_t addr;
    uint32_t num;
    uint64_t data;
} ioctl_reg_t;

typedef struct ioctl_performance_test_s {
    unsigned char algo_id;
    unsigned char alg_mode;
    unsigned char algo_dir;
    int srclen;
    int dstlen;
    int keylen;
    int ivlen;
    int taglen;
    int rcu;
    int packet_num;
    int packet_len;
    unsigned long used_time_us;
    unsigned long per_khz;
} __attribute__((packed)) ioctl_performance_test_t;

#define IOCTL_MAGIC 0x95

#define HX_OPEN_DEV      111
#define HX_CTX_ALLOC     1
#define HX_CTX_INIT      2
#define HX_CTX_SET_IV    3
#define HX_CTX_SET_KEY   4
#define HX_CTX_SET_AAD   5
#define HX_CTX_FREE      6
#define HX_CIPHER_OP     11
#define HX_HASH_OP       12
#define HX_RPU_HASH_OP   13
#define HX_HMAC_OP       14
#define HX_CTX_DUP       15
#define HX_PRF_OP        16
#define HX_CIPHER_STATUS 17
#define HX_SM2_OP        18
#define HX_RSA_OP        19

#define HX_POLLING     51
#define HX_POLLING_ALL 52

#define HX_RING_USING_MON 101

#define HX_GET_ALL_DEV_NUM    201
#define HX_GET_ALL_DEV_INFO   202
#define HX_GET_BDF_BY_NAME    203
#define HX_GET_DEV_CAP        204
#define HX_GET_VF_NUM_BY_NAME 205

#define HX_REG_READ_N  301
#define HX_REG_WRITE_N 302

#define HX_RING_CONFIG      400
#define HX_CMDQ_REG_READ    406
#define HX_CMDQ_REG_WRITE   407
#define HX_PERFORMANCE_INFO 408

#define IOCTL_OPEN_DEV    _IOWR(IOCTL_MAGIC, HX_OPEN_DEV, dev_name_t)
#define IOCTL_CTX_ALLOC   _IOWR(IOCTL_MAGIC, HX_CTX_ALLOC, ioctl_param_t)
#define IOCTL_CTX_FREE    _IOWR(IOCTL_MAGIC, HX_CTX_FREE, ioctl_param_t)
#define IOCTL_CTX_INIT    _IOWR(IOCTL_MAGIC, HX_CTX_INIT, ioctl_param_t)
#define IOCTL_CTX_SET_IV  _IOWR(IOCTL_MAGIC, HX_CTX_SET_IV, ioctl_param_t)
#define IOCTL_CTX_SET_KEY _IOWR(IOCTL_MAGIC, HX_CTX_SET_KEY, ioctl_param_t)
#define IOCTL_CIPHER_OP   _IOWR(IOCTL_MAGIC, HX_CIPHER_OP, ioctl_param_t)
#define IOCTL_HASH_OP     _IOWR(IOCTL_MAGIC, HX_HASH_OP, ioctl_param_t)
#define IOCTL_HMAC_OP     _IOWR(IOCTL_MAGIC, HX_HMAC_OP, ioctl_param_t)
#define IOCTL_PRF_OP      _IOWR(IOCTL_MAGIC, HX_PRF_OP, ioctl_param_t)
#define IOCTL_PUB_OP      _IOWR(IOCTL_MAGIC, HX_SM2_OP, ioctl_param_t)

#define IOCTL_POLLING       _IOWR(IOCTL_MAGIC, HX_POLLING, poll_param_t)
#define IOCTL_POLLING_ALL   _IOWR(IOCTL_MAGIC, HX_POLLING_ALL, poll_param_t)
#define IOCTL_CTX_DUP       _IOWR(IOCTL_MAGIC, HX_CTX_DUP, ioctl_param_t)
#define IOCTL_CIPHER_STATUS _IOWR(IOCTL_MAGIC, HX_CIPHER_STATUS, ioctl_param_t)

#define IOCTL_RING_USING_MON _IOWR(IOCTL_MAGIC, HX_RING_USING_MON, ioctl_ring_info_t)

#define IOCTL_GET_ALL_DEV_NUM  _IOWR(IOCTL_MAGIC, HX_GET_ALL_DEV_NUM, ioctl_dev_info_t)
#define IOCTL_GET_ALL_DEV_INFO _IOWR(IOCTL_MAGIC, HX_GET_ALL_DEV_INFO, ioctl_dev_info_t)
#define IOCTL_GET_BDF_BY_NAME  _IOWR(IOCTL_MAGIC, HX_GET_BDF_BY_NAME, dev_name_t)
#define IOCTL_REG_READ         _IOWR(IOCTL_MAGIC, HX_REG_READ_N, ioctl_reg_t)
#define IOCTL_REG_WRITE        _IOWR(IOCTL_MAGIC, HX_REG_WRITE_N, ioctl_reg_t)

#define IOCTL_RING_CONFIG    _IOWR(IOCTL_MAGIC, HX_RING_CONFIG, ioctl_cmdq_set_algo_t)
#define IOCTL_CMDQ_REG_WRITE _IOWR(IOCTL_MAGIC, HX_CMDQ_REG_WRITE, ioctl_reg_t)
#define IOCTL_CMDQ_REG_READ  _IOWR(IOCTL_MAGIC, HX_CMDQ_REG_READ, ioctl_reg_t)

#define IOCTL_PERGORMANCE_HARDWARE _IOWR(IOCTL_MAGIC, HX_PERFORMANCE_INFO, ioctl_performance_test_t)

typedef struct basic_ioctl_param_s {
    uint8_t dev_name[128];
    int bar;
    uint32_t reg_addr;
    uint32_t *reg_data;
    uint32_t reg_num;

    uint64_t ddr_virt;
    uint64_t ddr_phy;
    uint32_t ddr_size;
} basic_ioctl_param_t;

typedef enum hx_thread_bind_ {
    HX_SEND_BIND = 0,
    HX_QUEUE_BIND = 1,
    HX_POLL_BIND = 2,
} hx_thread_bind_e;

#endif
