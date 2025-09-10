#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "common.h"
#include "debug.h"
#include "pqcdata/pqc_data.h"

int cpa_log_level = CPA_LOG_PRINTF_SEL;
char *log_prefix[5] = {"", "[DEBUG] :", "[INFO] :", "[WARN] :", "[ERROR] :"};
void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    int i = 0;
    if (cpa_log_level > CPA_LOG_LEVEL_DUMP)
        return;
    LOG_DUMP("%s  %d ", info, len);
    for (i = 0; i < len; i++) {
        //  if(i % 16 == 0 )
        //      LOG_DUMP("\n 0x%08x :",i);
        LOG_DUMP("%s%02X%s", i % 16 == 0 ? "\n     " : " ",
                 buf[i], i == len - 1 ? "\n" : "");
    }
}

void data_dump(const unsigned char *data, unsigned int data_len)
{
    int i;
    for (i = 0; i < data_len; i++) {
        pr_cont("0x%02X ", data[i]);
        if (((i + 1) % 16) == 0)
            pr_cont("\n");
    }
    pr_cont("\n");
}

void xor_calculate(uint8_t *output, uint8_t *input1, uint8_t *input2, uint8_t len)
{
    for (int i = 0; i < len; i++) {
        output[i] = input1[i] ^ input2[i];
    }
}

atomic64_t pkg_id;
void init_id(void)
{
    atomic64_set(&pkg_id, 0);
}
uint64_t get_id(void)
{
    return atomic64_inc_return(&pkg_id);
}

void *get_opdata_from_req(void *req, int ring_type)
{
    cb_data_t *cb_data = NULL;
    struct cipher_req_st *cipher_req = req;

    cb_data = (cb_data_t *)((uint64_t)(cipher_req->opaque_data_h) << 32 | cipher_req->opaque_data_l);
    return cb_data;
}

void *get_opdata_from_resp(struct pub_head_st *head)
{
    cb_data_t *cb_data = NULL;

    cb_data = (cb_data_t *)((uint64_t)(head->operate_data_h) << 32 | head->operate_data_l);
    return cb_data;
}

int build_cipher_req_msg(struct cipher_req_st *req,
                         uint64_t src_phy, uint32_t src_len,
                         uint64_t dst_phy, uint32_t dst_len,
                         uint32_t key_len, uint32_t iv_len,
                         uint32_t add_len, uint32_t tag_len, uint32_t total_src_len,
                         void *cb, uint8_t algo_id, uint8_t mode, uint8_t dir, uint8_t padding, uint32_t pkg_pos, uint32_t partial)
{
    int ret = 0;

    req->service_cmd_id = algo_id;
    req->service_type = ((dir << 7) | mode);
    req->hdr_flags = 0x80;
    req->key_length = key_len;
    req->iv_length = iv_len;
    req->padding = partial;

    if (mode == HX_CIPHER_CCM || mode == HX_CIPHER_GCM) {
        req->tag_lenth = tag_len;
        req->aad_lenth = add_len;
        req->cur_pkg_byte_pos = pkg_pos;
    }

    req->opaque_data_l = (uint32_t)((uint64_t)cb);
    req->opaque_data_h = (uint32_t)((uint64_t)cb >> 32);

    req->src_addr_l = (uint32_t)((uint64_t)src_phy);
    req->src_addr_h = (uint32_t)((uint64_t)src_phy >> 32);

    req->dst_addr_l = (uint32_t)((uint64_t)dst_phy);
    req->dst_addr_h = (uint32_t)((uint64_t)dst_phy >> 32);

    req->src_len = src_len;

    if (mode == HX_CIPHER_CCM || mode == HX_CIPHER_GCM || (mode == HX_CIPHER_XTS && (partial == HX_PACKAGE_START || partial == HX_PACKAGE_MIDDLE)))
        dst_len = dst_len + 16;

    req->dst_len = dst_len;
    req->total_len = total_src_len;

    LOG_DEBUG("req->service_cmd_id = %d\n", req->service_cmd_id);
    LOG_DEBUG("req->service_type = %d\n", req->service_type);
    LOG_DEBUG("req->hdr_flags = %d\n", req->hdr_flags);
    LOG_DEBUG("req->key_length = %d\n", req->key_length);
    LOG_DEBUG("req->iv_length = %d\n", req->iv_length);
    LOG_DEBUG("req->padding = %d\n", req->padding);
    LOG_DEBUG("req->tag_lenth = %d\n", req->tag_lenth);
    LOG_DEBUG("req->aad_lenth = %d\n", req->aad_lenth);
    LOG_DEBUG("req->cur_pkg_byte_pos = %d\n", req->cur_pkg_byte_pos);
    LOG_DEBUG("req->src_len = %d\n", req->src_len);
    LOG_DEBUG("req->dst_len = %d\n", req->dst_len);
    LOG_DEBUG("req->total_len = %d\n", req->total_len);

    return ret;
}

int build_hash_req_msg(struct cipher_req_st *req,
                       uint64_t src_phy, uint32_t src_len,
                       uint64_t dst_phy, uint32_t dst_len,
                       uint32_t key_len, uint32_t iv_len, uint32_t aad_len, uint32_t total_src_len,
                       void *cb, uint8_t algo_id, uint8_t hash_mode, uint8_t padding, uint32_t partial)
{
    int ret = 0;

    req->service_cmd_id = algo_id;
    req->hdr_flags = 0x80;
    req->key_length = key_len;
    req->iv_length = iv_len;

    req->padding = (padding << 7 | hash_mode << 3 | partial << 0); // hash

    req->src_addr_l = (uint32_t)((u64)src_phy);
    req->src_addr_h = (uint32_t)((u64)src_phy >> 32);

    req->dst_addr_l = (uint32_t)((u64)dst_phy);
    req->dst_addr_h = (uint32_t)((u64)dst_phy >> 32);

    req->src_len = src_len;
    req->dst_len = dst_len;
    req->aad_lenth = aad_len;
    req->total_len = total_src_len;

    req->opaque_data_l = (uint32_t)((uint64_t)cb & 0xFFFFFFFF);
    req->opaque_data_h = (uint32_t)(((uint64_t)cb >> 32) & 0xFFFFFFFF);

    return ret;
}

void upif_axi_cmd_set(void *base, unsigned char rw_burst, unsigned char rw_mode, unsigned int dut_addr, unsigned int pkg_num, 
                        unsigned int pkg_size, unsigned char rd_mode)
{
    int wdata, data_cnt, data_len;
    unsigned int high_addr, low_addr, offset_addr;
    static unsigned char rd_cmd_id = 0;

    //word0 cmd1  
    wdata = 1 |(rw_mode<<1)|(rw_burst<<2)|(rd_mode<<3)|(rd_cmd_id<<4)|(pkg_size<<8)|(pkg_num<<20);
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x00, wdata);

    //word1, cmd2
    wdata = dut_addr;
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x04, wdata);

    //word2
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x08, 0x00);

    //word3
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x0c, 0x00);

    if(!rw_mode)
        rd_cmd_id = (rd_cmd_id + 1) % 16;
}

void upif_fifo_cmd_set(void *base, unsigned int pkg_num, unsigned int write_pkg_size, unsigned int read_pkg_size)
{
    int wdata;
    
    //word0 cmd1
    wdata = 0 |(1<<1)|(0<<2)|(0<<3)|(0xf<<4)|(write_pkg_size<<8)|(pkg_num<<20);
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x00, wdata);

    //word1, cmd2
    wdata = (read_pkg_size<<0)|(pkg_num<<12);
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x04, wdata);

    //word2
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x08, 0x00);

    //word3
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x0c, 0x00);
}

void pqc_fifo_cmd_set(void *base, unsigned int write_pkg_num, unsigned int write_pkg_size, 
                        unsigned int read_pkg_num, unsigned int read_pkg_size)
{
    int wdata;
    
    //word0 cmd1
    wdata = 0 |(1<<1)|(0<<2)|(1<<3)|(write_pkg_size<<8)|(write_pkg_num<<20);
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x00, wdata);

    //word1, cmd2
    wdata = (read_pkg_size<<0)|(read_pkg_num<<12);
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x04, wdata);

    //word2
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x08, 0x00);

    //word3
    HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x0c, 0x00);
}

void upif_fifo_write(void *base, uint32_t *para_ptr, int para_size)
{
    int i = 0;
    while(i<(para_size/4))
    {  
        HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x00, *(para_ptr+i));
        HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x04, *(para_ptr+i+1));
        HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x08, *(para_ptr+i+2));
        HX_REG_WRITE(base + UPIF_IFIFO_ADDR + 0x0c, *(para_ptr+i+3));
        i=i+4;
    }
}

void upif_axi_ring_request(ring_handle_t *ring, void *base, int64_t req_phy_addr, 
                            unsigned char rw_burst, unsigned char rw_mode, unsigned int dut_addr, 
                            unsigned int pkg_num, unsigned int pkg_size, unsigned char rd_mode)
{
    uint8_t *cmd_req_addr = (uint8_t *)(ring->ring_cmd_req_queue_virt_addr + ring->cmd_req_size*ring->cmd_req_tail);
    int *cmd_req = (int *)cmd_req_addr;

    //word0 
    *cmd_req = 1 |(rw_mode<<1)|(rw_burst<<2)|(rd_mode<<3)|(ring->rd_cmd_id<<4)|(pkg_size<<8)|(pkg_num<<20);
    cmd_req++;

    //word1
    *cmd_req = dut_addr;
    cmd_req++;

    //word2
    *cmd_req = req_phy_addr & 0xFFFFFFFF;
    cmd_req++;

    //word3
    *cmd_req = (req_phy_addr >> 32) & 0xFFFFFFFF;

    if(!rw_mode)
        ring->rd_cmd_id = (ring->rd_cmd_id + 1) % 16;

    ring->cmd_req_tail = (ring->cmd_req_tail + 1) % (ring->ring_queue_size);

    HX_REG_WRITE(base + UPIF_CMD_REQ_TRIG, 0x03);

}

void upif_axi_ring_send(ring_handle_t *ring, void *base, uint32_t addr, uint8_t *data, uint32_t data_len)
{
    uint64_t req_phy_addr = ring->ring_req_queue_phy_addr + ring->message_size*ring->req_tail;
    uint8_t *req_addr = (uint8_t *)(ring->ring_req_queue_virt_addr + ring->message_size*ring->req_tail);

    memcpy(req_addr, data, data_len);

    upif_axi_ring_request(ring, base, req_phy_addr, HX_MEMORY, 1, addr, 1, data_len, 0);

    ring->req_tail = (ring->req_tail + 1) % (ring->ring_queue_size);
}

void upif_fifo_ring_request(ring_handle_t *ring, void *base, int64_t req_phy_addr, 
                            unsigned int write_pkg_num, unsigned int write_pkg_size, 
                            unsigned int read_pkg_num, unsigned int read_pkg_size)
{
    uint8_t *cmd_req_addr = (uint8_t *)(ring->ring_cmd_req_queue_virt_addr + ring->cmd_req_size*ring->cmd_req_tail);
    int *cmd_req = (int *)cmd_req_addr;

    //word0 
    *cmd_req = 0 |(1<<1)|(0<<2)|(1<<3)|(write_pkg_size<<8)|(write_pkg_num<<20);
    cmd_req++;

    //word1
    *cmd_req = (read_pkg_size<<0)|(read_pkg_num<<12);
    cmd_req++;

    //word2
    *cmd_req = req_phy_addr & 0xFFFFFFFF;
    cmd_req++;

    //word3
    *cmd_req = (req_phy_addr >> 32) & 0xFFFFFFFF;

    ring->cmd_req_tail = (ring->cmd_req_tail + 1) % (ring->ring_queue_size);

    HX_REG_WRITE(base + UPIF_CMD_REQ_TRIG, 0x03);

}

int build_pub_head_msg(struct pub_head_st *head, uint8_t service_type, uint8_t func_id, uint8_t mode, 
                        uint8_t src_length, uint8_t dest_length, uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    head->hdr_flags = 1;
    head->direction = 0;
    head->service_type = service_type;
    head->func_id = func_id;
    head->mode = mode;
    head->src_length = src_length;
#if ESRAM_DEBUG    
    head->dest_length = src_length;
#else
    head->dest_length = dest_length;
#endif
    head->soft_id = HX_ID_MAGIC_CODE << 24 | soft_id;

    head->operate_data_l = (uint32_t)(opaque_data & 0xFFFFFFFF);
    head->operate_data_h = (uint32_t)((opaque_data >> 32) & 0xFFFFFFFF);

    //print_hex_dump(KERN_DEBUG, "head:", DUMP_PREFIX_ADDRESS, 16, 4, head, 16, false);

    return ret;
}

int build_sm2_sign_msg(struct sm2_sign_st *req, uint8_t func_id, uint8_t *message, uint8_t *da, uint8_t *random, 
                    uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, func_id, HX_SM2_SIGN, SM2_SIGN_REQ_HEAD_LEN, SM2_SIGN_RES_HEAD_LEN, 
                        soft_id, opaque_data);              
    memcpy(req->message, message, SM2_MESSAGE_LEN);
    memcpy(req->da, da, SM2_DA_LEN);
    memcpy(req->random, random, SM2_RANDOM_LEN);

    return ret;
}

int build_sm2_verify_msg(struct sm2_verify_st *req, uint8_t func_id, uint8_t *message, uint8_t *pa, uint8_t *verify, 
                    uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, func_id, HX_SM2_VERIFY, SM2_VERIFY_REQ_HEAD_LEN, SM2_VERIFY_RES_HEAD_LEN, 
                        soft_id, opaque_data);              
    memcpy(req->message, message, SM2_MESSAGE_LEN);
    memcpy(req->pa, pa, SM2_PA_LEN);
    memcpy(req->verify, verify, SM2_VERIFY_LEN);

    //print_hex_dump(KERN_DEBUG, "message:", DUMP_PREFIX_ADDRESS, 16, 1, req->message, SM2_MESSAGE_LEN, false);
    //print_hex_dump(KERN_DEBUG, "pa:", DUMP_PREFIX_ADDRESS, 16, 1, req->pa, SM2_PA_LEN, false);
    //print_hex_dump(KERN_DEBUG, "verify:", DUMP_PREFIX_ADDRESS, 16, 1, req->verify, SM2_VERIFY_LEN, false);

    return ret;
}

int build_sm2_kp_msg(struct sm2_kp_st *req, uint8_t func_id, uint8_t *da, uint8_t *pa, uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, func_id, HX_SM2_KP, SM2_KP_REQ_HEAD_LEN, SM2_KP_RES_HEAD_LEN, 
                        soft_id, opaque_data);              
    memcpy(req->da, da, SM2_DA_LEN);
    memcpy(req->pa, pa, SM2_PA_LEN);

    return ret;
}

int build_sm2_kg_msg(struct sm2_kg_st *req, uint8_t func_id, uint8_t *da, uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, func_id, HX_SM2_KG, SM2_KG_REQ_HEAD_LEN, SM2_KG_RES_HEAD_LEN, 
                        soft_id, opaque_data);              
    memcpy(req->da, da, SM2_DA_LEN);

    return ret;
}

int build_sm2_sign_trng_msg(struct sm2_sign_trng_st *req, uint8_t func_id, uint8_t *message, uint8_t *da,
                    uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, func_id, HX_SM2_SIGN_TRNG, SM2_SIGN_TRNG_REQ_HEAD_LEN, SM2_SIGN_TRNG_RES_HEAD_LEN, 
                        soft_id, opaque_data);              
    memcpy(req->message, message, SM2_MESSAGE_LEN);
    memcpy(req->da, da, SM2_DA_LEN);

    return ret;
}

int build_pub_sm2_msg(void *req_addr, uint8_t func_id, uint8_t sm2_mode, uint32_t soft_id, uint64_t opaque_data, 
                    uint8_t *message, uint8_t *da, uint8_t *pa, uint8_t* verify, uint8_t *random)
{
    int ret = 0;

    switch (sm2_mode) {
        case HX_SM2_SIGN:
            build_sm2_sign_msg((struct sm2_sign_st *)req_addr, func_id, message, da, random, soft_id, opaque_data);
            break;
        case HX_SM2_VERIFY:
            build_sm2_verify_msg((struct sm2_verify_st *)req_addr, func_id, message, pa, verify, soft_id, opaque_data);
            break;
        case HX_SM2_KP:
            build_sm2_kp_msg((struct sm2_kp_st *)req_addr, func_id, da, pa, soft_id, opaque_data);
            break;
        case HX_SM2_KG:
            build_sm2_kg_msg((struct sm2_kg_st *)req_addr, func_id, da, soft_id, opaque_data);
            break;
        case HX_SM2_SIGN_TRNG:
            build_sm2_sign_trng_msg((struct sm2_sign_trng_st *)req_addr, func_id, message, da, soft_id, opaque_data);
            break;
        default:
            printk("build_pub_sm2_msg: sm2 mode is not supported\n");
            return -1;
    }

    return ret;
}

int build_rsa_sign_1024_msg(struct rsa_sign_1024_st *req, uint8_t *message, uint8_t *d, uint8_t *N, 
                    uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, HX_RSA, HX_RSA_SIGN_1024, RSA_SIGN_1024_REQ_HEAD_LEN, 
                        RSA_SIGN_1024_RES_HEAD_LEN, soft_id, opaque_data);              
    memcpy(req->message, message, RSA_1024_LEN);
    memcpy(req->d, d, RSA_1024_LEN);
    memcpy(req->N, N, RSA_1024_LEN);

    return ret;
}

int build_rsa_sign_1024_crt_msg(struct rsa_sign_1024_crt_st *req, uint8_t *message, uint8_t *dp, uint8_t *dq, 
                    uint8_t *p, uint8_t *q, uint8_t *qinv, uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, HX_RSA, HX_RSA_SIGN_1024_CRT, RSA_SIGN_1024_CRT_REQ_HEAD_LEN, 
                        RSA_SIGN_1024_CRT_RES_HEAD_LEN, soft_id, opaque_data);              
    memcpy(req->message, message, RSA_1024_LEN);
    memcpy(req->dp, dp, RSA_CRT_1024_LEN);
    memcpy(req->dq, dq, RSA_CRT_1024_LEN);
    memcpy(req->p, p, RSA_CRT_1024_LEN);
    memcpy(req->q, q, RSA_CRT_1024_LEN);
    memcpy(req->qinv, qinv, RSA_CRT_1024_LEN);

    return ret;
}

int build_rsa_veiry_1024_msg(struct rsa_verify_1024_st *req, uint8_t *message, uint8_t *e, uint8_t *N, 
                    uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, HX_RSA, HX_RSA_VERIFY_1024, RSA_VERIFY_1024_REQ_HEAD_LEN, 
                        RSA_VERIFY_1024_RES_HEAD_LEN, soft_id, opaque_data);              
    memcpy(req->message, message, RSA_1024_LEN);
    memcpy(req->e, e, RSA_1024_LEN);
    memcpy(req->N, N, RSA_1024_LEN);

    return ret;
}

int build_rsa_sign_2048_msg(struct rsa_sign_2048_st *req, uint8_t *message, uint8_t *d, uint8_t *N, 
                    uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, HX_RSA, HX_RSA_SIGN_2048, RSA_SIGN_2048_REQ_HEAD_LEN, 
                        RSA_SIGN_2048_RES_HEAD_LEN, soft_id, opaque_data);              
    memcpy(req->message, message, RSA_2048_LEN);
    memcpy(req->d, d, RSA_2048_LEN);
    memcpy(req->N, N, RSA_2048_LEN);

    return ret;
}

int build_rsa_sign_2048_crt_msg(struct rsa_sign_2048_crt_st *req, uint8_t *message, uint8_t *dp, uint8_t *dq, 
                    uint8_t *p, uint8_t *q, uint8_t *qinv, uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, HX_RSA, HX_RSA_SIGN_2048_CRT, RSA_SIGN_2048_CRT_REQ_HEAD_LEN, 
                        RSA_SIGN_2048_CRT_RES_HEAD_LEN, soft_id, opaque_data);              
    memcpy(req->message, message, RSA_2048_LEN);
    memcpy(req->dp, dp, RSA_CRT_2048_LEN);
    memcpy(req->dq, dq, RSA_CRT_2048_LEN);
    memcpy(req->p, p, RSA_CRT_2048_LEN);
    memcpy(req->q, q, RSA_CRT_2048_LEN);
    memcpy(req->qinv, qinv, RSA_CRT_2048_LEN);

    return ret;
}

int build_rsa_veiry_2048_msg(struct rsa_verify_2048_st *req, uint8_t *message, uint8_t *e, uint8_t *N, 
                    uint32_t soft_id, uint64_t opaque_data)
{
    int ret = 0;

    build_pub_head_msg(&req->head, HX_PUB, HX_RSA, HX_RSA_VERIFY_2048, RSA_VERIFY_2048_REQ_HEAD_LEN, 
                        RSA_VERIFY_2048_RES_HEAD_LEN, soft_id, opaque_data);              
    memcpy(req->message, message, RSA_2048_LEN);
    memcpy(req->e, e, RSA_2048_LEN);
    memcpy(req->N, N, RSA_2048_LEN);

    return ret;
}

int build_pub_rsa_msg(void *req_addr, uint8_t rsa_mode, uint32_t soft_id, uint64_t opaque_data, uint8_t *message, 
                    uint8_t *d, uint8_t *e, uint8_t *N, uint8_t *dp, uint8_t *dq, uint8_t *p, uint8_t *q, 
                    uint8_t *qinv)
{
    int ret = 0;

    switch (rsa_mode) {
        case HX_RSA_SIGN_1024:
            build_rsa_sign_1024_msg((struct rsa_sign_1024_st *)req_addr, message, d, N, soft_id, opaque_data);
            break;
        case HX_RSA_SIGN_1024_CRT:
            build_rsa_sign_1024_crt_msg((struct rsa_sign_1024_crt_st *)req_addr, message, dp, dq, p, q, qinv, 
                                        soft_id, opaque_data);
            break;
        case HX_RSA_VERIFY_1024:
            build_rsa_veiry_1024_msg((struct rsa_verify_1024_st *)req_addr, message, e, N, soft_id, opaque_data);
            break;
        case HX_RSA_SIGN_2048:
            build_rsa_sign_2048_msg((struct rsa_sign_2048_st *)req_addr, message, d, N, soft_id, opaque_data);
            break;
        case HX_RSA_SIGN_2048_CRT:
            build_rsa_sign_2048_crt_msg((struct rsa_sign_2048_crt_st *)req_addr, message, dp, dq, p, q, qinv, 
                                        soft_id, opaque_data);
            break;
        case HX_RSA_VERIFY_2048:
            build_rsa_veiry_2048_msg((struct rsa_verify_2048_st *)req_addr, message, e, N, soft_id, opaque_data);
            break;
        default:
            printk("build_pub_rsa_msg: rsa mode is not supported\n");
            return -1;
    }

    return ret;
}

int build_sm2_data(void *req_addr, hx_sm2_pkg_t *user_pkg, uint8_t func_id, uint8_t mode, uint64_t opaque_data)
{
    int ret = 0; 
    hx_sm2_data_t *user_data = (hx_sm2_data_t *)user_pkg->addr;
    hx_sm2_data_t data;

    copy_from_user(&data, &user_data[user_pkg->index], sizeof(hx_sm2_data_t));

    build_pub_sm2_msg(req_addr, func_id, mode, data.id, opaque_data, 
                        data.message, data.da, data.pa, data.verify, data.random);
    
    user_pkg->index++;
    
    return ret;
}

int build_rsa_data(void *req_addr, hx_rsa_pkg_t *user_pkg, uint8_t func_id, uint8_t mode, uint64_t opaque_data)
{
    int ret = 0; 
    hx_rsa_data_t *user_data = (hx_rsa_data_t *)user_pkg->addr;
    hx_rsa_data_t data;

    copy_from_user(&data, &user_data[user_pkg->index], sizeof(hx_rsa_data_t));

    build_pub_rsa_msg(req_addr, mode, data.id, opaque_data, 
                        data.message, data.d, data.e, data.N, data.dp, data.dq, data.p, data.q, data.qinv);
    
    user_pkg->index++;
    
    return ret;
}

int build_pub_data(void *req_addr, void *user_pkg, uint8_t func_id, uint8_t mode, uint64_t opaque_data)
{
    int ret = 0; 

    if(func_id == HX_RSA)
        build_rsa_data(req_addr, (hx_rsa_pkg_t *)user_pkg, func_id, mode, opaque_data);
    else
        build_sm2_data(req_addr, (hx_sm2_pkg_t *)user_pkg, func_id, mode, opaque_data);
    
    return ret;
}

int pub_request_send(ring_handle_t *ring, void *base, void *user_pkg, void *cb, uint8_t func_id, uint8_t mode, uint32_t pkg_num, uint32_t msg_num)
{
    int ret = 0; 
    uint32_t i = 0, msg = 0, pkg = 0;
    uint8_t *req_addr = NULL;
    uint8_t *msg_addr = NULL;
    uint64_t req_phy_addr = 0;

    if(ring->req_tail + pkg_num > ring->ring_queue_size)
        ring->req_tail = 0;

    req_phy_addr = ring->ring_req_queue_phy_addr + ring->message_size*ring->req_tail;

    pkg = pkg_num;
    while(pkg--)
    {
        req_addr = (uint8_t *)(ring->ring_req_queue_virt_addr + ring->message_size*ring->req_tail);
        msg_addr = req_addr;
        msg = msg_num;
        while(msg--)
        {
            build_pub_data(msg_addr, user_pkg, func_id, mode, (uint64_t)cb);
            msg_addr += get_pub_req_len(func_id, mode);
        }
        ring->req_tail++;
    }

#if UPIF_CMD_REQ
    upif_axi_ring_request(ring, base, 0, HX_FIFO, 0, PUB_OFIFO_ADDR, 
                            pkg_num, get_pub_res_len(func_id, mode)*msg_num, 1);

    upif_axi_ring_request(ring, base, req_phy_addr, HX_FIFO, 1, PUB_IFIFO_ADDR, 
                            pkg_num, get_pub_req_len(func_id, mode)*msg_num, 0);
                            
#else
    while(HX_REG_READ(base + UPIF_RING_STATE_ADDR) & 0xC00);

    upif_axi_cmd_set(base, HX_FIFO, 0, PUB_OFIFO_ADDR, pkg_num, get_pub_res_len(func_id, mode)*msg_num, 1);
    upif_axi_cmd_set(base, HX_FIFO, 1, PUB_IFIFO_ADDR, pkg_num, get_pub_req_len(func_id, mode)*msg_num, 0);
    //upif_fifo_cmd_set(base, pkg_num, get_pub_req_len(func_id, mode)*msg_num, get_pub_res_len(func_id, mode)*msg_num);

    HX_REG_WRITE(base + UPIF_RING_ADDR_L_ADDR, req_phy_addr & 0xFFFFFFFF);
    HX_REG_WRITE(base + UPIF_RING_ADDR_H_ADDR, (req_phy_addr >> 32) & 0xFFFFFFFF);

    HX_REG_WRITE(base + UPIF_RESPON_PKG_NUM_ADDR, 0x00);
    HX_REG_WRITE(base + UPIF_RING_PKG_ADDR,  (pkg_num<<16)|(get_pub_req_len(func_id, mode)*msg_num));
    
    wmb();
    HX_REG_WRITE(base + UPIF_RING_START_ADDR, 0x01);
    while(!HX_REG_READ(base + UPIF_RING_START_ADDR));
    HX_REG_WRITE(base + UPIF_RING_START_ADDR, 0x00);
#endif

    return ret;
}

int build_pub_request(hx_ring_handle_t *ring_handle, void *cb, uint32_t algo, uint32_t mode, 
                    uint64_t src, uint32_t src_len, uint64_t dst, uint32_t dst_len)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    void *base = ring_handle->ptr_base;
    int ret = 0;
    hx_sm2_pkg_t sm2_pkg;
    hx_rsa_pkg_t rsa_pkg;
    void *user_pkg;
    uint32_t msg_total_num = 0;
    uint8_t msg_max_num = 0;
    uint32_t pkg_num = 0;
    uint32_t msg_num = 0;
    uint32_t msg_num_last = 0;
    uint32_t pkg_count = 0;
    uint32_t pkg = 0;

    ring->cb_data = NULL;

    if(algo == HX_RSA)
    {
        copy_from_user(&rsa_pkg, (void *)src, sizeof(hx_rsa_pkg_t));
        rsa_pkg.index = 0;
        msg_total_num = rsa_pkg.size;
        user_pkg = &rsa_pkg;
    }
    else
    {
        copy_from_user(&sm2_pkg, (void *)src, sizeof(hx_sm2_pkg_t));
        sm2_pkg.index = 0;
        msg_total_num = sm2_pkg.size;
        user_pkg = &sm2_pkg;
    }

    msg_max_num = get_pub_max_msg_num(algo, mode);

    if(msg_total_num <= msg_max_num)
    {
        msg_num = msg_total_num;
        pkg_num = 1;
    }
    else
    {
        if(msg_total_num%msg_max_num)
            msg_num_last = msg_total_num%msg_max_num;

        msg_num = msg_max_num;
        pkg_num = msg_total_num / msg_max_num;
    }

    LOG_DEBUG("msg_total_num = %d\r\n", msg_total_num);
    LOG_DEBUG("pkg_num = %d\r\n", pkg_num);
    LOG_DEBUG("msg_num_last = %d\r\n", msg_num_last);
    LOG_DEBUG("algo = %d, mode = %d\r\n", algo, mode);

    pkg_count = pkg_num;
    while(pkg_count)
    {
        pkg = pkg_count < PUB_MAX_PKG_NUM ? pkg_count : PUB_MAX_PKG_NUM;
        pub_request_send(ring, base, user_pkg, cb, algo, mode, pkg, msg_num);
        pkg_count -= pkg;
    }
    
    if(msg_num_last)
        pub_request_send(ring, base, user_pkg, cb, algo, mode, 1, msg_num_last);

    return ret;
}

int trng_request_send(ring_handle_t *ring, void *base, void *cb, uint32_t pkg_num, uint32_t pkg_len)
{
    uint64_t req_phy_addr = req_phy_addr = ring->ring_req_queue_phy_addr + ring->message_size*ring->req_tail;
    uint8_t *req_addr = (uint8_t *)(ring->ring_req_queue_virt_addr + ring->message_size*ring->req_tail);

    build_pub_head_msg((struct pub_head_st *)req_addr, HX_PUB, HX_TRNG, HX_TRNG_MODE_1, 
                        pkg_num, pkg_len/PUB_DATA_LEN, 0, (uint64_t)cb); 

    upif_axi_ring_request(ring, base, 0, HX_FIFO, 0, PUB_OFIFO_ADDR, pkg_num, pkg_len + PUB_HEAD_LEN, 1);

    upif_axi_ring_request(ring, base, req_phy_addr, HX_FIFO, 1, PUB_IFIFO_ADDR, 1, PUB_HEAD_LEN, 0);

    ring->req_tail = (ring->req_tail + 1) % (ring->ring_queue_size);

    return 0;
}

int build_trng_request(hx_ring_handle_t *ring_handle, void *cb, uint32_t dst_len)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    void *base = ring_handle->ptr_base;
    int ret = 0;
    void *user_pkg;
    uint32_t pkg_num = dst_len / TRNG_PKG_LEN;

    ring->cb_data = NULL;

    LOG_DEBUG("dst_len = %d\r\n", dst_len);
    LOG_DEBUG("pkg_num = %d\r\n", pkg_num);

    trng_request_send(ring, base, cb, pkg_num, TRNG_PKG_LEN);
    
    return ret;
}

int pqc_request_send(ring_handle_t *ring, void *base, uint8_t mode, uint64_t pqc_addr, uint8_t *src, uint32_t pkg_num, uint32_t pkg_size)
{
    int ret = 0; 
    uint8_t *req_addr = NULL;
    uint64_t req_phy_addr = 0;

    req_phy_addr = ring->ring_req_queue_phy_addr + ring->message_size*ring->req_tail;
    req_addr = (uint8_t *)(ring->ring_req_queue_virt_addr + ring->message_size*ring->req_tail);

    copy_from_user(req_addr, src, pkg_size*pkg_num);
    
    ring->req_tail += pkg_num;
    
    upif_axi_ring_request(ring, base, req_phy_addr, HX_MEMORY, 1, pqc_addr, pkg_num, pkg_size, 0);

    return ret;
}

int pqc_request_transmit(ring_handle_t *ring, void *base, uint8_t mode, uint64_t addr, uint64_t src, uint32_t src_len)
{
    uint8_t *data = (uint8_t *)src;
    uint32_t len_limit = MEMORY_PKG_LEN - addr % MEMORY_PKG_LEN;
    uint32_t first_len = (src_len > len_limit) ? len_limit : src_len;
    first_len = (first_len > UPIF_PKG_LEN) ? UPIF_PKG_LEN : first_len;
    uint32_t midle_times = (src_len - first_len) / UPIF_PKG_LEN;
    uint32_t last_len = (src_len - first_len) % UPIF_PKG_LEN;   
    int ret = 0; 

    LOG_DEBUG("request, src_len = %d\r\n", src_len);
    LOG_DEBUG("request, first_len = %d\r\n", first_len);
    LOG_DEBUG("request, midle_times = %d\r\n", midle_times);
    LOG_DEBUG("request, last_len = %d\r\n", last_len);
    LOG_DEBUG("ring->req_tail = %d\r\n", ring->req_tail);

    if(ring->req_tail + midle_times + 2 > ring->ring_queue_size)
        ring->req_tail = 0;

    pqc_request_send(ring, base, mode, addr, data, 1, first_len);
    data += first_len;
    addr += first_len;

    if(midle_times)
    {
        pqc_request_send(ring, base, mode, addr, data, midle_times, UPIF_PKG_LEN);
        data += (UPIF_PKG_LEN*midle_times);
        addr += (UPIF_PKG_LEN*midle_times);        
    }

    if(last_len)
        pqc_request_send(ring, base, mode, addr, data, 1, last_len); 

    return ret; 
}

int pqc_response_transmit(ring_handle_t *ring, void *base, uint8_t mode, uint64_t addr, uint32_t dst_len, uint8_t rd_mode)
{
    uint32_t len_limit = MEMORY_PKG_LEN - addr % MEMORY_PKG_LEN;
    uint32_t first_len = (dst_len > len_limit) ? len_limit : dst_len;
    first_len = (first_len > UPIF_PKG_LEN) ? UPIF_PKG_LEN : first_len;
    uint32_t midle_times = (dst_len - first_len) / UPIF_PKG_LEN;
    uint32_t last_len = (dst_len - first_len) % UPIF_PKG_LEN; 
    int ret = 0; 
    uint64_t resp_phy_addr = 0;

    LOG_DEBUG("response, dst_len = %d\r\n", dst_len);
    LOG_DEBUG("response, first_len = %d\r\n", first_len);
    LOG_DEBUG("response, midle_times = %d\r\n", midle_times);
    LOG_DEBUG("response, last_len = %d\r\n", last_len);

    if(ring->resp_tail + midle_times + 2 > ring->ring_queue_size)
    {
        ring->resp_tail = 0;
        resp_phy_addr = ring->ring_resp_queue_phy_addr + ring->message_size*ring->resp_tail;
        HX_REG_WRITE(base + UPIF_RESP_ADDR_L_ADDR, resp_phy_addr & 0xFFFFFFFF);
        HX_REG_WRITE(base + UPIF_RESP_ADDR_H_ADDR, (resp_phy_addr >> 32) & 0xFFFFFFFF);
    }

    upif_axi_ring_request(ring, base, 0, HX_MEMORY, 0, addr, 1, first_len, rd_mode);
    addr += first_len;

    if(midle_times)
    {
        upif_axi_ring_request(ring, base, 0, HX_MEMORY, 0, addr, midle_times, UPIF_PKG_LEN, rd_mode); 
        addr += UPIF_PKG_LEN*midle_times;
    }

    if(last_len)
        upif_axi_ring_request(ring, base, 0, HX_MEMORY, 0, addr, 1, last_len, rd_mode); 

    return ret; 
}

int pqc_fifo_ring_send(ring_handle_t *ring, void *base, uint8_t user_space, uint8_t *src, uint32_t pkg_num, uint32_t pkg_size)
{
    int ret = 0; 
    uint8_t *req_addr = NULL;
    uint64_t req_phy_addr = 0;

    if(ring->req_tail + pkg_num > ring->ring_queue_size)
        ring->req_tail = 0;

    req_phy_addr = ring->ring_req_queue_phy_addr + ring->message_size*ring->req_tail;
    req_addr = (uint8_t *)(ring->ring_req_queue_virt_addr + ring->message_size*ring->req_tail);

    if(user_space == USER_DATA)
        copy_from_user(req_addr, src, pkg_size*pkg_num);
    else
        memcpy(req_addr, src, pkg_size*pkg_num);
    
    ring->req_tail += pkg_num;
    
    upif_fifo_ring_request(ring, base, req_phy_addr, pkg_num, pkg_size, 0, 0);

    return ret;
}

int pqc_fifo_request_transmit(ring_handle_t *ring, void *base, uint8_t mode, uint8_t src_space, uint64_t src, uint32_t src_len, uint32_t dst_len)
{
    int ret = 0; 
    struct pqc_request_st request;
    memset(&request, 0, sizeof(request));

    build_pqc_request_msg(&request, src_len, dst_len, 0, 0, 0, get_pqc_request_algo_id(mode), 0);
    pqc_fifo_request_send(ring, base, KERNEL_DATA, (uint8_t *)&request, sizeof(request)); 

    pqc_fifo_request_send(ring, base, src_space, src, src_len); 

    return ret; 
}

int pqc_fifo_response_transmit(ring_handle_t *ring, void *base, uint32_t dst_len)
{
    uint32_t times = dst_len / UPIF_PKG_LEN;
    uint32_t last_len = dst_len % UPIF_PKG_LEN; 
    int ret = 0; 
    uint64_t resp_phy_addr = 0;

    //LOG_DEBUG("response, dst_len = %d\r\n", dst_len);
    //LOG_DEBUG("response, times = %d\r\n", times);
    //LOG_DEBUG("response, last_len = %d\r\n", last_len);

    if(ring->resp_tail + times + 1 > ring->ring_queue_size)
    {
        ring->resp_tail = 0;
        resp_phy_addr = ring->ring_resp_queue_phy_addr + ring->message_size*ring->resp_tail;
        HX_REG_WRITE(base + UPIF_RESP_ADDR_L_ADDR, resp_phy_addr & 0xFFFFFFFF);
        HX_REG_WRITE(base + UPIF_RESP_ADDR_H_ADDR, (resp_phy_addr >> 32) & 0xFFFFFFFF);
    }

    if(times)
        upif_fifo_ring_request(ring, base, 0, 0, 0, times, UPIF_PKG_LEN);

    if(last_len) 
        upif_fifo_ring_request(ring, base, 0, 0, 0, 1, last_len);

    return ret; 
}

int build_pqc_request(hx_ring_handle_t *ring_handle, void *cb, uint8_t bus, uint32_t mode, 
                    uint64_t src, uint32_t src_len, uint64_t dst, uint32_t dst_len)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    void *base = ring_handle->ptr_base;
    int ret = 0;

    ring->rd_cmd_id = 0;
    ring->cb_data = cb;
    
    if(bus == HX_AXI_RING_BUS)
    {
        pqc_config_data_init(ring, base, HX_AXI_RING_BUS, mode);

        //response
        if(mode == HX_DILI2_KG)
        {
            pqc_response_transmit(ring, base, mode, PQC_MEM_OUT7_ADDR, PQC_DILI2_KG_SK_OUT_LEN, 1);
            pqc_response_transmit(ring, base, mode, PQC_MEM_OUT8_ADDR, PQC_DILI2_KG_PK_OUT_LEN, 1);
        }
        else
            pqc_response_transmit(ring, base, mode, get_pqc_mem_out_address(mode), dst_len, 1);

        //request
        if(mode == HX_DILI2_SIGN)
        {
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN_ADDR, src, PQC_DILI2_ENC_SK_IN_LEN);
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN2_ADDR, src + PQC_DILI2_ENC_SK_IN_LEN, PQC_DILI2_ENC_MSG_IN_LEN);
        }
        else if(mode == HX_DILI2_VERIFY)
        {
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN_ADDR, src, PQC_DILI2_DEC_PK_IN_LEN);
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN2_ADDR, src + PQC_DILI2_DEC_PK_IN_LEN, PQC_DILI2_DEC_MSG_IN_LEN);
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN3_ADDR, src + PQC_DILI2_DEC_PK_IN_LEN + PQC_DILI2_DEC_MSG_IN_LEN, PQC_DILI2_DEC_SIGN_IN_LEN);
        }
        else if(mode == HX_FALCON_SIGN)
        {
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN4_ADDR, src, PQC_FALCON_ENC_SK_IN_LEN);
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN5_ADDR, src + PQC_FALCON_ENC_SK_IN_LEN, PQC_FALCON_ENC_SEED_IN_LEN);
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN6_ADDR, src + PQC_FALCON_ENC_SK_IN_LEN + PQC_FALCON_ENC_SEED_IN_LEN, PQC_FALCON_ENC_NONCE_IN_LEN);
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN7_ADDR, src + PQC_FALCON_ENC_SK_IN_LEN + PQC_FALCON_ENC_SEED_IN_LEN + PQC_FALCON_ENC_NONCE_IN_LEN, PQC_FALCON_ENC_MSG_IN_LEN);
        }
        else if(mode == HX_FALCON_VERIFY)
        {
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN8_ADDR, src, PQC_FALCON_DEC_PK_IN_LEN);
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN9_ADDR, src + PQC_FALCON_DEC_PK_IN_LEN, PQC_FALCON_DEC_SIGN_IN_LEN);
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN10_ADDR, src + PQC_FALCON_DEC_PK_IN_LEN + PQC_FALCON_DEC_SIGN_IN_LEN, PQC_FALCON_DEC_NONCE_IN_LEN);
        }
        else
            pqc_request_transmit(ring, base, mode, PQC_MEM_IN_ADDR, src, src_len);
        
        pqc_axi_mem_start(ring, base);
    }
    else if(bus == HX_FIFO_RING_BUS)
    {
        pqc_config_data_init(ring, base, HX_FIFO_RING_BUS, mode);

        pqc_fifo_response_transmit(ring, base, dst_len + PQC_HEAD_LEN);

        pqc_fifo_request_transmit(ring, base, mode, USER_DATA, src, src_len, dst_len);  
    }
    else
    {
        pqc_config_data_init(ring, base, HX_FIFO_REG_BUS, mode);

        uint8_t *src_data = kzalloc(src_len, GFP_KERNEL);
        copy_from_user(src_data, src, src_len);
        pqc_fifo_write_send(base, src_data, src_len, dst_len);
        kfree(src_data);

        pqc_fifo_read_cmd_send(base, dst_len + PQC_HEAD_LEN);
    }

    return ret;
}

int get_sm2_req_len(uint8_t sm2_mode)
{
    switch (sm2_mode) {
        case HX_SM2_SIGN:
            return SM2_SIGN_REQ_LEN;
        case HX_SM2_VERIFY:
            return SM2_VERIFY_REQ_LEN;
        case HX_SM2_KP:
            return SM2_KP_REQ_LEN;
        case HX_SM2_KG:
            return SM2_KG_REQ_LEN;
        case HX_SM2_SIGN_TRNG:
            return SM2_SIGN_TRNG_REQ_LEN;
        default:
            printk("get_sm2_req_len: sm2 mode is not supported\n");
            return 0;
    }
}

int get_sm2_res_len(uint8_t sm2_mode)
{
    switch (sm2_mode) {
        case HX_SM2_SIGN:
            return SM2_SIGN_RES_LEN;
        case HX_SM2_VERIFY:
            return SM2_VERIFY_RES_LEN;
        case HX_SM2_KP:
            return SM2_KP_RES_LEN;
        case HX_SM2_KG:
            return SM2_KG_RES_LEN;
        case HX_SM2_SIGN_TRNG:
            return SM2_SIGN_TRNG_RES_LEN;
        default:
            printk("get_sm2_res_len: sm2 mode is not supported\n");
            return 0;
    }
}

int get_sm2_max_msg_num(uint8_t sm2_mode)
{
    switch (sm2_mode) {
        case HX_SM2_SIGN:
            return UPIF_PKG_LEN/SM2_SIGN_REQ_LEN;
        case HX_SM2_VERIFY:
            return UPIF_PKG_LEN/SM2_VERIFY_REQ_LEN;
        case HX_SM2_KP:
            return UPIF_PKG_LEN/SM2_KP_REQ_LEN;
        case HX_SM2_KG:
            //input len must be not less than output len
            return UPIF_PKG_LEN/(SM2_KG_REQ_LEN+PUB_DATA_LEN*2);
        case HX_SM2_SIGN_TRNG:
            return UPIF_PKG_LEN/SM2_SIGN_TRNG_REQ_LEN;
        default:
            printk("get_sm2_max_msg_num: sm2 mode is not supported\n");
            return 0;
    }
}

int get_rsa_req_len(uint8_t rsa_mode)
{
    switch (rsa_mode) {
        case HX_RSA_SIGN_1024:
            return RSA_SIGN_1024_REQ_LEN;
        case HX_RSA_SIGN_1024_CRT:
            return RSA_SIGN_1024_CRT_REQ_LEN;
        case HX_RSA_VERIFY_1024:
            return RSA_VERIFY_1024_REQ_LEN;
        case HX_RSA_SIGN_2048:
            return RSA_SIGN_2048_REQ_LEN;
        case HX_RSA_SIGN_2048_CRT:
            return RSA_SIGN_2048_CRT_REQ_LEN;
        case HX_RSA_VERIFY_2048:
            return RSA_VERIFY_2048_REQ_LEN;
        default:
            printk("get_rsa_req_len: rsa mode is not supported\n");
            return 0;
    }
}

int get_rsa_res_len(uint8_t rsa_mode)
{
    switch (rsa_mode) {
        case HX_RSA_SIGN_1024:
            return RSA_SIGN_1024_RES_LEN;
        case HX_RSA_SIGN_1024_CRT:
            return RSA_SIGN_1024_CRT_RES_LEN;
        case HX_RSA_VERIFY_1024:
            return RSA_VERIFY_1024_RES_LEN;
        case HX_RSA_SIGN_2048:
            return RSA_SIGN_2048_RES_LEN;
        case HX_RSA_SIGN_2048_CRT:
            return RSA_SIGN_2048_CRT_RES_LEN;
        case HX_RSA_VERIFY_2048:
            return RSA_VERIFY_2048_RES_LEN;
        default:
            printk("get_rsa_res_len: rsa mode is not supported\n");
            return 0;
    }
}

int get_rsa_max_msg_num(uint8_t rsa_mode)
{
    switch (rsa_mode) {
        case HX_RSA_SIGN_1024:
            return UPIF_PKG_LEN/RSA_SIGN_1024_REQ_LEN;
        case HX_RSA_SIGN_1024_CRT:
            return UPIF_PKG_LEN/RSA_SIGN_1024_CRT_REQ_LEN;
        case HX_RSA_VERIFY_1024:
            return UPIF_PKG_LEN/RSA_VERIFY_1024_REQ_LEN;
        case HX_RSA_SIGN_2048:
            return UPIF_PKG_LEN/RSA_SIGN_2048_REQ_LEN;
        case HX_RSA_SIGN_2048_CRT:
            return UPIF_PKG_LEN/RSA_SIGN_2048_CRT_REQ_LEN;
        case HX_RSA_VERIFY_2048:
            return UPIF_PKG_LEN/RSA_VERIFY_2048_REQ_LEN;
        default:
            printk("get_rsa_max_msg_num: rsa mode is not supported\n");
            return 0;
    }
}

int get_pub_req_len(uint8_t algo, uint8_t mode)
{
    if((algo == HX_SM2) || (algo == HX_ECC))
        return get_sm2_req_len(mode);
    else if (algo == HX_RSA)
        return get_rsa_req_len(mode);
    else
    {
        printk("get_pub_req_len: mode is not supported\n");
        return 1;
    } 
}

int get_pub_res_len(uint8_t algo, uint8_t mode)
{
    if((algo == HX_SM2) || (algo == HX_ECC))
        return get_sm2_res_len(mode);
    else if (algo == HX_RSA)
        return get_rsa_res_len(mode);
    else
    {
        printk("get_pub_res_len: mode is not supported\n");
        return 1;
    } 
}

int get_pub_max_msg_num(uint8_t algo, uint8_t mode)
{
    if((algo == HX_SM2) || (algo == HX_ECC))
        return get_sm2_max_msg_num(mode);
    else if (algo == HX_RSA)
        return get_rsa_max_msg_num(mode);
    else
    {
        printk("get_pub_max_msg_num: mode is not supported\n");
        return 1;
    }     
}

int get_pqc_req_len(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return sizeof(hx_kyber512_kg_req_t);
        case HX_KYBER512_SIGN: 
            return sizeof(hx_kyber512_enc_req_t);
        default:
            printk("get_pqc_req_len: pqc mode is not supported\n");
            return 0;
    }
}

int get_pqc_res_len(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return PQC_KYBER512_SK_LEN;
        case HX_KYBER512_SIGN:
            return PQC_KYBER512_SIGN_OUT_LEN;
        case HX_KYBER512_VERIFY:
            return PQC_KYBER512_VERIFY_OUT_LEN;
        case HX_AIGIS_KG:
            return PQC_AIGIS_KG_OUT_LEN;
        case HX_AIGIS_SIGN:
            return PQC_AIGIS_SIGN_OUT_LEN;
        case HX_AIGIS_VERIFY:
            return PQC_AIGIS_VERIFY_OUT_LEN;
        default:
            printk("get_pqc_res_len: pqc mode is not supported\n");
            return 0;
    }
}

int get_pqc_mem_out_address(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
        case HX_KYBER512_SIGN:
        case HX_AIGIS_KG:
        case HX_AIGIS_SIGN:
            return PQC_MEM_OUT2_ADDR;
        case HX_KYBER512_VERIFY:
        case HX_AIGIS_VERIFY:
            return PQC_MEM_OUT3_ADDR;
        case HX_LAC128_KG:
        case HX_LAC128_SIGN:
        case HX_LAC128_VERIFY:
        case HX_SPHINCS_SIGN:
        case HX_SPHINCS_VERIFY:
        case HX_BIKE_SIGN:
        case HX_BIKE_VERIFY:
        case HX_MCELIECE_SIGN:
            return PQC_MEM_OUT_ADDR;
        case HX_SPHINCS_KG:
            return PQC_MEM_OUT1_ADDR;
        case HX_HQC_KG:
            return PQC_MEM_OUT4_ADDR;
        case HX_HQC_SIGN:
        case HX_HQC_VERIFY:
            return PQC_MEM_OUT5_ADDR;
        case HX_MCELIECE_VERIFY:
            return PQC_MEM_OUT6_ADDR;
        case HX_DILI2_SIGN:
            return PQC_MEM_OUT9_ADDR;
        case HX_DILI2_VERIFY:
            return PQC_MEM_OUT7_ADDR;
        case HX_FALCON_SIGN:
            return PQC_MEM_OUT10_ADDR;
        case HX_FALCON_VERIFY:
            return PQC_MEM_OUT11_ADDR;
        default:
            printk("get_pqc_mem_out_address: pqc mode is not supported\n");
            return 0;
    }
}

uint8_t get_pqc_request_algo_id(uint8_t pqc_mode)
{
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return LLP_KYBER512_KEYGEN;
        case HX_KYBER512_SIGN:
            return LLP_KYBER512_ENC;     
        case HX_KYBER512_VERIFY:
            return LLP_KYBER512_DEC;   
        case HX_AIGIS_KG:
            return LLP_AIGIS_KEYGEN;  
        case HX_AIGIS_SIGN:
            return LLP_AIGIS_ENC;  
        case HX_AIGIS_VERIFY:
            return LLP_AIGIS_DEC;
        case HX_LAC128_KG:
            return LLP_LAC128_KEYGEN;   
        case HX_LAC128_SIGN:
            return LLP_LAC128_ENC;
        case HX_LAC128_VERIFY:
            return LLP_LAC128_DEC;  
        case HX_SPHINCS_KG:
            return LLP_SPHINCS_KEYGEN; 
        case HX_SPHINCS_SIGN:
            return LLP_SPHINCS_SIGN;
        case HX_SPHINCS_VERIFY:
            return LLP_SPHINCS_VERIFY;
        case HX_HQC_KG:
            return LLP_HQC_KEYGEN;
        case HX_HQC_SIGN:
            return LLP_HQC_ENC;
        case HX_HQC_VERIFY:
            return LLP_HQC_DEC;
        case HX_BIKE_SIGN:
            return LLP_BIKE1_ENC;
        case HX_BIKE_VERIFY:
            return LLP_BIKE1_DEC;
        case HX_MCELIECE_SIGN:
            return LLP_MCELIECE_ENC;
        case HX_MCELIECE_VERIFY:
            return LLP_MCELIECE_DEC;
        case HX_DILI2_KG:
            return LLP_DILI2_KEYGEN;
        case HX_DILI2_SIGN:
            return LLP_DILI2_SIGN;
        case HX_DILI2_VERIFY:
            return LLP_DILI2_VERIFY;
        case HX_FALCON_SIGN:
            return LLP_FALCON512_SIGN;
        case HX_FALCON_VERIFY:
            return LLP_FALCON_VERIFY;
        default:
            printk("get_pqc_request_algo_id: pqc mode is not supported\n");
            return 0;
    }
}

int build_pqc_config_msg(struct pqc_config_st *config, uint32_t src_length, uint32_t dst_address)
{ 
    config->head = 0xEB90;

    src_length = src_length / 16;
    memcpy(config->src_length, &src_length, sizeof(config->src_length));

    config->direction = 0;
    config->pkg_mode = 0;
    config->dst_address = dst_address;

    return 0;
}

int build_pqc_request_msg(struct pqc_request_st *config, uint32_t src_length, uint32_t dst_length,
                        uint8_t bank_mode, uint8_t len_mode, uint16_t pkg_num, uint8_t algo_id, uint32_t real_len)
{ 
    config->head = PQC_MAGIC_NUM;

    src_length = src_length / 16;
    memcpy(config->src_length, &src_length, sizeof(config->src_length));
    dst_length = dst_length / 16;
    memcpy(config->dst_length, &dst_length, sizeof(config->dst_length));

    config->direction = 0;
    config->pkg_mode = 1;
    config->dp_bank_en = bank_mode;
    config->variable_en = len_mode;
    config->pkg_number = pkg_num;
    config->algo_id = algo_id;
    config->mlen = real_len;
    
    //print_hex_dump(KERN_DEBUG, "head:", DUMP_PREFIX_ADDRESS, 16, 4, config, 16, false);

    return 0;
}

int pqc_fifo_send(void *base, uint8_t *data, uint32_t data_len)
{
    uint32_t len = (data_len > UPIF_PKG_LEN) ? UPIF_PKG_LEN : data_len; 
    uint32_t times = data_len / UPIF_PKG_LEN;
    uint32_t mod_len = data_len % UPIF_PKG_LEN;
    uint8_t *data_addr = data;

    while(times--)
    {
        pqc_fifo_cmd_set(base, 1, len, 0, 0);
        upif_fifo_write(base, (uint32_t *)data_addr, len);
        data_addr += len;
    }

    if(mod_len)
    {
        pqc_fifo_cmd_set(base, 1, mod_len, 0, 0);
        upif_fifo_write(base, (uint32_t *)data_addr, mod_len);
    }

    return 0;
}

int pqc_fifo_request_send(ring_handle_t *ring, void *base, uint8_t user_space, uint8_t *data, uint32_t data_len)
{
    uint32_t times = data_len / UPIF_PKG_LEN;
    uint32_t last_len = data_len % UPIF_PKG_LEN;

    //printk("request, data_len = %d\r\n", data_len);
    //printk("request, times = %d\r\n", times);
    //printk("request, last_len = %d\r\n", last_len);

    if(times)
    {
        pqc_fifo_ring_send(ring, base, user_space, data, times, UPIF_PKG_LEN);
        data += (UPIF_PKG_LEN*times); 
    }

    if(last_len)
        pqc_fifo_ring_send(ring, base, user_space, data, 1, last_len);

    return 0;
}

int pqc_axi_fifo_send(void *base, uint32_t addr, uint8_t *data, uint32_t data_len)
{
    uint32_t len = (data_len > UPIF_PKG_LEN) ? UPIF_PKG_LEN : data_len; 
    uint32_t times = data_len / UPIF_PKG_LEN;
    uint32_t mod_len = data_len % UPIF_PKG_LEN;

    while(times--)
    {
        upif_axi_cmd_set(base, HX_MEMORY, 1, addr, 1, len, 0);
        upif_fifo_write(base, (uint32_t *)data, len);
        data += len;
        addr += len;
    }

    if(mod_len)
    {
        upif_axi_cmd_set(base, HX_MEMORY, 1, addr, 1, mod_len, 0);
        upif_fifo_write(base, (uint32_t *)data, mod_len);
    }

    return 0;
}

int pqc_axi_mem_send(ring_handle_t *ring, void *base, uint32_t addr, uint8_t *data, uint32_t data_len)
{
    uint32_t len = (data_len > UPIF_PKG_LEN) ? UPIF_PKG_LEN : data_len; 
    uint32_t times = data_len / UPIF_PKG_LEN;
    uint32_t mod_len = data_len % UPIF_PKG_LEN;

    while(times--)
    {
        upif_axi_ring_send(ring, base, addr, data, len);
        data += len;
        addr += len;
    }

    if(mod_len)
    {
        upif_axi_ring_send(ring, base, addr, data, mod_len);
    }

    return 0;
}

int pqc_axi_fifo_start(void *base)
{
    uint8_t wdata[16];

    upif_axi_cmd_set(base, HX_MEMORY, 1, PQC_STARTCONTROL_TASKADDR, 1, 4, 0);
    wdata[0] = 0x00; 
    wdata[1] = 0x10; 
    upif_fifo_write(base, (uint32_t *)wdata, sizeof(wdata));

    upif_axi_cmd_set(base, HX_MEMORY, 1, PQC_STARTCONTROL_START, 1, 4, 0);
    wdata[0] = 0x01; 
    upif_fifo_write(base, (uint32_t *)wdata, sizeof(wdata));

    return 0;
}

int pqc_axi_reset(ring_handle_t *ring, void *base)
{
    uint32_t wdata[4];

    memset(wdata, 0, 16);

    wdata[0] = (1<<(16+4) & ~(1<<4)); 
    pqc_axi_mem_send(ring, base, SYSCTL_CRG_GRP3_SRST, (uint8_t *)wdata, 16);

    wdata[0] = (1<<(16+4) | (1<<4));
    pqc_axi_mem_send(ring, base, SYSCTL_CRG_GRP3_SRST, (uint8_t *)wdata, 16);

    return 0;
}

int pqc_axi_mem_start(ring_handle_t *ring, void *base)
{
    uint8_t wdata[16];

    memset(wdata, 0, 16);

    wdata[0] = 0x00; 
    wdata[1] = 0x10; 
    pqc_axi_mem_send(ring, base, PQC_STARTCONTROL_TASKADDR, (uint8_t *)wdata, 4);

    wdata[0] = 0x01;
    wdata[1] = 0x00; 
    pqc_axi_mem_send(ring, base, PQC_STARTCONTROL_START, (uint8_t *)wdata, 4);

    return 0;
}

int init_pqc_data(ring_handle_t *ring, void *base, uint8_t bus, uint8_t mode, uint8_t *const_data, uint32_t const_len, 
                    uint8_t *task_data, uint32_t task_len)
{
    if(bus == HX_FIFO_REG_BUS)
    {
        LOG_DEBUG("pqc const data fifo reg init\r\n");
        struct pqc_config_st config;

        //send const data
        build_pqc_config_msg(&config, const_len, PQC_ESRAM_INNER_ADDR);
        pqc_fifo_send(base, (uint8_t *)&config, sizeof(struct pqc_config_st));
        pqc_fifo_send(base, const_data, const_len);

        //send task data
        build_pqc_config_msg(&config, task_len, PQC_ESRAM2_INNER_ADDR);
        pqc_fifo_send(base, (uint8_t *)&config, sizeof(struct pqc_config_st));
        pqc_fifo_send(base, task_data, task_len);
    }
    else if(bus == HX_FIFO_RING_BUS)
    {
        LOG_DEBUG("pqc const data fifo ring init\r\n");
        struct pqc_config_st config;

        //send const data
        build_pqc_config_msg(&config, const_len, PQC_ESRAM_INNER_ADDR);
        pqc_fifo_request_send(ring, base, KERNEL_DATA, (uint8_t *)&config, sizeof(struct pqc_config_st));
        pqc_fifo_request_send(ring, base, KERNEL_DATA, const_data, const_len);   

        //send task data
        build_pqc_config_msg(&config, task_len, PQC_ESRAM2_INNER_ADDR);
        pqc_fifo_request_send(ring, base, KERNEL_DATA, (uint8_t *)&config, sizeof(struct pqc_config_st));
        pqc_fifo_request_send(ring, base, KERNEL_DATA, task_data, task_len);           
    }
    else if(bus == HX_AXI_REG_BUS)
    {
        LOG_DEBUG("pqc const data axi reg init\r\n");
        pqc_axi_fifo_send(base, PQC_ESRAM_ADDR, const_data, const_len);
        pqc_axi_fifo_send(base, PQC_ESRAM2_ADDR, task_data, task_len);
    }
    else
    {
        LOG_DEBUG("pqc const data axi ring init\r\n");
        if(mode == HX_FALCON_SIGN || mode == HX_FALCON_VERIFY)
            pqc_axi_mem_send(ring, base, PQC_ESRAM3_ADDR, const_data, const_len);
        else
            pqc_axi_mem_send(ring, base, PQC_ESRAM_ADDR, const_data, const_len);
        pqc_axi_mem_send(ring, base, PQC_ESRAM2_ADDR, task_data, task_len); 
    }

    return 0;
}

int pqc_config_data_init(ring_handle_t *ring, void *base, uint8_t bus, uint8_t mode)
{
    static uint8_t current_mode = 0xFF;
    static uint8_t fifo_config_flag = 0;

    //falcon sign need reset every time
    if(mode == current_mode && mode != HX_FALCON_SIGN  && mode != HX_FALCON_VERIFY)
        return 0;

    current_mode = mode;

    if(bus == HX_AXI_RING_BUS)
        pqc_axi_reset(ring, base);
    else if(bus == HX_FIFO_RING_BUS)
    {
        if(fifo_config_flag == 0)
        {
            LOG_DEBUG("pqc config data fifo init\r\n");
            pqc_fifo_request_send(ring, base, KERNEL_DATA, (uint8_t *)fifo_config_data, sizeof(fifo_config_data));
            fifo_config_flag = 1;
        } 
    }  
    else
        pqc_fifo_send(base, (uint8_t *)fifo_config_data, sizeof(fifo_config_data));

    switch (mode) {
    case HX_KYBER512_KG:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)kyber_keygen_512_constdata, sizeof(kyber_keygen_512_constdata), 
                        (uint8_t *)kyber_keygen_512_taskcode, sizeof(kyber_keygen_512_taskcode));
        break;
    case HX_KYBER512_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)kyber_enc_512_constdata, sizeof(kyber_enc_512_constdata), 
                        (uint8_t *)kyber_enc_512_taskcode, sizeof(kyber_enc_512_taskcode));
        break;
    case HX_KYBER512_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)kyber_dec_512_constdata, sizeof(kyber_dec_512_constdata), 
                        (uint8_t *)kyber_dec_512_taskcode, sizeof(kyber_dec_512_taskcode));
        break;
    case HX_AIGIS_KG:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)aigis_keygen_constdata, sizeof(aigis_keygen_constdata), 
                        (uint8_t *)aigis_keygen_taskcode, sizeof(aigis_keygen_taskcode));
        break;   
    case HX_AIGIS_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)aigis_enc_constdata, sizeof(aigis_enc_constdata), 
                        (uint8_t *)aigis_enc_taskcode, sizeof(aigis_enc_taskcode));
        break;     
    case HX_AIGIS_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)aigis_dec_constdata, sizeof(aigis_dec_constdata), 
                        (uint8_t *)aigis_dec_taskcode, sizeof(aigis_dec_taskcode));
        break; 
    case HX_LAC128_KG:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)lac128_keygen_constdata, sizeof(lac128_keygen_constdata), 
                        (uint8_t *)lac128_keygen_taskcode, sizeof(lac128_keygen_taskcode));
        break;  
    case HX_LAC128_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)lac128_enc_constdata, sizeof(lac128_enc_constdata), 
                        (uint8_t *)lac128_enc_taskcode, sizeof(lac128_enc_taskcode));
        break; 
    case HX_LAC128_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)lac128_dec_constdata, sizeof(lac128_dec_constdata), 
                        (uint8_t *)lac128_dec_taskcode, sizeof(lac128_dec_taskcode));
        break;     
    case HX_SPHINCS_KG:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)sphincs_keygen_constdata, sizeof(sphincs_keygen_constdata), 
                        (uint8_t *)sphincs_keygen_taskcode, sizeof(sphincs_keygen_taskcode));
        break;  
    case HX_SPHINCS_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)sphincs_sign_constdata, sizeof(sphincs_sign_constdata), 
                        (uint8_t *)sphincs_sign_taskcode, sizeof(sphincs_sign_taskcode));
        break;
    case HX_SPHINCS_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)sphincs_verify_constdata, sizeof(sphincs_verify_constdata), 
                        (uint8_t *)sphincs_verify_taskcode, sizeof(sphincs_verify_taskcode));
        break;
    case HX_HQC_KG:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)hqc_keygen_constdata, sizeof(hqc_keygen_constdata), 
                        (uint8_t *)hqc_keygen_taskcode, sizeof(hqc_keygen_taskcode));
        break;
    case HX_HQC_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)hqc_enc_constdata, sizeof(hqc_enc_constdata), 
                        (uint8_t *)hqc_enc_taskcode, sizeof(hqc_enc_taskcode));
        break;
    case HX_HQC_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)hqc_dec_constdata, sizeof(hqc_dec_constdata), 
                        (uint8_t *)hqc_dec_taskcode, sizeof(hqc_dec_taskcode));
        break;
    case HX_BIKE_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)bike_enc_constdata, sizeof(bike_enc_constdata), 
                        (uint8_t *)bike_enc_taskcode, sizeof(bike_enc_taskcode));
        break;
    case HX_BIKE_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)bike_dec_constdata, sizeof(bike_dec_constdata), 
                        (uint8_t *)bike_dec_taskcode, sizeof(bike_dec_taskcode));
        break;
    case HX_MCELIECE_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)mceliece_enc_constdata, sizeof(mceliece_enc_constdata), 
                        (uint8_t *)mceliece_enc_taskcode, sizeof(mceliece_enc_taskcode));
        break;
    case HX_MCELIECE_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)mceliece_dec_constdata, sizeof(mceliece_dec_constdata), 
                        (uint8_t *)mceliece_dec_taskcode, sizeof(mceliece_dec_taskcode));
        break;
    case HX_DILI2_KG:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)dili2_keygen_constdata, sizeof(dili2_keygen_constdata), 
                        (uint8_t *)dili2_keygen_taskcode, sizeof(dili2_keygen_taskcode));
        break;
    case HX_DILI2_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)dili2_sign_constdata, sizeof(dili2_sign_constdata), 
                        (uint8_t *)dili2_sign_taskcode, sizeof(dili2_sign_taskcode));
        break;
    case HX_DILI2_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)dili2_verify_constdata, sizeof(dili2_verify_constdata), 
                        (uint8_t *)dili2_verify_taskcode, sizeof(dili2_verify_taskcode));
        break;
    case HX_FALCON_SIGN:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)falcon_sign_constdata, sizeof(falcon_sign_constdata), 
                        (uint8_t *)falcon_sign_taskcode, sizeof(falcon_sign_taskcode));
        break;
    case HX_FALCON_VERIFY:
        init_pqc_data(ring, base, bus, mode, (uint8_t *)falcon_verify_constdata, sizeof(falcon_verify_constdata), 
                        (uint8_t *)falcon_verify_taskcode, sizeof(falcon_verify_taskcode));
        break;
    default:
        printk("pqc_config_data_init fail\n");
        break;
    } 

    return 0;
}

int pqc_fifo_write_send(void *base, uint8_t *src_data, uint32_t src_length, uint32_t dst_length)
{
    struct pqc_request_st request;
    build_pqc_request_msg(&request, src_length, dst_length, 0, 0, 0, 0, 0);
    pqc_fifo_send(base, (uint8_t *)&request, sizeof(struct pqc_request_st));
    pqc_fifo_send(base, src_data, src_length);

    return 0;
}

int pqc_fifo_read_cmd_send(void *base, uint32_t read_len)
{
    uint32_t len = (read_len > UPIF_PKG_LEN) ? UPIF_PKG_LEN : read_len; 
    uint32_t times = read_len / UPIF_PKG_LEN;
    uint32_t mod_len = read_len % UPIF_PKG_LEN;

    if(times)
        pqc_fifo_cmd_set(base, 0, 0, times, len);

    if(mod_len)
        pqc_fifo_cmd_set(base, 0, 0, 1, mod_len);

    return 0;
}

void data_swap(unsigned char *buff, int len)
{
    int i = 0, start = 0;
    unsigned char tmp = 0;

    start = len - 1;
    for (i = 0; i < ((start + 1) / 2); i++) {
        tmp = *(buff + i);
        *(buff + i) = *(buff + (start - i));
        *(buff + (start - i)) = tmp;
    };
}

int hx_init_hash_ctx(void *ctx, uint32_t algo, uint32_t pkg_mode,
                     uint8_t *key, uint32_t key_len, uint8_t padding)
{
    int ret = 0;
    session_t *sctx = ctx;
    sctx->algo = algo;
    sctx->pkg_mode = pkg_mode;
    sctx->padding = padding;

    if (sctx->hash_len_update != 0)
        return 0; // already seting
    switch (algo) {
    case HX_ALGO_SM3:
        sctx->hash_len_update = 32;
        sctx->actual_hash_mid_len = 32;
        sctx->hash_dgst_len = 32;
        sctx->hash_key_len = 64;
        break;

    case HX_ALGO_SHA256:
        sctx->hash_len_update = 32;
        sctx->actual_hash_mid_len = 32;
        sctx->hash_dgst_len = 32;
        sctx->hash_key_len = 64;
        break;

    case HX_ALGO_SHA3_256:
        sctx->hash_len_update = 208;
        sctx->actual_hash_mid_len = 208;
        sctx->hash_dgst_len = 32;
        sctx->hash_key_len = 144; // 实际136B
        break;
    }
    ret = copy_from_user(sctx->hash_key, key, key_len);
    // if(ret != 0)
    // {
    //     printk(">>>[ERROR] copy key error! \n");
    //     return ret;
    // }

    // ret=copy_from_user(sctx->hash_midval, iv, iv_len);
    // if(ret != 0)
    // {
    //     printk(">>>[ERROR] copy iv error! \n");
    // }
    return ret;
}

int hx_init_cipher_ctx(void *ctx, uint32_t algo, uint32_t mode, uint32_t dir, int force_update, int pkg_from, int pkg_mode,
                       uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *tag, uint32_t tag_len, uint32_t total_len)
{
    int ret = 0;
    uint32_t len = key_len;
    session_t *sctx = ctx;
    uint8_t zero[16];
    sctx->algo = algo;
    sctx->mode = mode;
    sctx->dir = dir;
    sctx->pkg_mode = pkg_mode;
    sctx->total_len = total_len;

    memset(zero, 0, 16);

    if (sctx->mode == HX_CIPHER_ECB || sctx->mode == HX_CIPHER_CBC || sctx->mode == HX_CIPHER_CFB || sctx->mode == HX_CIPHER_OFB || sctx->mode == HX_CIPHER_CTR || sctx->mode == HX_CIPHER_XTS) {
        /*key*/
        if (((key_len != 0) && (sctx->key_len == 0)) || (force_update == 1)) {
            ret |= copy_from_user(sctx->key, key, key_len);
            if (key_len % 16 != 0) {
                memcpy(sctx->key + key_len, zero, 16 - (key_len % 16));
                len = key_len + 16 - (key_len % 16);
            }
            sctx->key_len = key_len;
            sctx->actual_key_len = len;
        }
        /*iv*/
        if (((iv_len != 0) && (sctx->iv_len == 0)) || (force_update == 1)) {
            sctx->iv_len = iv_len;
            sctx->actual_iv_len = iv_len;
            ret |= copy_from_user((void *)(&sctx->iv[0]), (void *)(iv), sctx->iv_len);
        }

    } else if (sctx->mode == HX_CIPHER_CMAC || sctx->mode == HX_CIPHER_CBC_MAC) {
        /*key*/
        if (((key_len != 0) && (sctx->key_len == 0)) || (force_update == 1)) {
            ret |= copy_from_user(sctx->key, key, key_len);
            if (key_len % 16 != 0) {
                memcpy(sctx->key + key_len, zero, 16 - (key_len % 16));
                len = key_len + 16 - (key_len % 16);
            }
            sctx->key_len = key_len;
            sctx->actual_key_len = len;
        }

        /*iv*/
        if ((sctx->iv_len == 0) || (force_update == 1)) {
            sctx->iv_len = 16;
            sctx->actual_iv_len = 16;
            memcpy(sctx->iv, zero, sctx->iv_len);
        }

        /*tag*/
        if ((sctx->tag_len == 0) || (force_update == 1)) {
            if (dir == HX_CIPHER_ENCRYPT) {
                memcpy(sctx->tag, zero, 16);
                tag_len = 16;
            } else {
                ret |= copy_from_user(sctx->tag, tag, tag_len);
            }
            sctx->tag_len = tag_len;
            sctx->actual_tag_len = 16;
        }

    } else if (sctx->mode == HX_CIPHER_CCM || sctx->mode == HX_CIPHER_GCM) {
        /*key*/
        if (((key_len != 0) && (sctx->key_len == 0)) || (force_update == 1)) {
            ret |= copy_from_user(sctx->key, key, key_len);
            if (key_len % 16 != 0) {
                memcpy(sctx->key + key_len, zero, 16 - (key_len % 16));
                len = key_len + 16 - (key_len % 16);
            }
            sctx->key_len = key_len;
            sctx->actual_key_len = len;
        }
        /*iv*/
        if (((iv_len != 0) && (sctx->iv_len == 0)) || (force_update == 1)) {
            if (sctx->mode == HX_CIPHER_CCM) {
                ret |= copy_from_user((void *)(&sctx->iv[0]), (void *)(iv), iv_len);
                if (iv_len % 16 != 0) {
                    memcpy(sctx->iv + iv_len, zero, 16 - ((iv_len + 1) % 16));
                    sctx->iv[15] = iv_len;
                    len = iv_len - (iv_len % 16) + 16;
                }
                sctx->iv_len = iv_len;
                sctx->actual_iv_len = len;
            } else {
                /* iv_len == 12 */
                ret |= copy_from_user((void *)(&sctx->iv[0]), (void *)(iv), iv_len);
                sctx->iv[12] = 0;
                sctx->iv[13] = 0;
                sctx->iv[14] = 0;
                sctx->iv[15] = 1;
                len = iv_len - (iv_len % 16) + 16;

                sctx->iv_len = iv_len;
                sctx->actual_iv_len = len;
            }
        }
        /*mid_tag*/
        if (((sctx->actual_mid_tag_len == 0)) || (force_update == 1)) {
            memcpy(sctx->mid_tag, zero, 16);
            sctx->mid_tag_len = 16;
            sctx->actual_mid_tag_len = 16;
        }

        /*tag*/
        if ((dir == HX_CIPHER_DECRYPT) && (pkg_mode == HX_PACKAGE_COMPLETE || pkg_mode == HX_PACKAGE_END)) {
            ret |= copy_from_user((void *)(&sctx->tag[0]), (void *)(tag), tag_len);
            if (tag_len % 16 != 0) {
                memcpy(sctx->tag + tag_len, zero, 16 - tag_len);
            }
        } else
            memcpy(sctx->tag, zero, 16);
        sctx->tag_len = tag_len;
        sctx->actual_tag_len = 16;

        /*aad*/
        if (((aad_len != 0) && (sctx->aad_len == 0)) || (force_update == 1)) {
            if (sctx->mode == HX_CIPHER_CCM) {
                ret |= copy_from_user((void *)(&sctx->aad[2]), (void *)(aad), aad_len);
                sctx->aad[0] = aad_len / 256;
                sctx->aad[1] = aad_len % 256;
                len = aad_len + 2;
                if ((len) % 16 != 0) {
                    memcpy(sctx->aad + len, zero, 16 - (len % 16));
                    len = len - (len % 16) + 16;
                }
                sctx->aad_len = aad_len;
                sctx->actual_aad_len = len;
            } else {
                ret |= copy_from_user((void *)(&sctx->aad[0]), (void *)(aad), aad_len);
                len = aad_len;
                if ((len) % 16 != 0) {
                    memcpy(sctx->aad + len, zero, 16 - (len % 16));
                    len = len - (len % 16) + 16;
                }
                sctx->aad_len = aad_len;
                sctx->actual_aad_len = len;
            }
        }
    }

    return ret;
}

int build_cipher_src_data(void *ctx, uint8_t *src_vir, uint8_t *src, uint32_t src_len)
{
    int ret = 0, len = 0;
    session_t *sctx = ctx;
    uint8_t zero[16] = {0};

    if (sctx->mode == HX_CIPHER_ECB) {
        /*key*/
        memcpy(src_vir, sctx->key, sctx->actual_key_len);
        len += sctx->actual_key_len;
        /*data*/
        ret |= copy_from_user(src_vir + len, src, src_len);
        if (ret != 0) {
            LOG_ERROR("build_cipher_src_data copy_data fail\n");
            ret = HX_RET_PARAM_ERROR;
            return ret;
        }
    } else if (sctx->mode == HX_CIPHER_CBC || sctx->mode == HX_CIPHER_CFB || sctx->mode == HX_CIPHER_OFB || sctx->mode == HX_CIPHER_CTR || sctx->mode == HX_CIPHER_XTS) {
        /*key*/
        memcpy(src_vir, sctx->key, sctx->actual_key_len);
        len += sctx->actual_key_len;
        /*iv*/
        memcpy(src_vir + len, sctx->iv, sctx->iv_len);
        len += sctx->iv_len;
        /*data*/
        ret |= copy_from_user(src_vir + len, src, src_len);
        if (ret != 0) {
            LOG_ERROR("build_cipher_src_data copy_data fail\n");
            ret = HX_RET_PARAM_ERROR;
            return ret;
        }
    } else if (sctx->mode == HX_CIPHER_CMAC || sctx->mode == HX_CIPHER_CBC_MAC) {
        /*key*/
        memcpy(src_vir, sctx->key, sctx->actual_key_len);
        len += sctx->actual_key_len;
        /*iv*/
        memcpy(src_vir + len, sctx->iv, sctx->iv_len);
        len += sctx->iv_len;
        /*tag*/
        memcpy(src_vir + len, sctx->tag, sctx->tag_len);
        len += sctx->tag_len;
        /*data*/
        ret |= copy_from_user(src_vir + len, src, src_len);
        if (ret != 0) {
            LOG_ERROR("build_cipher_src_data copy_data fail\n");
            ret = HX_RET_PARAM_ERROR;
            return ret;
        }

    } else if (sctx->mode == HX_CIPHER_CCM || sctx->mode == HX_CIPHER_GCM) {
        /*key*/
        memcpy(src_vir, sctx->key, sctx->actual_key_len);
        len += sctx->actual_key_len; // 16
        /*iv*/
        memcpy(src_vir + len, sctx->iv, sctx->actual_iv_len);
        len += sctx->actual_iv_len; // 16
        /*mid_tag*/
        memcpy(src_vir + len, sctx->mid_tag, sctx->mid_tag_len);
        len += sctx->mid_tag_len; // 16
        /*tag*/
        memcpy(src_vir + len, sctx->tag, sctx->tag_len);
        len += sctx->tag_len;
        if (sctx->pkg_mode == HX_PACKAGE_COMPLETE || sctx->pkg_mode == HX_PACKAGE_START) {
            /*aad*/
            memcpy(src_vir + len, sctx->aad, sctx->actual_aad_len);
            len += sctx->actual_aad_len;
        }
        /*data*/
        ret |= copy_from_user(src_vir + len, src, src_len);
        if (ret != 0) {
            LOG_ERROR("build_cipher_src_data copy_data fail\n");
            ret = HX_RET_PARAM_ERROR;
            return ret;
        }
    }
    sctx->actual_src_len = src_len + len;
    return ret;
}

int build_hash_src_data(void *ctx, uint8_t *src_vir, uint8_t *src, uint32_t src_len)
{
    int ret = 0, len = 0;
    session_t *sctx = ctx;

    if (sctx->pkg_mode == HX_PACKAGE_START || sctx->pkg_mode == HX_PACKAGE_COMPLETE) {
        /*message*/
        ret |= copy_from_user(src_vir, src, src_len);
        if (ret != 0) {
            LOG_ERROR("build_hash_src_data copy_data fail 1\n");
            ret = HX_RET_FAILED;
            return ret;
        }

    } else if (sctx->pkg_mode == HX_PACKAGE_MIDDLE || sctx->pkg_mode == HX_PACKAGE_END) {
        /*iv*/
        memcpy(src_vir, sctx->hash_midval, sctx->actual_hash_mid_len);
        len += sctx->actual_hash_mid_len;
        /*message*/
        ret |= copy_from_user(src_vir + len, src, src_len);
        if (ret != 0) {
            LOG_ERROR("build_hash_src_data copy_data fail 2\n");
            ret = HX_RET_FAILED;
            return ret;
        }
    } else {
        LOG_ERROR("build_hash_src_data copy_data fail 3\n");
        ret = HX_RET_PARAM_ERROR;
        return ret;
    }

    sctx->actual_src_len = src_len + len;
    sctx->iv_len = len;

    return ret;
}

int build_hmac_src_data(void *ctx, uint8_t *src_vir, uint8_t *src, uint32_t src_len)
{
    int ret = 0, len = 0;
    session_t *sctx = ctx;

    if (sctx->pkg_mode == HX_PACKAGE_START || sctx->pkg_mode == HX_PACKAGE_COMPLETE) {
        /*key*/
        memcpy(src_vir, sctx->hash_key, sctx->hash_key_len);
        len += sctx->hash_key_len;
        /*message*/
        ret |= copy_from_user(src_vir + len, src, src_len);
        if (ret != 0) {
            LOG_ERROR("build_hmac_src_data copy_data fail 1\n");
            ret = HX_RET_FAILED;
            return ret;
        }

    } else if (sctx->pkg_mode == HX_PACKAGE_MIDDLE || sctx->pkg_mode == HX_PACKAGE_END) {
        /*key*/
        memcpy(src_vir, sctx->hash_key, sctx->hash_key_len);
        len += sctx->hash_key_len;
        /*iv*/
        memcpy(src_vir + len, sctx->hash_midval, sctx->actual_hash_mid_len);
        len += sctx->actual_hash_mid_len;
        /*message*/
        ret |= copy_from_user(src_vir + len, src, src_len);
        if (ret != 0) {
            LOG_ERROR("build_hmac_src_data copy_data fail 2\n");
            ret = HX_RET_FAILED;
            return ret;
        }
    } else {
        LOG_ERROR("build_hmac_src_data copy_data fail 3\n");
        ret = HX_RET_PARAM_ERROR;
        return ret;
    }

    sctx->actual_src_len = src_len + len;
    sctx->iv_len = sctx->actual_hash_mid_len;

    return ret;
}

int build_prf_src_data(void *ctx, uint8_t *src_vir, uint8_t *src, uint32_t src_len)
{
    int ret = 0, len = 0;
    session_t *sctx = ctx;

    /*key*/
    memcpy(src_vir, sctx->hash_key, sctx->hash_key_len); // hmac
    len += sctx->hash_key_len;
    /*seed*/
    ret |= copy_from_user(src_vir + len, src, src_len - len);
    if (ret != 0) {
        LOG_ERROR("build_prf_src_data copy_data fail 1\n");
        ret = HX_RET_FAILED;
        return ret;
    }
    sctx->actual_src_len = src_len;

    return ret;
}

int hx_get_block_len(uint32_t algo)
{
    int hash_block_len = 0;
    switch (algo) {
    case HX_ALGO_SM3:
        hash_block_len = 64;
        break;
    case HX_ALGO_SHA256:
        hash_block_len = 64;
        break;
    case HX_ALGO_SHA3_256:
        hash_block_len = 64;
        break;
    default:
        break;
    }
    return hash_block_len;
}

int hx_get_hmac_len(uint32_t algo)
{
    int hash_block_len = 0;
    switch (algo) {
    case HX_ALGO_SM3:
        hash_block_len = 32;
        break;

    case HX_ALGO_SHA256:
        hash_block_len = 32;
        break;

    case HX_ALGO_SHA3_256:
        hash_block_len = 32;
        break;
    default:
        break;
    }
    return hash_block_len;
}

void *hx_dma_alloc_consistent(void *pdev, size_t size, dma_addr_t *dma_handle)
{
    void *ret = NULL;

#if PCIE_ENABLE
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
    ret = pci_alloc_consistent((struct pci_dev *)pdev, size, dma_handle);
#else
    ret = dma_alloc_coherent(&((struct pci_dev *)pdev)->dev, size, dma_handle, GFP_KERNEL);
#endif
#else
    ret = dma_alloc_coherent((struct device *)pdev, size, dma_handle, GFP_KERNEL);
#endif

    return ret;
}

void hx_dma_free_consistent(void *pdev, size_t size, void *cpu_addr, dma_addr_t dma_addr)
{
#if PCIE_ENABLE
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
    pci_free_consistent((struct pci_dev *)pdev, size, cpu_addr, dma_addr);
#else
    dma_free_coherent(&((struct pci_dev *)pdev)->dev, size, cpu_addr, dma_addr);
#endif
#else
    dma_free_coherent((struct device *)pdev, size, cpu_addr, dma_addr);
#endif
}

int hx_copy_from(void *dst, void *src, int len, int type)
{
    int ret = copy_from_user(dst, src, len);
    return 0;
}