#include <linux/delay.h>
#include <linux/eventfd.h>
#include <linux/fdtable.h>
#include <linux/ktime.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/platform_device.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include "algo.h"
#include "common.h"
#include "ioctl_cmds.h"
#include "data.h"

#define MAX_POLL_COUNT 20000
#define CORE_NUMBER    16

#define PQC_DATA 0

extern int kyber_keygen_512_in_ref[16];
extern int kyber_keygen_512_out_ref[400];

int pqc_result[1024];

typedef struct hx_performance_s {
    uint8_t poll_running;
    uint8_t packet_error;
    uint32_t packet_num;
} __attribute__((packed)) hx_performance_t;

hx_performance_t perf_item;

int upif_wait_response(uint8_t *base, uint8_t pkg_num)
{
    unsigned int resp;
    unsigned int wait_count = 0;

    while(1)
    {
        resp = HX_REG_READ(base + UPIF_RESPON_PKG_NUM_ADDR);
        if((resp&0xffffffff) == pkg_num)
        {   
            HX_REG_WRITE(base + UPIF_RESPON_PKG_NUM_ADDR, 0x00);
            printk("upif resp success\n");
            break;
        }
        if(wait_count++ > 1000)
        {
            printk("upif wait time out, resp = %d\r\n", resp);
            break;
        }
        usleep_range(1000, 1000);
    }

    return 0;
}

int pqc_compare_data(int *pqc_result, int *out_ref, uint32_t len)
{
    int i ;

    if(memcmp(pqc_result, out_ref, len) == 0)
        printk("upif compare success\r\n");
    else
    {
        for(i=0; i< (len/4); i++)
        {
            if(pqc_result[i] != out_ref[i])
            {
                printk("i = %d\r\n", i);
                print_hex_dump(KERN_DEBUG, "pqc_result:", DUMP_PREFIX_ADDRESS, 16, 4, &pqc_result[i-4], 64, false);
                print_hex_dump(KERN_DEBUG, "out_ref:", DUMP_PREFIX_ADDRESS, 16, 4, &out_ref[i-4], 64, false);
                break;
            }
        }
    }

    return 0;
}

int build_pub_sm2_data(void *req_addr, uint8_t func_id, uint8_t sm2_mode, uint32_t soft_id, uint64_t opaque_data)
{
    switch (sm2_mode) {
        case HX_SM2_SIGN:
            build_pub_sm2_msg(req_addr, func_id, HX_SM2_SIGN, soft_id, 0, hash_value, private_key, NULL, NULL, (uint8_t *)random_k);
            break;
        case HX_SM2_VERIFY:
            build_pub_sm2_msg(req_addr, func_id, HX_SM2_VERIFY, soft_id, 0, hash_value, NULL, public_key, verify_value, NULL);
            break;
        case HX_SM2_KP:
            build_pub_sm2_msg(req_addr, func_id, HX_SM2_KP, soft_id, 0, NULL, private_key, public_key, NULL, NULL);
            break;
        case HX_SM2_KG:
            build_pub_sm2_msg(req_addr, func_id, HX_SM2_KG, soft_id, 0, NULL, private_key, NULL, NULL, NULL);
            break;
        case HX_SM2_SIGN_TRNG:
            build_pub_sm2_msg(req_addr, func_id, HX_SM2_SIGN_TRNG, soft_id, 0, hash_value, private_key, NULL, NULL, NULL);
            break;
        default:
            printk("build_pub_sm2_data is not supported\n");
            break;
    }

    return 0;
}

int build_pub_rsa_data(void *req_addr, uint8_t rsa_mode, uint32_t soft_id, uint64_t opaque_data)
{
    switch (rsa_mode) {
        case HX_RSA_SIGN_1024:
            build_pub_rsa_msg(req_addr, HX_RSA_SIGN_1024, soft_id, 0, (uint8_t *)rsa_1024, (uint8_t *)d_1024, NULL, (uint8_t *)N_1024, 
                                NULL, NULL, NULL, NULL, NULL);
            break;
        case HX_RSA_SIGN_1024_CRT:
            build_pub_rsa_msg(req_addr, HX_RSA_SIGN_1024_CRT, soft_id, 0, (uint8_t *)rsa_1024, NULL, NULL, NULL, 
                                (uint8_t *)Dp_1024, (uint8_t *)Dq_1024, (uint8_t *)P_1024, (uint8_t *)Q_1024, (uint8_t *)Qinv_1024);
            break;
        case HX_RSA_VERIFY_1024:
            build_pub_rsa_msg(req_addr, HX_RSA_VERIFY_1024, soft_id, 0, (uint8_t *)sign_1024, NULL, (uint8_t *)e_1024, (uint8_t *)N_1024, 
                                NULL, NULL, NULL, NULL, NULL);
            break;
        case HX_RSA_SIGN_2048:
            build_pub_rsa_msg(req_addr, HX_RSA_SIGN_2048, soft_id, 0, (uint8_t *)rsa_2048, (uint8_t *)d_2048, NULL, (uint8_t *)N_2048, 
                                NULL, NULL, NULL, NULL, NULL);
            break;
        case HX_RSA_SIGN_2048_CRT:
            build_pub_rsa_msg(req_addr, HX_RSA_SIGN_2048_CRT, soft_id, 0, (uint8_t *)rsa_2048, NULL, NULL, NULL, 
                                (uint8_t *)Dp_2048, (uint8_t *)Dq_2048, (uint8_t *)P_2048, (uint8_t *)Q_2048, (uint8_t *)Qinv_2048);
            break;
        case HX_RSA_VERIFY_2048:
            build_pub_rsa_msg(req_addr, HX_RSA_VERIFY_2048, soft_id, 0, (uint8_t *)sign_2048, NULL, (uint8_t *)e_2048, (uint8_t *)N_2048, 
                                NULL, NULL, NULL, NULL, NULL);
            break;
        default:
            printk("build_pub_rsa_data is not supported\n");
            break;
    }

    return 0;
}

uint8_t *pub_get_cmp_data(uint8_t func_id, uint8_t mode)
{
    if(func_id == HX_SM2)
    {
        switch (mode) {
        case HX_SM2_SIGN:
            return verify_value;
        case HX_SM2_VERIFY:
            return NULL;
        case HX_SM2_KP:
            return NULL;
        case HX_SM2_KG:
            return NULL;
        case HX_SM2_SIGN_TRNG:
            return NULL;
        default:
            printk("pub_get_cmp_data: mode is not supported\n");
            return NULL;
        }
    }
    else if(func_id == HX_ECC)
    {
        switch (mode) {
        case HX_SM2_SIGN:
            return NULL;
        case HX_SM2_VERIFY:
            return NULL;
        case HX_SM2_KP:
            return NULL;
        case HX_SM2_KG:
            return NULL;
        case HX_SM2_SIGN_TRNG:
            return NULL;
        default:
            printk("pub_get_cmp_data: mode is not supported\n");
            return NULL;
        }
    }
    else if(func_id == HX_RSA)
    {
        switch (mode) {
        case HX_RSA_SIGN_1024:
            return (uint8_t *)sign_1024;
        case HX_RSA_SIGN_1024_CRT:
            return (uint8_t *)sign_crt_1024;
        case HX_RSA_VERIFY_1024:
            return (uint8_t *)rsa_1024;
        case HX_RSA_SIGN_2048:
            return (uint8_t *)sign_2048;
        case HX_RSA_SIGN_2048_CRT:
            return (uint8_t *)sign_crt_2048;
        case HX_RSA_VERIFY_2048:
            return (uint8_t *)rsa_2048;
        default:
            printk("pub_get_cmp_data: mode is not supported\n");
            return NULL;
    }
    }
    else
    {
       printk("pub_get_cmp_data: func_id is not supported\r\n");
       return NULL;
    }
}

int build_pqc_data_test(void *req_addr, uint8_t pqc_mode)
{
#if PQC_DATA    
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            memcpy(req_addr, kyber_keygen_512_in_ref, sizeof(kyber_keygen_512_in_ref));
            break;
        case HX_KYBER512_SIGN:
            memcpy(req_addr, kyber_enc_512_in_ref, sizeof(kyber_enc_512_in_ref));
            break;
        default:
            printk("build_pqc_data_test is not supported\n");
            break;
    }
#endif

    return 0; 
}

int pqc_axi_fifo_write_inref(void *base, uint8_t pqc_mode)
{
    uint32_t *data = NULL;
    uint32_t len = 0;

#if PQC_DATA
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            data = kyber_keygen_512_in_ref;
            len = sizeof(kyber_keygen_512_in_ref);
            break;
        case HX_KYBER512_SIGN:
            data = kyber_enc_512_in_ref;
            len = sizeof(kyber_enc_512_in_ref);
            break;
        case HX_KYBER512_VERIFY:
            data = kyber_dec_512_in_ref;
            len = sizeof(kyber_dec_512_in_ref);
            break;
        case HX_AIGIS_KG:
            data = aigis_keygen_in_ref;
            len = sizeof(aigis_keygen_in_ref);
            break;
        case HX_AIGIS_SIGN:
            data = aigis_enc_in_ref;
            len = sizeof(aigis_enc_in_ref);
            break;
        case HX_AIGIS_VERIFY:
            data = aigis_dec_in_ref;
            len = sizeof(aigis_dec_in_ref);
            break;
        default:
            printk("pqc_axi_fifo_write_in_ref is not supported\n");
            break;
    }
#endif

    pqc_axi_fifo_send(base, PQC_MEM_IN_ADDR, (uint8_t *)data, len);

    return 0;
}

uint8_t *pqc_get_cmp_data(uint8_t pqc_mode)
{
#if PQC_DATA
    switch (pqc_mode) {
        case HX_KYBER512_KG:
            return kyber_keygen_512_out_ref;
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
        default:
            printk("pqc_get_cmp_data: mode is not supported\n");
            return NULL;
    }
#endif

    return NULL;
}

int pub_get_data(uint8_t *resp_addr)
{
    int ret = 0;
    struct pub_head_st *head = (struct pub_head_st *)resp_addr;
    uint8_t *data = resp_addr + sizeof(struct pub_head_st);
    uint8_t *cmp_data = pub_get_cmp_data(head->func_id, head->mode);
    uint32_t len = head->dest_length*PUB_DATA_LEN;

    if(cmp_data)
    {
        if(memcmp(data, cmp_data, len))
        {
            printk("pub_get_data: compare fail, func_id = %d, mode = %d\r\n", head->func_id, head->mode);
            print_hex_dump(KERN_DEBUG, "data:", DUMP_PREFIX_ADDRESS, 16, 4, data, len, false);
            perf_item.packet_error = 1;
            return -1;
        }
        //else
            //printk("pub_get_data: compare succuss\r\n");
    }
    else
    {
        printk("pub_get_data: cmp_data is NULL\r\n");
        return -1;
    }

    return 0;
}

int perf_pub_get_response(ring_handle_t *ring, int pkg_num, int pkg_size, int *msg_count, uint8_t compare)
{
    int ret = 0;
    int pkg = 0;
    int pkg_len = 0;
    int msg_len = 0;
    struct pub_head_st *head = NULL;

    printk("ring->resp_tail = %d\r\n", ring->resp_tail);

    printk("pkg_num = %d, pkg_size = %d\r\n", pkg_num, pkg_size);

    pkg = pkg_num;
    while(pkg--)
    {
        uint8_t *resp_addr = (uint8_t *)(ring->ring_resp_queue_virt_addr + ring->resp_size * ring->resp_tail);

        pkg_len = pkg_size;
        while(pkg_len)
        {
            if(compare == 1)
            {
                ret = pub_get_data(resp_addr);
                if(ret)
                    printk("error: pkg = %d, msg_count = %d\r\n", pkg_num-pkg, *msg_count);
            }
            else if(compare == 2)
            {
                print_hex_dump(KERN_DEBUG, "data:", DUMP_PREFIX_ADDRESS, 16, 4, 
                                resp_addr + PUB_HEAD_LEN, head->dest_length * PUB_DATA_LEN, false);
            }
            else if(compare == 3)
            {
                print_hex_dump(KERN_DEBUG, "data:", DUMP_PREFIX_ADDRESS, 16, 4, resp_addr, 64, false);               
            }
            head = (struct pub_head_st *)resp_addr;
            msg_len = (head->dest_length + 1)*PUB_DATA_LEN;
            pkg_len -= msg_len;           
            resp_addr += msg_len;
            (*msg_count)++;
        }

        ring->resp_tail = (ring->resp_tail + 1) % (ring->ring_queue_size);
    }

    printk("msg_count = %d, func_id = %d, soft_id = %d\r\n", *msg_count, head->func_id, head->soft_id);

    return ret;
}

int perf_pqc_get_response(ring_handle_t *ring, int pkg_num, int pkg_size, int *msg_count, uint8_t compare)
{
    int ret = 0;
    int pkg = 0;
    int pkg_len = 0;
    int msg_len = 0;

    printk("ring->resp_tail = %d\r\n", ring->resp_tail);

    uint8_t *resp_addr = (uint8_t *)(ring->ring_resp_queue_virt_addr + ring->resp_size * ring->resp_tail);
    (*msg_count)++;

    print_hex_dump(KERN_DEBUG, "data:", DUMP_PREFIX_ADDRESS, 16, 4, resp_addr, 64, false); 

    if(pqc_get_cmp_data(1) == NULL)
        return 0;

    pqc_compare_data((int *)resp_addr, (int *)pqc_get_cmp_data(1), get_pqc_res_len(1));

    ring->resp_tail = (ring->resp_tail + 1) % (ring->ring_queue_size);

    return ret;
}

int sm2_request_send(ring_handle_t *ring, void *base, uint8_t func_id, uint8_t sm2_mode, uint32_t pkg_num, uint32_t msg_num)
{
    int ret = 0; 
    uint32_t i = 0, msg = 0, pkg = 0;
    uint8_t *req_addr = NULL;
    uint8_t *msg_addr = NULL;
    uint64_t req_phy_addr = 0;
    static uint32_t id = 1;

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
            build_pub_sm2_data(msg_addr, func_id, sm2_mode, id, 0);
            id++;
            msg_addr += get_sm2_req_len(sm2_mode);
        }
        ring->req_tail++;
    }

    while(HX_REG_READ(base + UPIF_RING_STATE_ADDR) & 0xC00);

    upif_axi_cmd_set(base, HX_FIFO, 0, PUB_OFIFO_ADDR, pkg_num, get_sm2_res_len(sm2_mode)*msg_num, 1);
    upif_axi_cmd_set(base, HX_FIFO, 1, PUB_IFIFO_ADDR, pkg_num, get_sm2_req_len(sm2_mode)*msg_num, 0);

    HX_REG_WRITE(base + UPIF_RING_ADDR_L_ADDR, req_phy_addr & 0xFFFFFFFF);
    HX_REG_WRITE(base + UPIF_RING_ADDR_H_ADDR, (req_phy_addr >> 32) & 0xFFFFFFFF);

    HX_REG_WRITE(base + UPIF_RESPON_PKG_NUM_ADDR, 0x00);
    HX_REG_WRITE(base + UPIF_RING_PKG_ADDR,  (pkg_num<<16)|(get_sm2_req_len(sm2_mode)*msg_num));
    
    wmb();
    HX_REG_WRITE(base + UPIF_RING_START_ADDR, 0x01);
    while(!HX_REG_READ(base + UPIF_RING_START_ADDR));
    HX_REG_WRITE(base + UPIF_RING_START_ADDR, 0x00);

    return ret;
}

int rsa_request_send(ring_handle_t *ring, void *base, uint8_t rsa_mode, uint32_t pkg_num, uint32_t msg_num)
{
    int ret = 0; 
    uint32_t i = 0, msg = 0, pkg = 0;
    uint8_t *req_addr = NULL;
    uint8_t *msg_addr = NULL;
    uint64_t req_phy_addr = 0;
    static uint32_t id = 1;

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
            build_pub_rsa_data(msg_addr, rsa_mode, id, 0);
            id++;
            msg_addr += get_rsa_req_len(rsa_mode);
        }
        ring->req_tail++;
    }

    while(HX_REG_READ(base + UPIF_RING_STATE_ADDR) & 0xC00);

    upif_axi_cmd_set(base, HX_FIFO, 0, PUB_OFIFO_ADDR, pkg_num, get_rsa_res_len(rsa_mode)*msg_num, 1);
    upif_axi_cmd_set(base, HX_FIFO, 1, PUB_IFIFO_ADDR, pkg_num, get_rsa_req_len(rsa_mode)*msg_num, 0);

    HX_REG_WRITE(base + UPIF_RING_ADDR_L_ADDR, req_phy_addr & 0xFFFFFFFF);
    HX_REG_WRITE(base + UPIF_RING_ADDR_H_ADDR, (req_phy_addr >> 32) & 0xFFFFFFFF);

    HX_REG_WRITE(base + UPIF_RESPON_PKG_NUM_ADDR, 0x00);
    HX_REG_WRITE(base + UPIF_RING_PKG_ADDR,  (pkg_num<<16)|(get_rsa_req_len(rsa_mode)*msg_num));
    
    wmb();
    HX_REG_WRITE(base + UPIF_RING_START_ADDR, 0x01);
    while(!HX_REG_READ(base + UPIF_RING_START_ADDR));
    HX_REG_WRITE(base + UPIF_RING_START_ADDR, 0x00);

    return ret;
}

int trng_request_send_test(ring_handle_t *ring, void *base, uint8_t trng_mode, uint32_t pkg_num, uint32_t pkg_len)
{
    int ret = 0; 
    uint32_t i = 0, msg = 0, pkg = 0;
    uint8_t *req_addr = NULL;
    uint8_t *msg_addr = NULL;
    uint64_t req_phy_addr = 0;
    static uint32_t id = 1;

    if(ring->req_tail > ring->ring_queue_size)
        ring->req_tail = 0;

    req_phy_addr = ring->ring_req_queue_phy_addr + ring->message_size*ring->req_tail;

    req_addr = (uint8_t *)(ring->ring_req_queue_virt_addr + ring->message_size*ring->req_tail);
    build_pub_head_msg((struct pub_head_st *)req_addr, HX_PUB, HX_TRNG, HX_TRNG_MODE_1, pkg_num, pkg_len/PUB_DATA_LEN, id, 0); 
    ring->req_tail++;
    id++;

    while(HX_REG_READ(base + UPIF_RING_STATE_ADDR) & 0xC00);

    upif_axi_cmd_set(base, HX_FIFO, 0, PUB_OFIFO_ADDR, pkg_num, pkg_len + PUB_HEAD_LEN, 1);
    upif_axi_cmd_set(base, HX_FIFO, 1, PUB_IFIFO_ADDR, 1, PUB_HEAD_LEN, 0);

    HX_REG_WRITE(base + UPIF_RING_ADDR_L_ADDR, req_phy_addr & 0xFFFFFFFF);
    HX_REG_WRITE(base + UPIF_RING_ADDR_H_ADDR, (req_phy_addr >> 32) & 0xFFFFFFFF);

    HX_REG_WRITE(base + UPIF_RESPON_PKG_NUM_ADDR, 0x00);
    HX_REG_WRITE(base + UPIF_RING_PKG_ADDR,  (1<<16)|(PUB_HEAD_LEN));
    
    wmb();
    HX_REG_WRITE(base + UPIF_RING_START_ADDR, 0x01);
    while(!HX_REG_READ(base + UPIF_RING_START_ADDR));
    HX_REG_WRITE(base + UPIF_RING_START_ADDR, 0x00);

    return ret;
}

int pqc_request_send_test(ring_handle_t *ring, void *base, uint8_t pqc_mode, uint32_t pkg_num, uint32_t msg_num)
{
    int ret = 0; 
    uint32_t i = 0, msg = 0, pkg = 0;
    uint8_t *req_addr = NULL;
    uint8_t *msg_addr = NULL;
    uint64_t req_phy_addr = 0;
    static uint32_t id = 1;

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
            build_pqc_data_test(msg_addr, pqc_mode);
            id++;
            msg_addr += get_pqc_req_len(pqc_mode);
        }
        ring->req_tail++;
    }

    pqc_axi_mem_start(ring, base);

    upif_axi_ring_request(ring, base, 0, HX_MEMORY, 0, PQC_MEM_OUT2_ADDR, 
                            pkg_num, get_pqc_res_len(pqc_mode)*msg_num, 1);

    upif_axi_ring_request(ring, base, req_phy_addr, HX_MEMORY, 1, PQC_MEM_IN_ADDR, 
                            pkg_num, get_pqc_req_len(pqc_mode)*msg_num, 0);

    return ret;
}

int performance_poll_thread(void *param)
{
    hx_ring_handle_t *ring_handle = (hx_ring_handle_t *)param;
    ring_handle_t *ring = &(ring_handle->com_ring);
    volatile uint32_t *resp;
    struct upif_cmd_resp_st *cmd;
    uint32_t id = 0, poll_cnt;
    uint32_t ring_count = 0, poll_count = 0;

    while (id < perf_item.packet_num) {
        ring_count = 0;

        while (1) {

            cmd = (struct upif_cmd_resp_st *)(ring->ring_cmd_resp_queue_virt_addr + 
                                                ring->cmd_resp_size*ring->cmd_resp_tail);
            if(cmd->response == HX_RESP_INIT_CODE)
                break;

            perf_pub_get_response(ring, cmd->pkg_num, cmd->pkg_size, &ring_count, 0);
            //perf_pqc_get_response(ring, cmd->pkg_num, cmd->pkg_size, &ring_count, 0);
            cmd->response = HX_RESP_INIT_CODE;
            ring->cmd_resp_tail = (ring->cmd_resp_tail + 1) % (ring->ring_queue_size);
            poll_count = 0;
        }

        if (ring_count > 0) {
            atomic_sub(ring_count, &ring->in_flight);
            id += ring_count;
        }

        if (poll_count > MAX_POLL_COUNT) {
            printk("cmd->pkg_num = %d\r\n", cmd->pkg_num);
            printk("cmd->pkg_size = %d\r\n", cmd->pkg_size);
            printk("cmd->response = %x\r\n", cmd->response);

            printk("RPU wait Response Message time out [ring->resp_tail:%d]!\n", ring->resp_tail);
            perf_item.packet_error = 1;
            break;
        }

        if (ring_count == 0) {
            usleep_range(500, 500);
            poll_count++;
        }
    }

    perf_item.poll_running = 0;

    return 0;
}

int performance_poll_run(hx_ring_handle_t *ring_handle)
{
    struct task_struct *poll_kthread;

    poll_kthread = kthread_create(performance_poll_thread, ring_handle, "perf pollthread");
    kthread_bind(poll_kthread, 1);
    wake_up_process(poll_kthread);

    return 0;
}

static unsigned long performance_cipher_power(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle, ioctl_performance_test_t *cipher_item)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    dma_addr_t dma_src_addr, dma_dst_addr;
    void *dst_buff_base = NULL, *src_buff_base = NULL;
    uint64_t resp_addr = 0;
    void *base = ring_handle->ptr_base;
    volatile uint32_t *resp;
    struct cipher_req_st *req = NULL;
    void *alloc_dev = NULL;
    uint32_t dst_len, total_src_len;
    uint32_t id = 0;

#if PCIE_ENABLE
    alloc_dev = accel_dev->accel_pci.pci_dev;
#else
    alloc_dev = &accel_dev->platform_dev->dev;
#endif

    src_buff_base = (uint8_t *)hx_dma_alloc_consistent(alloc_dev, 8192, &dma_src_addr);
    if (IS_ERR(src_buff_base)) {
        printk("%d:Malloc Src Buffer Fail\n", __LINE__);
        return -1;
    }
    memset(src_buff_base, 0xAA, 8192);

    dst_buff_base = (uint8_t *)hx_dma_alloc_consistent(alloc_dev, 8192, &dma_dst_addr);
    if (IS_ERR(dst_buff_base)) {
        printk("%d:Malloc Dst Buffer Fail\n", __LINE__);
        return -1;
    }
    memset(dst_buff_base, 0x0, 8192);

    printk("cipher_item->alg_mode = %d\n", cipher_item->alg_mode);

    switch (cipher_item->alg_mode) {
    case HX_CIPHER_ECB:
        memcpy(src_buff_base, cipher_aes_key, cipher_item->keylen);
        total_src_len = cipher_item->keylen + cipher_item->srclen;
        break;
    case HX_CIPHER_CBC:
    case HX_CIPHER_CFB:
    case HX_CIPHER_OFB:
    case HX_CIPHER_CTR:
    case HX_CIPHER_XTS:
        memcpy(src_buff_base, cipher_aes_key, cipher_item->keylen);
        memcpy(src_buff_base + cipher_item->keylen, cipher_aes_iv, cipher_item->ivlen);
        total_src_len = cipher_item->keylen + cipher_item->ivlen + cipher_item->srclen;
        break;
    default:
        printk("current cipher mode is not supported\n");
        return -1;
    }

    printk("cipher_item->packet_num = %d\n", cipher_item->packet_num);

    memset(&perf_item, 0x0, sizeof(perf_item));
    perf_item.packet_num = cipher_item->packet_num;

    atomic_set(&ring->in_flight, 0);

    performance_poll_run(ring_handle);

    while ((id < perf_item.packet_num) && (perf_item.packet_error == 0)) {
        if (atomic_read(&ring->in_flight) >= ring->max_flight) {
            usleep_range(10, 10);
            continue;
        }

        req = (struct cipher_req_st *)(ring->ring_req_queue_virt_addr + ring->message_size * ring->req_tail);
        memset(req, 0, ring->message_size);

        resp_addr = ring->ring_resp_queue_phy_addr + ring->req_tail * ring->resp_size;
        req->res_addr_l = (uint32_t)(resp_addr & 0xffffffff);
        req->res_addr_h = (uint32_t)((resp_addr >> 32) & 0xffffffff);

        resp = (uint32_t *)(ring->ring_resp_queue_virt_addr + ring->req_tail * ring->resp_size);
        *resp = HX_RESP_INIT_CODE;

        req->service_cmd_id = cipher_item->algo_id;
        req->service_type = ((cipher_item->algo_dir << 7) | cipher_item->alg_mode);
        req->hdr_flags = 0x80;
        req->key_length = cipher_item->keylen;
        req->iv_length = cipher_item->ivlen;
        req->padding = HX_PACKAGE_COMPLETE;

        if (cipher_item->alg_mode == HX_CIPHER_CCM || cipher_item->alg_mode == HX_CIPHER_GCM) {
            req->tag_lenth = cipher_item->taglen;
            req->aad_lenth = 16;
            req->cur_pkg_byte_pos = 0;
        }

        req->src_addr_l = (uint32_t)((uint64_t)dma_src_addr);
        req->src_addr_h = (uint32_t)((uint64_t)dma_src_addr >> 32);

        req->dst_addr_l = (uint32_t)((uint64_t)dma_dst_addr);
        req->dst_addr_h = (uint32_t)((uint64_t)dma_dst_addr >> 32);

        req->src_len = total_src_len;

        dst_len = cipher_item->dstlen;
        if (cipher_item->alg_mode == HX_CIPHER_CCM || cipher_item->alg_mode == HX_CIPHER_GCM)
            dst_len = dst_len + 16;

        req->dst_len = dst_len;
        req->total_len = cipher_item->srclen;

        ring->req_tail = (ring->req_tail + 1) % (ring->ring_queue_size);

        wmb();
        HX_REG_WRITE(base + NPUB_RING_PLUS(ring_handle->ring_id), 1);
        atomic_inc(&ring->in_flight);
        id++;
    }

    while (perf_item.poll_running == 1)
        usleep_range(100, 100);

    hx_dma_free_consistent(alloc_dev, 8192, src_buff_base, dma_src_addr);
    hx_dma_free_consistent(alloc_dev, 8192, dst_buff_base, dma_dst_addr);

    return 0;
}

static unsigned long performance_sm2_power(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle, ioctl_performance_test_t *cipher_item)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    dma_addr_t dma_src_addr, dma_dst_addr;
    void *dst_buff_base = NULL, *src_buff_base = NULL;
    uint64_t resp_addr = 0;
    void *base = ring_handle->ptr_base;
    volatile uint32_t *resp;
    void *alloc_dev = NULL;
    struct upif_cmd_resp_st *cmd = NULL;
    uint32_t dst_len, total_src_len;
    uint32_t msg_total_num = cipher_item->packet_num;
    uint32_t pkg_num = 0;
    uint32_t msg_num = 0;
    uint32_t msg_num_last = 0;
    uint32_t pkg_count = 0;
    uint32_t pkg = 0;
    uint32_t i = 0;
    uint8_t func_id = cipher_item->algo_id;
    uint8_t sm2_mode = cipher_item->alg_mode;
    uint8_t msg_max_num = get_sm2_max_msg_num(sm2_mode);

    alloc_dev = accel_dev->accel_pci.pci_dev;

    printk("\r\n");
    printk("func id = %d\r\n", func_id);
    printk("sm2 mode = %d\r\n", sm2_mode);
    printk("msg_max_num = %d\r\n", msg_max_num);
    
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

    printk("msg_total_num = %d\r\n", msg_total_num);
    printk("pkg_num = %d\r\n", pkg_num);
    printk("msg_num_last = %d\r\n", msg_num_last);
    
    memset(&perf_item, 0x0, sizeof(perf_item));
    perf_item.packet_num = cipher_item->packet_num;

    atomic_set(&ring->in_flight, 0);

    perf_item.poll_running = 1;
    performance_poll_run(ring_handle);

    pkg_count = pkg_num;
    while(pkg_count)
    {
        pkg = pkg_count < PUB_MAX_PKG_NUM ? pkg_count : PUB_MAX_PKG_NUM;
        sm2_request_send(ring, base, func_id, sm2_mode, pkg, msg_num);
        printk("pkg = %d\r\n", pkg);
        pkg_count -= pkg;
    }
    
    if(msg_num_last)
        sm2_request_send(ring, base, func_id, sm2_mode, 1, msg_num_last);

    while (perf_item.poll_running == 1)
        usleep_range(500, 500);

    return 0;
}

static unsigned long performance_rsa_power(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle, ioctl_performance_test_t *cipher_item)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    dma_addr_t dma_src_addr, dma_dst_addr;
    void *dst_buff_base = NULL, *src_buff_base = NULL;
    uint64_t resp_addr = 0;
    void *base = ring_handle->ptr_base;
    volatile uint32_t *resp;
    void *alloc_dev = NULL;
    struct upif_cmd_resp_st *cmd = NULL;
    uint32_t dst_len, total_src_len;
    uint32_t msg_total_num = cipher_item->packet_num;
    uint32_t pkg_num = 0;
    uint32_t msg_num = 0;
    uint32_t msg_num_last = 0;
    uint32_t pkg_count = 0;
    uint32_t pkg = 0;
    uint32_t i = 0;
    uint8_t func_id = cipher_item->algo_id;
    uint8_t rsa_mode = cipher_item->alg_mode;
    uint8_t msg_max_num = get_rsa_max_msg_num(rsa_mode);
    int ret = 0;

    alloc_dev = accel_dev->accel_pci.pci_dev;

    printk("\r\n");
    printk("func id = %d\r\n", func_id);
    printk("rsa mode = %d\r\n", rsa_mode);
    printk("msg_max_num = %d\r\n", msg_max_num);

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

    printk("msg_total_num = %d\r\n", msg_total_num);
    printk("pkg_num = %d\r\n", pkg_num);
    printk("msg_num_last = %d\r\n", msg_num_last);
    
    memset(&perf_item, 0x0, sizeof(perf_item));
    perf_item.packet_num = cipher_item->packet_num;

    atomic_set(&ring->in_flight, 0);

    perf_item.poll_running = 1;
    performance_poll_run(ring_handle);

    pkg_count = pkg_num;
    while(pkg_count)
    {
        pkg = pkg_count < PUB_MAX_PKG_NUM ? pkg_count : PUB_MAX_PKG_NUM;
        rsa_request_send(ring, base, rsa_mode, pkg, msg_num);
        printk("pkg = %d\r\n", pkg);
        pkg_count -= pkg;
    }
    
    if(msg_num_last)
        rsa_request_send(ring, base, rsa_mode, 1, msg_num_last);

    while (perf_item.poll_running == 1)
        usleep_range(500, 500);

    if(perf_item.packet_error == 1)
        ret = -1;

    return ret;
}

static unsigned long performance_trng_power(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle, ioctl_performance_test_t *cipher_item)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    dma_addr_t dma_src_addr, dma_dst_addr;
    void *dst_buff_base = NULL, *src_buff_base = NULL;
    uint64_t resp_addr = 0;
    void *base = ring_handle->ptr_base;
    volatile uint32_t *resp;
    void *alloc_dev = NULL;
    struct upif_cmd_resp_st *cmd = NULL;
    uint32_t pkg_num = cipher_item->packet_num;
    uint32_t pkg_len = 2032;
    uint8_t func_id = cipher_item->algo_id;
    uint8_t trng_mode = cipher_item->alg_mode;
    int i = 0;
    int ret = 0;

    alloc_dev = accel_dev->accel_pci.pci_dev;

    printk("\r\n");
    printk("func id = %d\r\n", func_id);
    printk("trng mode = %d\r\n", trng_mode);
    
    memset(&perf_item, 0x0, sizeof(perf_item));
    perf_item.packet_num = cipher_item->packet_num;

    atomic_set(&ring->in_flight, 0);

    perf_item.poll_running = 1;
    performance_poll_run(ring_handle);

    trng_request_send_test(ring, base, trng_mode, pkg_num, pkg_len);

    while (perf_item.poll_running == 1)
        usleep_range(500, 500);

    if(perf_item.packet_error == 1)
        ret = -1;

    return ret;
}

static unsigned long performance_pqc_power(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle, ioctl_performance_test_t *cipher_item)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    dma_addr_t dma_src_addr, dma_dst_addr;
    void *dst_buff_base = NULL, *src_buff_base = NULL;
    uint64_t resp_addr = 0;
    void *base = ring_handle->ptr_base;
    volatile uint32_t *resp;
    void *alloc_dev = NULL;
    struct upif_cmd_resp_st *cmd = NULL;
    uint32_t dst_len, total_src_len;
    uint32_t msg_total_num = cipher_item->packet_num;
    uint32_t pkg_num = 0;
    uint32_t msg_num = 0;
    uint32_t msg_num_last = 0;
    uint32_t pkg_count = 0;
    uint32_t pkg = 0;
    uint32_t i = 0;
    uint8_t func_id = cipher_item->algo_id;
    uint8_t pqc_mode = cipher_item->alg_mode;

    alloc_dev = accel_dev->accel_pci.pci_dev;

    printk("\r\n");
    printk("func id = %d\r\n", func_id);
    printk("pqc mode = %d\r\n", pqc_mode);
    
    memset(&perf_item, 0x0, sizeof(perf_item));
    perf_item.packet_num = cipher_item->packet_num;

    atomic_set(&ring->in_flight, 0);

    perf_item.poll_running = 1;
    performance_poll_run(ring_handle);

    pqc_config_data_init(ring, base, HX_AXI_RING_BUS, pqc_mode);

    pqc_request_send_test(ring, base, pqc_mode, 1, 1);

    while (perf_item.poll_running == 1)
        usleep_range(500, 500);

    return 0;
}

static unsigned long performance_pqc_axi_power(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle, ioctl_performance_test_t *cipher_item)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    void *base = ring_handle->ptr_base;
    uint32_t msg_total_num = cipher_item->packet_num;
    uint32_t pkg_num = 0;
    uint32_t msg_num = 0;
    uint32_t msg_num_last = 0;
    uint32_t pkg_count = 0;
    uint32_t pkg = 0;
    uint32_t i = 0;
    uint8_t func_id = cipher_item->algo_id;
    uint8_t pqc_mode = cipher_item->alg_mode;
    uint8_t *resp_addr = (uint8_t *)(ring->ring_resp_queue_virt_addr + ring->resp_size * ring->resp_tail);
    
    printk("\r\n");
    printk("func id = %d\r\n", func_id);
    printk("pqc mode = %d\r\n", pqc_mode);
    
    memset(&perf_item, 0x0, sizeof(perf_item));
    perf_item.packet_num = cipher_item->packet_num;

    atomic_set(&ring->in_flight, 0);

    pqc_config_data_init(ring, base, HX_AXI_REG_BUS, pqc_mode);

    pqc_axi_fifo_write_inref(base, pqc_mode);

    pqc_axi_fifo_start(base);

    upif_axi_cmd_set(base, HX_MEMORY, 0, get_pqc_mem_out_address(pqc_mode), 1, get_pqc_res_len(pqc_mode), 1);

    upif_wait_response(base, 2);

    memcpy(pqc_result, resp_addr, get_pqc_res_len(pqc_mode));
    ring->resp_tail = (ring->resp_tail + 1) % (ring->ring_queue_size);
    printk("upif read data success\r\n");

    print_hex_dump(KERN_DEBUG, "data:", DUMP_PREFIX_ADDRESS, 16, 4, pqc_result, 64, false);

    if(pqc_get_cmp_data(pqc_mode) == NULL)
        return 0;

    pqc_compare_data(pqc_result, (int *)pqc_get_cmp_data(pqc_mode), get_pqc_res_len(pqc_mode));

    return 0;
}

static unsigned long performance_pqc_fifo_power(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle, ioctl_performance_test_t *cipher_item)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    dma_addr_t dma_src_addr, dma_dst_addr;
    void *dst_buff_base = NULL, *src_buff_base = NULL;
    uint64_t resp_addr = 0;
    void *base = ring_handle->ptr_base;
    void *alloc_dev = NULL;
    struct upif_cmd_resp_st *cmd = NULL;
    uint32_t pkg_num = cipher_item->packet_num;
    uint32_t pkg_len = 128;
    uint8_t func_id = cipher_item->algo_id;
    uint8_t pqc_mode = cipher_item->alg_mode;
    int i = 0;
    int ret = 0;
    unsigned int resp;
    unsigned int wait_count = 0;

    alloc_dev = accel_dev->accel_pci.pci_dev;

    printk("\r\n");
    printk("func id = %d\r\n", func_id);
    printk("pqc mode = %d\r\n", pqc_mode);
    
    pqc_config_data_init(ring, base, HX_FIFO_REG_BUS, pqc_mode);
    pqc_fifo_write_send(base, (uint8_t *)kyber_keygen_512_in_ref, sizeof(kyber_keygen_512_in_ref), PQC_KYBER512_KEY_LEN);
    pqc_fifo_read_cmd_send(base, PQC_KYBER512_KEY_LEN + PQC_HEAD_LEN);

    while(1)
    {
        resp = HX_REG_READ(base + UPIF_RESPON_PKG_NUM_ADDR);
        if((resp&0xffffffff) == 4)
        {   
            HX_REG_WRITE(base + UPIF_RESPON_PKG_NUM_ADDR, 0x00);
            printk("upif resp success\n");
            break;
        }
        
        if(wait_count++ > 1000)
        {
            printk("upif wait time out, resp = %d\r\n", resp);
            break;
        }
        usleep_range(1000, 1000);
    }

    memcpy(pqc_result, ring->ring_resp_queue_virt_addr, PQC_KYBER512_SK_LEN+16);
    printk("upif read data success\r\n");

    if(memcmp(&pqc_result[4], kyber_keygen_512_out_ref, PQC_KYBER512_SK_LEN) == 0)
        printk("upif compare succuss\r\n");
    else
        printk("upif compare fail\r\n");

    return ret;
}

ssize_t hx_performance_main(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle,
                            ioctl_performance_test_t *algo_item)
{
    int ret = 0;
    uint64_t start_time, end_time, used_time;

    start_time = ktime_get_real_ns();

    switch (algo_item->algo_id) {
    case HX_ALGO_SM2:
    case HX_ALGO_ECC:
        ret = performance_sm2_power(accel_dev, ring_handle, algo_item);
        break;
    case HX_ALGO_RSA:
        ret = performance_rsa_power(accel_dev, ring_handle, algo_item);
        break;
    case HX_ALGO_TRNG:
        ret = performance_trng_power(accel_dev, ring_handle, algo_item);
        break;
    case HX_ALGO_PQC:
        //ret = performance_pqc_power(accel_dev, ring_handle, algo_item);
        //ret = performance_pqc_axi_power(accel_dev, ring_handle, algo_item);
        ret = performance_pqc_fifo_power(accel_dev, ring_handle, algo_item);
        break;
    default:
        printk("performance_main algo id unusing\n");
        break;
    }

    end_time = ktime_get_real_ns();
    used_time = (end_time - start_time) / (uint64_t)1000UL;
    printk("used_time = %d\r\n", used_time);
    algo_item->used_time_us = used_time;

    return ret;
}