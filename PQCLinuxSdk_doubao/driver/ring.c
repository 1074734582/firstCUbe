#include <linux/delay.h>
#include <linux/err.h>
#include <linux/eventfd.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/platform_device.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/kfifo.h>

#include "algo.h"
#include "common.h"
#include "debug.h"
#include "ring.h"

#define RING_CNT_DEBUG 0

#define CTX_MAX_NUM 50

int g_rpu_ring_num = RPU_TOTAL_RING_NUM;
int g_rpu_ring_process = RPU_TOTAL_VALID_NUM;

uint8_t rpu_reg_write_error = 0;
static atomic_t hx_algo_timeout_cnt;

atomic_t dequeue_runing; // all device share one dequeue

LIST_HEAD(ctx_head);
struct mutex ctx_lock;

list_ctx_t *ctx_node[CTX_MAX_NUM];

DEFINE_KFIFO(cb_fifo, void *, HX_COOKIE_FIFO_COUNT);

hx_wait_t *dequeue_wait = NULL;

struct reserve_s {
    int size;
    void *virt;
    uint64_t phy;
};

void hx_ctr32_inc(unsigned char *counter, int inc)
{
    uint32_t n = 4, c = inc;

    do {
        --n;
        c += counter[n];
        counter[n] = (uint8_t)c;
        c >>= 8;
    } while (n);
}

#define SWAP(a, b)    \
    {                 \
        uint8_t temp; \
        temp = a;     \
        a = b;        \
        b = temp;     \
    }
void swap_word_data(uint8_t *data, uint32_t len)
{
    int i = 0;
    if (len % 4 != 0)
        return;

    for (i = 0; i < len; i += 4) {
        SWAP(data[i], data[i + 3]);
        SWAP(data[i + 1], data[i + 2]);
    }
}

int pub_queue_recieve(hx_ring_handle_t *ring_handle, cb_data_t *cb_data)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    void *base = ring_handle->ptr_base;

    kfifo_put(&cb_fifo, cb_data);

    pqc_config_data_init(ring, base, HX_FIFO_RING_BUS, cb_data->mode);

    pqc_fifo_response_transmit(ring, base, cb_data->dst_len + PQC_HEAD_LEN);

    pqc_fifo_request_transmit(ring, base, cb_data->mode, KERNEL_DATA, cb_data->src_virt, cb_data->src_len, cb_data->dst_len);

    atomic_inc(&ring->in_flight);

    LOG_DEBUG("pqc send, pkg_id = %d\n", cb_data->pkg_id);

    return 0;
}

int dequeue_pending_request(session_t *ctx)
{
    request_node_t *req_node = NULL;
    hx_ring_handle_t *ring_handle = ctx->ring_handle;
    ring_handle_t *ring = &(ring_handle->com_ring);
    int ret = 0;

    if (ring_handle == NULL)
        return HX_RET_FAILED;

    if (ring->time_out)
        return HX_RET_TIMEOUT;

    mutex_lock(&ctx->request_queue_lock);

    while (ctx->request_queue_head != NULL) {
        //LOG_DEBUG("dequeue request\n");
        req_node = ctx->request_queue_head;

        pub_queue_recieve(ring_handle, (cb_data_t *)req_node->req_handle);

        ctx->request_queue_head = ctx->request_queue_head->next;
        kfree(req_node);
    }

    if (ctx->request_queue_head == NULL)
        ctx->request_queue_tail = NULL;

    mutex_unlock(&ctx->request_queue_lock);

    return ret;
}

void pub_callback_func(uint8_t *resp)
{
    int ret = 0;
    struct pub_head_st *head = (struct pub_head_st *)resp;
    cb_data_t *cb_data = get_opdata_from_resp(head);

    switch (head->func_id) {
    case HX_ALGO_SM2:
    case HX_ALGO_ECC:{
        hx_sm2_result_t *sm2_res = (hx_sm2_result_t *)(cb_data->kernel_dst);
        sm2_res->data[sm2_res->index].id = head->soft_id;

        //printk("id = %d\r\n", head->soft_id);
        //print_hex_dump(KERN_DEBUG, "data:", DUMP_PREFIX_ADDRESS, 16, 1, resp + sizeof(struct pub_head_st), 64, false);

        memcpy(&sm2_res->data[sm2_res->index].output, resp + sizeof(struct pub_head_st), 
                head->dest_length*PUB_DATA_LEN);

        sm2_res->index++;
        cb_data->msg_num = sm2_res->size;
        cb_data->msg_index = sm2_res->index;
        }
        break;
    case HX_ALGO_RSA:{
        hx_rsa_result_t *rsa_res = (hx_rsa_result_t *)(cb_data->kernel_dst);
        rsa_res->data[rsa_res->index].id = head->soft_id;

        //printk("id = %d\r\n", head->soft_id);
        //print_hex_dump(KERN_DEBUG, "data:", DUMP_PREFIX_ADDRESS, 16, 1, resp + sizeof(struct pub_head_st), 64, false);

        memcpy(&rsa_res->data[rsa_res->index].output, resp + sizeof(struct pub_head_st), 
                head->dest_length*PUB_DATA_LEN);

        rsa_res->index++;
        cb_data->msg_num = rsa_res->size;
        cb_data->msg_index = rsa_res->index;
        }
        break;
    case HX_ALGO_TRNG:{
        memcpy(cb_data->kernel_dst, resp + sizeof(struct pub_head_st), head->dest_length*PUB_DATA_LEN);

        //print_hex_dump(KERN_DEBUG, "data:", DUMP_PREFIX_ADDRESS, 16, 1, resp + sizeof(struct pub_head_st), 64, false);
        }
        break;
    }
}

int pub_get_response(ring_handle_t *ring, int pkg_num, int pkg_size, cb_data_t **cb_data)
{
    int ret = 0;
    int pkg = 0;
    int pkg_len = 0;
    int msg_len = 0;
    struct pub_head_st *head = NULL;

    LOG_DEBUG("ring->resp_tail = %d\r\n", ring->resp_tail);

    pkg = pkg_num;
    while(pkg--)
    {
        uint8_t *resp_addr = (uint8_t *)(ring->ring_resp_queue_virt_addr + ring->resp_size * ring->resp_tail);

        pkg_len = pkg_size;
        while(pkg_len)
        { 
            head = (struct pub_head_st *)resp_addr;
            if((head->soft_id >> 24) != HX_ID_MAGIC_CODE)
            {
                printk("soft id check error\r\n");
                print_hex_dump(KERN_DEBUG, "head:", DUMP_PREFIX_ADDRESS, 16, 4, head, 16, false);
                return HX_RET_FAILED;
            }
            pub_callback_func(resp_addr);
            msg_len = (head->dest_length + 1)*PUB_DATA_LEN;
            pkg_len -= msg_len;           
            resp_addr += msg_len;
        }

        ring->resp_tail = (ring->resp_tail + 1) % (ring->ring_queue_size);
    }

    *cb_data = get_opdata_from_resp(head);

    return ret;
}

void pqc_callback_func(uint8_t *resp, cb_data_t *cb_data, int pkg_size)
{
    print_hex_dump(KERN_DEBUG, "resp:", DUMP_PREFIX_ADDRESS, 16, 4, resp, 64, false);

    printk("cb_data->algo = %d\r\n", cb_data->algo);
    printk("cb_data->mode = %d\r\n", cb_data->mode);

    memcpy(cb_data->kernel_dst + cb_data->dst_index, resp, pkg_size);
}

int pqc_get_response(ring_handle_t *ring, int pkg_num, int pkg_size, cb_data_t *cb)
{
    int ret = 0;
    int pkg = 0;
    int pkg_len = 0;
    int msg_len = 0;
    uint8_t *resp_addr = NULL;
    struct pqc_request_st *request = NULL;

    LOG_DEBUG("ring->resp_tail = %d\r\n", ring->resp_tail);
    LOG_DEBUG("pkg_num = %d\r\n", pkg_num);
    LOG_DEBUG("pkg_size = %d\r\n", pkg_size);

    resp_addr = (uint8_t *)(ring->ring_resp_queue_virt_addr + ring->resp_size * ring->resp_tail);

    LOG_DEBUG("cb->algo = %d\r\n", cb->algo);
    LOG_DEBUG("cb->mode = %d\r\n", cb->mode);
    //print_hex_dump(KERN_DEBUG, "resp:", DUMP_PREFIX_ADDRESS, 16, 4, resp_addr, 64, false);

    pkg = pkg_num;
    while(pkg--)
        ring->resp_tail = (ring->resp_tail + 1) % (ring->ring_queue_size);

    request = (struct pqc_request_st *)resp_addr;
    if(request->head == PQC_MAGIC_NUM)
    {
        memcpy(cb->kernel_dst + cb->dst_index, resp_addr + PQC_HEAD_LEN, pkg_size*pkg_num - PQC_HEAD_LEN);
        cb->dst_index += (pkg_size*pkg_num - PQC_HEAD_LEN);
    }
    else
    {
        memcpy(cb->kernel_dst + cb->dst_index, resp_addr, pkg_size*pkg_num);
        cb->dst_index += pkg_size*pkg_num;
    }

    return ret;
}

int hx_init_bulk_ring(struct hx_accel_dev *accel_dev, int ring_id, hx_ring_handle_t **bulk_ring)
{
    uint32_t size_temp = 0;
    uint64_t phy_temp = 0;
    int i = 0;
    struct reserve_s *reserve_addr = NULL;
    struct reserve_s *ra = NULL;
    dma_addr_t dma_handle;
    hx_op_cookie_t *op_cookies;
    hx_ring_handle_t *ring_handle = NULL;
    void *bar_base = NULL;
    void *alloc_dev = NULL;
    struct upif_cmd_resp_st *cmd = NULL;

#if PCIE_ENABLE
    bar_base = accel_dev->accel_pci.bars[0].virt_addr;
    alloc_dev = accel_dev->accel_pci.pci_dev;
#else
    //Just for test, need change to SOC AMBA base address
    bar_base = kzalloc(NPUB_RING_REG_SIZE * RPU_TOTAL_RING_NUM, GFP_KERNEL);
    alloc_dev = &accel_dev->platform_dev->dev;
#endif

    // init ring
    ring_handle = kzalloc(sizeof(hx_ring_handle_t), GFP_KERNEL);
    if (ring_handle == NULL) {
        LOG_ERROR("bulk_ring vmalloc failed! \n");
        goto err;
    }

    ring_handle->ptr_base = bar_base;
    ring_handle->ring_id = ring_id;
    ring_handle->status = 0;

    ring_handle->com_ring.ring_queue_size = (HX_BULK_RING_QUEUE_DEPTH);
    ring_handle->com_ring.message_size = HX_REQ_SIZE;
    ring_handle->com_ring.resp_size = HX_RESP_SIZE;
    ring_handle->com_ring.cmd_resp_size = HX_CMD_RESP_SIZE;
    ring_handle->com_ring.cmd_req_size = HX_CMD_REQ_SIZE;

    ring_handle->com_ring.max_flight = ring_handle->com_ring.ring_queue_size;
    atomic_set(&ring_handle->com_ring.in_flight, 0);
    //ring_handle->com_ring.callback = ring_callback_func;

    mutex_init(&ring_handle->com_ring.req_lock);
    ring_handle->com_ring.req_head = 0;
    ring_handle->com_ring.req_tail = 0;

    mutex_init(&ring_handle->com_ring.resp_lock);
    ring_handle->com_ring.resp_head = 0;
    ring_handle->com_ring.resp_tail = 0;

    mutex_init(&ring_handle->com_ring.cmd_resp_lock);
    ring_handle->com_ring.cmd_resp_head = 0;
    ring_handle->com_ring.cmd_resp_tail = 0;

    mutex_init(&ring_handle->com_ring.cmd_req_lock);
    ring_handle->com_ring.cmd_req_head = 0;
    ring_handle->com_ring.cmd_req_tail = 0;

    ring_handle->com_ring.rd_cmd_id = 0;
    ring_handle->com_ring.cb_data = NULL;

    mutex_init(&ring_handle->com_ring.list_lock);
    mutex_init(&ring_handle->com_ring.list_p_lock);
    spin_lock_init(&ring_handle->com_ring.list_spin_p_lock);
    INIT_LIST_HEAD(&ring_handle->com_ring.pkg_head);
    atomic_set(&ring_handle->com_ring.list_node_num, 0);

    mutex_init(&ring_handle->com_ring.s_list_lock);
    INIT_LIST_HEAD(&ring_handle->com_ring.s_pkg_head);
    atomic_set(&ring_handle->com_ring.s_list_node_num, 0);

    ring_handle->com_ring.ring_req_queue_virt_addr = hx_dma_alloc_consistent(alloc_dev,
                                                                             ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.message_size,
                                                                             &dma_handle);
    ring_handle->com_ring.ring_req_queue_phy_addr = dma_handle;
    if (ring_handle->com_ring.ring_req_queue_virt_addr == NULL) {
        LOG_ERROR(">>> ring_id = %d , alloc ring_req_queue_virt_addr error !\n", ring_id);
        goto err;
    }

    ring_handle->com_ring.ring_resp_queue_virt_addr = hx_dma_alloc_consistent(alloc_dev,
                                                                              ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.resp_size,
                                                                              &dma_handle);
    ring_handle->com_ring.ring_resp_queue_phy_addr = dma_handle;
    if (ring_handle->com_ring.ring_resp_queue_virt_addr == NULL) {
        LOG_ERROR(">>> ring_id = %d , alloc ring_resp_queue_virt_addr error !\n", ring_id);
        goto err;
    }

    ring_handle->com_ring.ring_cmd_req_queue_virt_addr = hx_dma_alloc_consistent(alloc_dev,
                                                                              ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.cmd_req_size,
                                                                              &dma_handle);
    ring_handle->com_ring.ring_cmd_req_queue_phy_addr = dma_handle;
    if (ring_handle->com_ring.ring_cmd_req_queue_virt_addr == NULL) {
        LOG_ERROR(">>> ring_id = %d , alloc ring_cmd_req_queue_virt_addr error !\n", ring_id);
        goto err;
    }

    ring_handle->com_ring.ring_cmd_resp_queue_virt_addr = hx_dma_alloc_consistent(alloc_dev,
                                                                              ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.cmd_resp_size,
                                                                              &dma_handle);
    ring_handle->com_ring.ring_cmd_resp_queue_phy_addr = dma_handle;
    if (ring_handle->com_ring.ring_cmd_resp_queue_virt_addr == NULL) {
        LOG_ERROR(">>> ring_id = %d , alloc ring_cmd_resp_queue_virt_addr error !\n", ring_id);
        goto err;
    }

    LOG_DEBUG("ring_id = %d\n", ring_id);
    LOG_DEBUG("ring_handle->com_ring.ring_req_queue_virt_addr = %p (0x%x)\n", ring_handle->com_ring.ring_req_queue_virt_addr, ring_handle->com_ring.ring_req_queue_phy_addr);
    LOG_DEBUG("ring_handle->com_ring.ring_resp_queue_virt_addr = %p (0x%x)\n", ring_handle->com_ring.ring_resp_queue_virt_addr, ring_handle->com_ring.ring_resp_queue_phy_addr);
    LOG_DEBUG("ring_handle->com_ring.ring_cmd_resp_queue_virt_addr = %p (0x%x)\n", ring_handle->com_ring.ring_cmd_resp_queue_virt_addr, ring_handle->com_ring.ring_cmd_resp_queue_phy_addr);

    //enable upif
    //HX_REG_WRITE(bar_base + UPIF_CTRL_REG_ADDR, 0x03);
    HX_REG_WRITE(bar_base + UPIF_CTRL_REG_ADDR, (HX_BULK_RING_QUEUE_DEPTH<<2) | 0x03);
    HX_REG_WRITE(bar_base + UPIF_TX_CFG_ADDR, (HX_BULK_RING_QUEUE_DEPTH<<16) | 0x04<<8 | 0x0F);

    //enable command request
#if UPIF_CMD_REQ    
    HX_REG_WRITE(bar_base + UPIF_CMD_REQ_MODE_CTR, (HX_BULK_RING_QUEUE_DEPTH<<16) | 0x01);
#endif    

    //config response address
    HX_REG_WRITE(bar_base + UPIF_RESP_ADDR_L_ADDR, ring_handle->com_ring.ring_resp_queue_phy_addr & 0xFFFFFFFF);
    HX_REG_WRITE(bar_base + UPIF_RESP_ADDR_H_ADDR, (ring_handle->com_ring.ring_resp_queue_phy_addr >> 32) & 0xFFFFFFFF);

    //config request address
    HX_REG_WRITE(bar_base + UPIF_RING_ADDR_L_ADDR, ring_handle->com_ring.ring_req_queue_phy_addr & 0xFFFFFFFF);
    HX_REG_WRITE(bar_base + UPIF_RING_ADDR_H_ADDR, (ring_handle->com_ring.ring_req_queue_phy_addr >> 32) & 0xFFFFFFFF);

    //config command response address
    HX_REG_WRITE(bar_base + UPIF_CMD_RESP_ADDR_L_ADDR, ring_handle->com_ring.ring_cmd_resp_queue_phy_addr & 0xFFFFFFFF);
    HX_REG_WRITE(bar_base + UPIF_CMD_RESP_ADDR_H_ADDR, (ring_handle->com_ring.ring_cmd_resp_queue_phy_addr >> 32) & 0xFFFFFFFF);

    //config command request address
    HX_REG_WRITE(bar_base + UPIF_CMD_REQ_ADDR_L_ADDR, ring_handle->com_ring.ring_cmd_req_queue_phy_addr & 0xFFFFFFFF);
    HX_REG_WRITE(bar_base + UPIF_CMD_REQ_ADDR_H_ADDR, (ring_handle->com_ring.ring_cmd_req_queue_phy_addr >> 32) & 0xFFFFFFFF);


    //clear package number
    HX_REG_WRITE(bar_base + UPIF_RESPON_PKG_NUM_ADDR, 0x00);

    for(i=0; i< ring_handle->com_ring.ring_queue_size; i++)
    {
        cmd = (struct upif_cmd_resp_st *)(ring_handle->com_ring.ring_cmd_resp_queue_virt_addr + ring_handle->com_ring.cmd_resp_size*i);
        cmd->response = HX_RESP_INIT_CODE;
    }

    ring_handle->accel_dev = accel_dev;

    // cookie set
    op_cookies = &ring_handle->com_ring.op_cookies;
    op_cookies->count = HX_COOKIE_QUEUE_COUNT;
    op_cookies->size = HX_COOKIE_SIZE_BULK;
    op_cookies->offset = 0;
    spin_lock_init(&op_cookies->lock);
    op_cookies->cookies = vmalloc(sizeof(hx_cookies_t) * op_cookies->count);
    if (op_cookies->cookies == NULL) {
        LOG_ERROR("op_cookies->cookies vmalloc failed! \n");
        goto err;
    }
    memset(op_cookies->cookies, 0x00, sizeof(hx_cookies_t) * op_cookies->count);
    for (i = 0; i < op_cookies->count; i++) {
        op_cookies->cookies[i].virt = hx_dma_alloc_consistent(alloc_dev,
                                                              op_cookies->size,
                                                              &dma_handle);
        op_cookies->cookies[i].phy = dma_handle;
        if (op_cookies->cookies[i].virt == NULL) {
            LOG_ERROR("BULK: %d \n", i);
            LOG_ERROR("op_cookies->cookies[i].virt=%p op_cookies->cookies[i].phy=%llx \n", op_cookies->cookies[i].virt, op_cookies->cookies[i].phy);
            op_cookies->count = i;
            goto err;
        }
    }

err:
    if ((ring_handle != NULL) &&
        ((ring_handle->com_ring.ring_resp_queue_virt_addr == NULL) || (ring_handle->com_ring.ring_resp_queue_virt_addr == NULL)
            || (ring_handle->com_ring.ring_cmd_resp_queue_virt_addr == NULL))) {
        if (ring_handle->com_ring.ring_req_queue_virt_addr != NULL) {
            hx_dma_free_consistent(alloc_dev,
                                   ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.message_size,
                                   ring_handle->com_ring.ring_req_queue_virt_addr,
                                   ring_handle->com_ring.ring_req_queue_phy_addr);
        }

        if (ring_handle->com_ring.ring_resp_queue_virt_addr != NULL) {
            hx_dma_free_consistent(alloc_dev,
                                   ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.resp_size,
                                   ring_handle->com_ring.ring_resp_queue_virt_addr,
                                   ring_handle->com_ring.ring_resp_queue_phy_addr);
        }

        if (ring_handle->com_ring.ring_cmd_resp_queue_virt_addr != NULL) {
            hx_dma_free_consistent(alloc_dev,
                                   ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.cmd_resp_size,
                                   ring_handle->com_ring.ring_cmd_resp_queue_virt_addr,
                                   ring_handle->com_ring.ring_cmd_resp_queue_phy_addr);
        }
        kfree(ring_handle);
        ring_handle = NULL;
    }
    *bulk_ring = ring_handle;
    return 0;
}

int hx_free_bulk_ring(struct hx_accel_dev *accel_dev, hx_ring_handle_t *ring_handle)
{
    int i = 0;
    int ring_id = 0;
    void *alloc_dev = NULL;
    hx_op_cookie_t *op_cookies;
    ring_id = ring_handle->ring_id;

#if PCIE_ENABLE
    alloc_dev = accel_dev->accel_pci.pci_dev;
#else
    alloc_dev = &accel_dev->platform_dev->dev;
#endif

    hx_dma_free_consistent(alloc_dev,
                           ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.message_size,
                           ring_handle->com_ring.ring_req_queue_virt_addr,
                           ring_handle->com_ring.ring_req_queue_phy_addr);

    hx_dma_free_consistent(alloc_dev,
                           ring_handle->com_ring.ring_queue_size * ring_handle->com_ring.resp_size,
                           ring_handle->com_ring.ring_resp_queue_virt_addr,
                           ring_handle->com_ring.ring_resp_queue_phy_addr);
    // free cookie
    op_cookies = &ring_handle->com_ring.op_cookies;
    for (i = 0; i < op_cookies->count; i++) {
        // free ss
        hx_dma_free_consistent(alloc_dev,
                               op_cookies->size,
                               op_cookies->cookies[i].virt,
                               op_cookies->cookies[i].phy);
    }

    vfree(ring_handle->com_ring.op_cookies.cookies);
    kfree(ring_handle);
    return 0;
}

int ring_put_msg(hx_ring_handle_t *ring_handle, void *msg, uint32_t algo)
{
    ring_handle_t *ring = &(ring_handle->com_ring);
    volatile uint32_t *head = NULL;
    int flight = 0;
    cb_data_t *cb_data = NULL;
    volatile uint32_t *res;
    s_list_pkg_t *s_pkg = NULL;
    struct cipher_req_st *req = (struct cipher_req_st *)msg;
    int ring_type = 0;
    int message_size = ring->message_size;
    uint64_t resp_addr = 0;
    void *base = ring_handle->ptr_base;

    mutex_lock(&ring->req_lock);
    flight = atomic_read(&ring->in_flight);

    if (flight >= ring->ring_queue_size - 1) {
        mutex_unlock(&ring->req_lock);
        return -1;
    }

    resp_addr = ring->ring_resp_queue_phy_addr + ring->req_tail * ring->resp_size; // zwd
    req->res_addr_l = (uint32_t)(resp_addr & 0xffffffff);
    req->res_addr_h = (uint32_t)((resp_addr >> 32) & 0xffffffff);

    memcpy(ring->ring_req_queue_virt_addr + message_size * ring->req_tail, req, message_size);

    res = (uint32_t *)(ring->ring_resp_queue_virt_addr + ring->req_tail * ring->resp_size);
    *res = HX_RESP_MAGIC_CODE;

    ring->req_tail++;
    // ring->req_tail %= ring->ring_queue_size;
    if (ring->req_tail >= ring->ring_queue_size) {
        ring->req_tail = 0;
    }

    atomic_inc(&ring->in_flight);
    ring->enq++;
    cb_data = get_opdata_from_req(req, ring_type);
    ring->enq_size += cb_data->src_len;
    // dump_buf(">>> req",(uint8_t *)req,message_size);
    wmb();

    /*  only one ring */
    HX_REG_WRITE(base + NPUB_RING_PLUS(ring_handle->ring_id), 1);

    LOG_DEBUG("TX ring_id=%d  req_tail=%d \n", ring_handle->ring_id, ring->req_tail);
    mutex_unlock(&ring->req_lock);

    return 0;
}

uint32_t polling_ring(hx_ring_handle_t *ring_handle, list_pkg_t **item)
{
    hx_page_info_t *p_info = NULL;
    user_cb_func p_user_cb_func;
    void *q = NULL;
    uint64_t t_status[3];
    int total_poll;
    int h_t;
    int t_t;
    int t_p;
    int index = 0;
    int cnt = 0;
    int i = 0;
    int ret = 0;
    hx_wait_t *psync_wait = NULL;
    wait_queue_head_t wq;
    session_t *ctx = NULL;
    cb_data_t *cb_data;
    volatile uint32_t *msg = NULL;
    volatile uint32_t *msg_req = NULL;
    void *ptr_base = ring_handle->ptr_base;
    int ring_id = ring_handle->ring_id;
    int ring_type = 0;
    ring_handle_t *ring = &ring_handle->com_ring;
    struct upif_cmd_resp_st *cmd;
    total_poll = 0;

    if (mutex_trylock(&ring->resp_lock) == 0) {
        printk(">>> mutex_trylock error !\n");
        return 0;
    }

    while (1) {
        cmd = (struct upif_cmd_resp_st *)(ring->ring_cmd_resp_queue_virt_addr + ring->cmd_resp_tail * ring->cmd_resp_size);
        if(cmd->response == HX_RESP_INIT_CODE)
            break;

        LOG_DEBUG("[SUCCESS] :>>> MSG success!\n");

        if(ring->sess_mode == HX_ASYNC_POLLING_MODE)
        {
            if(ring->cb_data == NULL)
                kfifo_get(&cb_fifo, &ring->cb_data);   
            cb_data = ring->cb_data;
            if(cb_data)
                ret = pqc_get_response(ring, cmd->pkg_num, cmd->pkg_size, cb_data);
            else
            {
                LOG_DEBUG("cb_data is NULL\n");
                break;
            }
        }
        else
        {
            if(ring->cb_data)
            {
                cb_data = ring->cb_data;
                ret = pqc_get_response(ring, cmd->pkg_num, cmd->pkg_size, cb_data);
            }  
            else
                ret = pub_get_response(ring, cmd->pkg_num, cmd->pkg_size, &cb_data);
        }
                
        cmd->response = HX_RESP_INIT_CODE;

        ring->cmd_resp_tail = (ring->cmd_resp_tail + 1) % (ring->ring_queue_size);

        if(cb_data->algo == HX_PQC)
        {
            if(cb_data->dst_index < cb_data->dst_len)
            {
                cnt++;
                break;
            }         
        }
        else
        {
            if(cb_data->msg_index < cb_data->msg_num)
            {
                cnt++;
                break;
            }      
        }
  
        if(ring->sess_mode == HX_ASYNC_POLLING_MODE)
        {
            put_cookie((hx_cookies_t *)cb_data->src_cookie);
            ring->cb_data = NULL;
        }
                
        ctx = cb_data->ctx;

        vunmap(cb_data->vmap_dst);
        for(i=0; i < cb_data->nr_pages; i++) {
            set_page_dirty(cb_data->pages[i]);
            put_page(cb_data->pages[i]);
        }
        kfree(cb_data->pages);
        
        if ((cb_data->sess_mode == HX_SYNC_MODE) && ((void *)cb_data->sync_wait != NULL)) {
            LOG_DEBUG("====>>> HX_SYNC_MODE :wake up\n");
            psync_wait = (hx_wait_t *)(cb_data->sync_wait);
            psync_wait->condition = 1;
            psync_wait->state = cb_data->state;
            wake_up_interruptible(&psync_wait->wq);
            psync_wait->condition = 2;
            ring->cb_data = NULL;
        } else if (cb_data->sess_mode == HX_ASYNC_POLLING_MODE){   
            LOG_DEBUG("====>>> HX_ASYNC_POLLING_MODE, pkg_id = %d\r\n\r\n", cb_data->pkg_id);
            t_status[0] = cb_data->pkg_id;
            t_status[1] = cb_data->state;
            if ((ctx != NULL) && (!ctx->internal)) {
                ctx->pkg_count++;
                t_status[2] = ctx->pkg_count;
            }
            p_info = (hx_page_info_t *)cb_data->user_sess_page_info;
            q = &(t_status);
            for (int i = 0; i < cb_data->user_sess_page_num; ++i) {
                memcpy((void *)(p_info[i].addr + p_info[i].offset), q, p_info[i].size);
                q += p_info[i].size;
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_sess_page_info);
            wmb();
        }

        if ((ctx != NULL) && (ctx->status == HX_RET_FAILED) && (ctx->request_queue_head == NULL)) {
            if(cb_data->sess_mode == HX_ASYNC_POLLING_MODE && cb_data->update_final == 0)
                continue;
            ctx->status = HX_RET_SUCCESS;
            if (ctx->internal)
                kfree(ctx);
            wmb();
        }

        cnt++;
        ring->deq_size += cb_data->dst_len;

        kfree(cb_data);
        if (index >= HX_MAX_POLL_ITEMS) {
            break;
        }
    }

    if (cnt != 0) {
        atomic_sub(cnt, &ring->in_flight);
        ring->deq += cnt;
    }
    mutex_unlock(&ring->resp_lock);

    return cnt;
}

#define HX_LIST_NUM  1
#define HX_LIST_NODE 1

void clear_pkg(ring_handle_t *ring)
{
    struct pid *ppid;
    int index = 0;
    list_pkg_t *pkg = NULL;
    list_pkg_t *next = NULL;

    for (index = 0; index < HX_LIST_NUM; index++) {
        mutex_lock(&ring->list_lock);
        list_for_each_entry_safe(pkg, next, &ring->pkg_head, list)
        {
            ppid = find_vpid(pkg->pid);
            if (ppid == NULL) {
                list_del(&pkg->list);
                // atomic_dec(&ring->list_node_num[index]);
                kfree(pkg);
                pkg = NULL;
            }
        }
        mutex_unlock(&ring->list_lock);
    }
}

/* items: user recive item, item: internal poll result save item list */
int hx_ring_user_poll(hx_ring_handle_t *ring_handle, list_pkg_t **item, ioctl_item_t *item_s, int pid)
{
    int res_num = 0;

    res_num = polling_ring(ring_handle, item);

    return res_num;
}

int hx_ring_init(struct hx_accel_dev *accel_dev)
{
    hx_dev_rp_info_t *rp_info = accel_dev->rp_info;
    for (int ring_id = 0; ring_id < g_rpu_ring_num; ring_id++) {
        hx_init_bulk_ring(accel_dev, ring_id, &rp_info->rpu_ring_handle[ring_id]);
        rp_info->max_valid_rpu_ring_num++;
    }
    atomic_set(&rp_info->in_rpu_polling, 0);
    LOG_DEBUG("max_valid_bulk_ring_num = %d \n", rp_info->max_valid_rpu_ring_num);
    return 0;
}

int hx_ring_free(struct hx_accel_dev *accel_dev)
{
    hx_dev_rp_info_t *rp_info = accel_dev->rp_info;
    LOG_INFO("hx ring free\n");

    for (int ring_id = 0; ring_id < rp_info->max_valid_rpu_ring_num; ring_id++) {
        hx_free_bulk_ring(accel_dev, rp_info->rpu_ring_handle[ring_id]);
    }
    return 0;
}

void hx_ctrl_init(void)
{
    init_id();
    hx_table_lock_init();
    // hxk_dev_table_lock_init();

#if RING_CNT_DEBUG
    atomic_set(&rpu_pack_recv_cnt, 0);
    atomic_set(&npub_pack_recv_cnt, 0);
#endif
    atomic_set(&hx_algo_timeout_cnt, 0);
    /*
        create dequeue thread
    */
    dequeue_thread_run();
}

void hx_ctrl_destroy(void)
{
    /*
        stop dequeue thread
    */
    dequeue_thread_stop();
}

// EXPORT_SYMBOL_GPL(hx_hw_free);
// dequeue thread run
int hx_dequeue_thread(void *param)
{
    int i = 0;
    int ret = 0;
    list_ctx_t *ctx_node = NULL;
    list_ctx_t *next = NULL;

    dequeue_wait = kzalloc(sizeof(hx_wait_t), GFP_KERNEL);
    init_waitqueue_head(&dequeue_wait->wq);
    dequeue_wait->condition = 0;

    mutex_init(&ctx_lock);
    atomic_inc(&dequeue_runing);
    while (!kthread_should_stop()) {
        set_current_state(TASK_UNINTERRUPTIBLE);

        wait_event_interruptible(dequeue_wait->wq, dequeue_wait->condition || kthread_should_stop());

        if(kthread_should_stop())
            break;

        mutex_lock(&ctx_lock);
        list_for_each_entry_safe(ctx_node, next, &ctx_head, list)
        {
            if (ctx_node->ctx != NULL) {
                ret = dequeue_pending_request(ctx_node->ctx);

                if (ret != HX_RET_SUCCESS)
                    usleep_range(10, 10);
            }
        }
        mutex_unlock(&ctx_lock);

        usleep_range(100, 100);
    }

    kfree(dequeue_wait);
    atomic_dec(&dequeue_runing);
    return 0;
}

struct task_struct *dequeue_comm_kthread;
int dequeue_thread_run(void)
{
    atomic_set(&dequeue_runing, 0);
    // dequeue thread
    dequeue_comm_kthread = kthread_create(hx_dequeue_thread, NULL, "%s", "dequeue_thread");
    kthread_bind(dequeue_comm_kthread, HX_QUEUE_BIND);
    wake_up_process(dequeue_comm_kthread);
    return 0;
}

int dequeue_thread_stop(void)
{
    kthread_stop(dequeue_comm_kthread);
    while (atomic_read(&dequeue_runing) != 0);
    return 0;
}

int check_state_all(hx_ring_handle_t *rpu_handle[], int rpu_ring_num, int pid, ioctl_item_t *item)
{
    int list_num;
    int max_ring = 0;
    int num_total = 0;
    int num = 0;
    int c_l_n = 0;
    int index;
    int index_list;
    struct pid *ppid;
    list_pkg_t *pkg = NULL;
    list_pkg_t *next = NULL;
    hx_ring_handle_t **ring_handle;
    ring_handle_t *ring;

    for (;;) {
        max_ring = rpu_ring_num;
        ring_handle = rpu_handle;

        num_total = 0;
        for (index = 0; index < max_ring; index++) {
            num = 0;
            if (ring_handle[index] == NULL)
                continue;

            ring = &ring_handle[index]->com_ring;

            if (ring->time_out)
                break;

            num = hx_ring_user_poll(ring_handle[index], (list_pkg_t **)(item + HX_MAX_POLL_ITEMS), item, pid);

            if (num > 0)
                ring->wait_count = 0;
            else {
                if (atomic_read(&ring->in_flight) > 0)
                    ring->wait_count++;
                if (ring->wait_count > HX_MAX_WAIT_COUNT) {
                    LOG_ERROR("ring %d timeout\n", index);
                    ring->time_out = 1;
                }
            }

            num_total += num;
        }

        if (num_total == 0) {
            usleep_range(1, 1);
            break;
        }
    }

    return num;
}

hx_cookies_t *get_cookie(hx_ring_handle_t *ring_handle)
{
    int i = 0;
    struct timespec64 stamp_temp;
    ring_handle_t *ring = &ring_handle->com_ring;
    hx_op_cookie_t *op_cookies = NULL;
    hx_cookies_t *cookie = NULL;
    op_cookies = &ring->op_cookies;

    spin_lock(&op_cookies->lock);
    for (i = 0; i < op_cookies->count; i++) {
        cookie = &op_cookies->cookies[op_cookies->offset++];
        if (op_cookies->offset >= op_cookies->count)
            op_cookies->offset = 0;
        if (cookie->state == 0) {
            break;
        } else {
            ktime_get_real_ts64(&stamp_temp);
            if ((stamp_temp.tv_sec - cookie->stamp.tv_sec) > 31526000)
                break;
        }
    }
    if (i >= op_cookies->count)
        cookie = NULL;
    else {
        cookie->state = 1;
        ktime_get_real_ts64(&cookie->stamp);
    }
    spin_unlock(&op_cookies->lock);

    return cookie;
}

void put_cookie(hx_cookies_t *cookie)
{
    if (cookie != NULL)
        cookie->state = 0;
}

int in_flight_pre_check(hx_ring_handle_t *ring_handle)
{
    return atomic_read(&ring_handle->com_ring.in_flight) > ring_handle->com_ring.max_flight ? 1 : 0;
}

int ctx_list_init(void)
{
    uint8_t id;

    mutex_lock(&ctx_lock);
    for (id = 0; id < CTX_MAX_NUM; id++)
        ctx_node[id] = NULL;
    mutex_unlock(&ctx_lock);

    return 0;
}

int ctx_list_add(void *ctx)
{
    uint8_t id;

    mutex_lock(&ctx_lock);
    for (id = 0; id < CTX_MAX_NUM; id++) {
        if (ctx_node[id] == NULL)
            goto success;
    }

    LOG_DEBUG("ring_list_add fail\n");
    mutex_unlock(&ctx_lock);
    return -1;

success:
    LOG_DEBUG("ctx_list_add, id = %d\n", id);
    ctx_node[id] = kzalloc(sizeof(list_ctx_t), GFP_KERNEL);
    ctx_node[id]->ctx = ctx;
    list_add(&ctx_node[id]->list, &ctx_head);
    mutex_unlock(&ctx_lock);

    return 0;
}

int ctx_list_remove(void *ctx)
{
    uint8_t id;

    mutex_lock(&ctx_lock);
    for (id = 0; id < CTX_MAX_NUM; id++) {
        if (ctx_node[id] != NULL && ctx_node[id]->ctx == ctx)
            goto success;
    }

    LOG_DEBUG("ring_list_remove fail\n");
    mutex_unlock(&ctx_lock);
    return -1;

success:
    LOG_DEBUG("ring_list_remove, id = %d\n", id);
    list_del(&ctx_node[id]->list);
    kfree(ctx_node[id]);
    ctx_node[id] = NULL;
    mutex_unlock(&ctx_lock);

    return 0;
}