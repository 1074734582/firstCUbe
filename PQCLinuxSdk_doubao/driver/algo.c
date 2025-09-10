#include "algo.h"
#include "asm/page.h"
#include "common.h"
#include "ring.h"
#include <linux/delay.h>
#include <linux/eventfd.h>
#include <linux/fdtable.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

int rpu_cmd_send(hx_ring_handle_t *ring_handle, session_t *ctx, struct cipher_req_st *req, void *src)
{
    int ret = 0;
    int retry = 0;
    request_node_t *req_node;

    if (ring_handle->busy != 0) {
        return 1;
    }
    // get req lock
    mutex_lock(&ctx->request_queue_lock);

    if (ctx->internal == 0 && ctx->pkg_mode == HX_PACKAGE_COMPLETE) {
        LOG_DEBUG("rpu_cmd_send queue\n");

        req_node = kzalloc(sizeof(request_node_t), GFP_KERNEL);
        req_node->req_handle = req;
        req_node->request_type = REQUEST_TYPE_CIPHER;
        req_node->src_vir = src;

        if (ctx->request_queue_tail != NULL) {
            // queue non-empty
            ctx->request_queue_tail->next = req_node;
        } else {
            // queue empty
            ctx->request_queue_head = req_node;
        }
        ctx->request_queue_tail = req_node;
        ctx->request_queue_tail->next = NULL;
    } else {
        LOG_DEBUG("rpu_cmd_send ring\n");
        retry = HX_MAX_RETRY_TIMES;
        do {
            ret = ring_put_msg(ring_handle, req, ctx->algo);
            if (ret == 0)
                break;
            usleep_range(50, 50);
        } while (retry--);
        if (retry < 0) {
            printk("kfree req fail\n");
            ret = -1;
        } else {
            kfree(req);
            ret = 0;
        }
    }

    mutex_unlock(&ctx->request_queue_lock);
    return ret;
}

int rpu_cipher(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from,
               void *src, uint32_t src_len,
               void *dst, uint32_t dst_len,
               void *key, uint32_t key_len,
               void *tag, uint32_t tag_len,
               uint64_t pkg_id, ioctl_item_t *item, void *sync_wait, uint8_t final)
{
    uint64_t sess = item->sess;
    int pid = item->pid;
    int sess_mode = item->mode;
    uint64_t sess_cb = item->cb;
    uint64_t sess_cb_param = item->cb_param;
    uint32_t iv_len = ctx->iv_len;
    char *iv = (char *)ctx->iv;
    int ret = 0;
    int num = 0;
    hx_page_info_t *p_info = NULL;
    cb_data_t *cb_data = NULL;
    struct cipher_req_st *req = NULL;
    hx_cookies_t *s_cookie = NULL;
    hx_cookies_t *d_cookie = NULL;
    ring_handle_t *ring = &(ring_handle->com_ring);

    if (ring_handle == NULL)
        return HX_RET_PARAM_ERROR;

    if (ring->time_out)
        return HX_RET_TIMEOUT;

    cb_data = kzalloc(sizeof(cb_data_t), GFP_KERNEL);
    req = kzalloc(sizeof(struct cipher_req_st), GFP_KERNEL);
    if ((req == NULL) || (cb_data == NULL)) {
        LOG_ERROR("alloc failed req+cb_data \n");
        ret = HX_RET_NO_MEM;
        goto err;
    }

    cb_data->update_final = final;

    s_cookie = get_cookie(ring_handle);
    if (s_cookie == NULL) {
        // LOG_ERROR("alloc failed s_cookie \n");
        ret = HX_RET_NO_MEM;
        goto err;
    } else {
        cb_data->src_virt = s_cookie->virt;
        cb_data->src_phy = s_cookie->phy;
        cb_data->src_cookie = s_cookie;

        ret = build_cipher_src_data(ctx, cb_data->src_virt, src, src_len);
        if (ret != 0) {
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->src_len = ctx->actual_src_len;
    }

    d_cookie = get_cookie(ring_handle);
    if (d_cookie == NULL) {
        // LOG_ERROR("alloc failed d_cookie \n");
        ret = HX_RET_NO_MEM;
        goto err;
    } else {
        cb_data->dst_data_len = src_len;
        cb_data->dst_len = dst_len;

        cb_data->dst_virt = d_cookie->virt;
        cb_data->dst_phy = d_cookie->phy;
        cb_data->dst_cookie = d_cookie;
    }

    cb_data->pkg_from = pkg_from;
    cb_data->sync_wait = (uint64_t)sync_wait;
    cb_data->sess_mode = sess_mode;
    cb_data->pid = pid;
    cb_data->user_sess = sess;

    if ((cb_data->sess_mode == HX_ASYNC_POLLING_MODE) && (cb_data->user_sess != 0)) {
        num = get_page_nums((uint64_t)(sess + 8), (uint32_t)24);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)(sess + 8), 24, num, p_info);
        if (ret != 0) {
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_sess_page_info = (uint64_t)p_info;
        cb_data->user_sess_page_num = num;
    }

    cb_data->user_sess_cb = sess_cb;
    cb_data->user_sess_cb_param = sess_cb_param;
    cb_data->pkg_id = pkg_id;
    cb_data->ctx = ctx;
    cb_data->ring_handle = ring_handle;
    cb_data->algo = ctx->algo;
    cb_data->mode = ctx->mode;
    cb_data->dir = ctx->dir;
    cb_data->pkg_mode = ctx->pkg_mode;

    cb_data->user_src = (uint64_t)src;

    cb_data->op_type = CIPHER_OP;

    if (dst_len != 0) {
        num = get_page_nums((uint64_t)dst, (uint32_t)dst_len);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)dst, dst_len, num, p_info);
        if (ret != 0) {
            LOG_ERROR("user_to_kernel \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_dst = (uint64_t)p_info;
        cb_data->user_dst_page_num = num;
    }

    if (ctx->tag_len != 0 || final == 1) {
        num = get_page_nums((uint64_t)tag, (uint32_t)tag_len);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_ATOMIC);
        ret = user_to_kernel((uint64_t)tag, tag_len, num, p_info);
        if (ret != 0) {
            LOG_ERROR("user_to_kernel \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_tag = (uint64_t)p_info;
        cb_data->user_tag_page_num = num;
    }

    if (final == 1)
        ctx->split_flag = 2;

    dump_buf(">>> rpu_cipher src:", cb_data->src_virt, ctx->actual_src_len);

    build_cipher_req_msg(req, cb_data->src_phy, cb_data->src_len,
                         cb_data->dst_phy, cb_data->dst_len,
                         ctx->key_len, (uint32_t)ctx->actual_iv_len,
                         (uint32_t)ctx->actual_aad_len, (uint32_t)ctx->tag_len,
                         ctx->total_len, cb_data, (uint32_t)ctx->algo, (uint32_t)ctx->mode, (uint32_t)ctx->dir,
                         (uint32_t)ctx->padding, ctx->total_pos, ctx->pkg_mode);

    if (ctx->pkg_mode != HX_PACKAGE_COMPLETE)
        ctx->total_pos += src_len;

    ctx->ring_handle = ring_handle;
    LOG_DEBUG("resp_size = %d, message_size = %d\n", ring_handle->com_ring.resp_size, ring_handle->com_ring.message_size);

    ret = rpu_cmd_send(ring_handle, ctx, req, cb_data->src_virt);
    if (ret != 0) {
        LOG_ERROR("rpu_cmd_send fail\n");
        ret = HX_RET_DEVICE_BUSY;
        goto err;
    }
err:
    if (ret != 0) {
        // send failed , we need to free all memory
        put_cookie(s_cookie);
        put_cookie(d_cookie);

        if ((void *)cb_data->user_dst != NULL) {
            p_info = (hx_page_info_t *)cb_data->user_dst;
            for (int i = 0; i < cb_data->user_dst_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_dst);
        }

        if ((cb_data->sess_mode == 1) && ((void *)cb_data->user_sess_page_info != NULL)) {
            p_info = (hx_page_info_t *)cb_data->user_sess_page_info;
            for (int i = 0; i < cb_data->user_sess_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_sess_page_info);
        }

        if (cb_data != NULL)
            kfree(cb_data);
        if (req != NULL)
            kfree(req);
    }
    return ret;
}

int rpu_hash(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from,
             void *src, uint32_t src_len,
             void *dst, uint32_t dst_len,
             uint32_t iv_len, uint64_t pkg_id, ioctl_item_t *item,
             void *sync_wait, int hash_final)
{
    uint64_t sess = item->sess;
    int pid = item->pid;
    int sess_mode = item->mode;
    uint64_t sess_cb = item->cb;
    uint64_t sess_cb_param = item->cb_param;
    int ret = 0;
    int num = 0;

    uint32_t hash_len_update = ctx->hash_len_update;
    uint8_t *p;
    uint64_t *q;
    struct hx_accel_pci *accel_pci = NULL;
    hx_page_info_t *p_info = NULL;

    cb_data_t *cb_data = NULL;
    struct cipher_req_st *req = NULL;
    hx_cookies_t *s_cookie = NULL;
    hx_cookies_t *d_cookie = NULL;
    ring_handle_t *ring = &(ring_handle->com_ring);

    if (ring_handle == NULL)
        return HX_RET_PARAM_ERROR;

    if (ring->time_out)
        return HX_RET_TIMEOUT;

    if ((hash_final == 1) && (dst == NULL)) // hash final must out data
        return HX_RET_PARAM_ERROR;

    if (src_len <= 0) {
        LOG_ERROR("hash src_len=%d a\n", src_len);
        return HX_RET_PARAM_ERROR;
    }
    // pre check
    if (in_flight_pre_check(ring_handle)) {
        return HX_RET_DEVICE_BUSY;
    }
    cb_data = kzalloc(sizeof(cb_data_t), GFP_KERNEL);
    req = kzalloc(sizeof(struct cipher_req_st), GFP_KERNEL);
    if ((req == NULL) || (cb_data == NULL)) {
        LOG_ERROR("alloc failed req+cb_data \n");
        ret = HX_RET_NO_MEM;
        goto err;
    }

    ctx->hash_len_update = ((ctx->hash_len_update + (15)) & (~0xf));

    s_cookie = get_cookie(ring_handle);
    if (s_cookie == NULL) {
        LOG_ERROR("alloc failed s_cookie \n");
        ret = HX_RET_NO_MEM;
        goto err;
    } else {
        cb_data->src_virt = s_cookie->virt;
        cb_data->src_phy = s_cookie->phy;
        cb_data->src_cookie = s_cookie;

        ret = build_hash_src_data(ctx, cb_data->src_virt, src, src_len);
        if (ret != 0) {
            LOG_ERROR("do build_hash_src_data error! \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->src_len = ctx->actual_src_len;
        iv_len = ctx->iv_len;
    }

    if (hash_final == 0)
        cb_data->dst_data_len = ctx->hash_len_update;
    else
        cb_data->dst_data_len = ctx->hash_dgst_len;

    d_cookie = get_cookie(ring_handle);
    if (d_cookie == NULL) {
        LOG_ERROR("alloc failed d_cookie \n");
        ret = HX_RET_NO_MEM;
        goto err;
    } else {
        cb_data->dst_len = (cb_data->dst_data_len + 15) & (~0xf);
        cb_data->dst_virt = d_cookie->virt;
        cb_data->dst_phy = d_cookie->phy;
        cb_data->dst_cookie = d_cookie;
    }

    cb_data->pkg_from = pkg_from;
    cb_data->sync_wait = (uint64_t)sync_wait;
    cb_data->sess_mode = sess_mode;
    cb_data->pid = pid;
    cb_data->user_sess = sess;

    if ((cb_data->sess_mode == HX_ASYNC_POLLING_MODE) && (cb_data->user_sess != 0)) {
        num = get_page_nums((uint64_t)(sess + 8), (uint32_t)24);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)(sess + 8), 24, num, p_info);
        if (ret != 0) {
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_sess_page_info = (uint64_t)p_info;
        cb_data->user_sess_page_num = num;
    }

    cb_data->user_sess_cb = sess_cb;
    cb_data->user_sess_cb_param = sess_cb_param;
    cb_data->pkg_id = pkg_id;
    cb_data->ctx = ctx;
    cb_data->ring_handle = ring_handle;
    cb_data->algo = ctx->algo;
    cb_data->mode = ctx->mode;
    cb_data->dir = ctx->dir;
    // set up fin flag
    cb_data->update_final = hash_final;
    cb_data->pkg_mode = ctx->pkg_mode;
    cb_data->op_type = HASH_OP;

    if (hash_final == 1) // just final need out data
    {
        num = get_page_nums((uint64_t)dst, (uint32_t)dst_len);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)dst, dst_len, num, p_info);
        if (ret != 0) {
            printk(">>> HX_RET_PARAM_ERROR \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_dst = (uint64_t)p_info;
        cb_data->user_dst_page_num = num;
    }

    ctx->total_len += src_len;
    build_hash_req_msg(req, cb_data->src_phy, cb_data->src_len, cb_data->dst_phy, cb_data->dst_data_len,
                       0, iv_len, 0, ctx->total_len,
                       cb_data, ctx->algo, HASH_MODE, ctx->padding, ctx->pkg_mode);

    ctx->ring_handle = ring_handle;

    ret = rpu_cmd_send(ring_handle, ctx, req, cb_data->src_virt);
    if (ret == 0) {
        ctx->hash_block_len += src_len;
    } else {
        ret = HX_RET_DEVICE_BUSY;
        goto err;
    }
err:
    if (ret != 0) {
        // send failed , we need to free all memory
        put_cookie(s_cookie);
        put_cookie(d_cookie);
        if ((void *)cb_data->user_dst != NULL) {
            p_info = (hx_page_info_t *)cb_data->user_dst;
            for (int i = 0; i < cb_data->user_dst_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_dst);
        }

        if ((cb_data->sess_mode == 1) && ((void *)cb_data->user_sess_page_info != NULL)) {
            p_info = (hx_page_info_t *)cb_data->user_sess_page_info;
            for (int i = 0; i < cb_data->user_sess_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_sess_page_info);
        }

        if (cb_data != NULL)
            kfree(cb_data);
        if (req != NULL)
            kfree(req);
    };
    return ret;
}

int rpu_hmac(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from,
             void *src, uint32_t src_len,
             void *dst, uint32_t dst_len,
             uint32_t iv_len, uint64_t pkg_id, ioctl_item_t *item,
             void *sync_wait, int hash_final)
{
    uint64_t sess = item->sess;
    int pid = item->pid;
    int sess_mode = item->mode;
    uint64_t sess_cb = item->cb;
    uint64_t sess_cb_param = item->cb_param;
    int ret = 0;
    int num = 0;
    uint8_t *p;
    uint64_t *q;

    hx_page_info_t *p_info = NULL;

    cb_data_t *cb_data = NULL;
    struct cipher_req_st *req = NULL;
    hx_cookies_t *s_cookie = NULL;
    hx_cookies_t *d_cookie = NULL;
    ring_handle_t *ring = &(ring_handle->com_ring);

    if (ring_handle == NULL)
        return HX_RET_PARAM_ERROR;

    if (ring->time_out)
        return HX_RET_TIMEOUT;

    if ((hash_final == 1) && (dst == NULL)) // hash final must out data
        return HX_RET_PARAM_ERROR;

    if (src_len <= 0) {
        LOG_ERROR("hash src_len=%d a\n", src_len);
        return HX_RET_PARAM_ERROR;
    }
    // pre check
    if (in_flight_pre_check(ring_handle)) {
        return HX_RET_DEVICE_BUSY;
    }

    cb_data = kzalloc(sizeof(cb_data_t), GFP_KERNEL);
    req = kzalloc(sizeof(struct cipher_req_st), GFP_KERNEL);
    if ((req == NULL) ||
        (cb_data == NULL)) {
        LOG_ERROR("alloc failed req+cb_data \n");
        ret = HX_RET_NO_MEM;
        goto err;
    }

    ctx->hash_len_update = ((ctx->hash_len_update + (15)) & (~0xf));

    s_cookie = get_cookie(ring_handle);
    if (s_cookie == NULL) {
        LOG_ERROR("alloc failed s_cookie \n");
        ret = HX_RET_NO_MEM;
        goto err;
    } else {
        cb_data->src_virt = s_cookie->virt;
        cb_data->src_phy = s_cookie->phy;
        cb_data->src_cookie = s_cookie;

        ret = build_hmac_src_data(ctx, cb_data->src_virt, src, src_len);
        if (ret != 0) {
            LOG_ERROR("do build_hash_src_data error! \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->src_len = ctx->actual_src_len;
        iv_len = ctx->iv_len;
    }

    if (hash_final == 0)
        cb_data->dst_data_len = ctx->hash_len_update;
    else
        cb_data->dst_data_len = ctx->hash_dgst_len;

    d_cookie = get_cookie(ring_handle);
    if (d_cookie == NULL) {
        LOG_ERROR("alloc failed d_cookie \n");
        ret = HX_RET_NO_MEM;
        goto err;
    } else {
        cb_data->dst_len = (cb_data->dst_data_len + 15) & (~0xf);
        cb_data->dst_virt = d_cookie->virt;
        cb_data->dst_phy = d_cookie->phy;
        cb_data->dst_cookie = d_cookie;
    }

    cb_data->pkg_from = pkg_from; //  1
    cb_data->sync_wait = (uint64_t)sync_wait;
    cb_data->sess_mode = sess_mode;
    cb_data->pid = pid;
    cb_data->user_sess = sess;
    if ((cb_data->sess_mode == HX_ASYNC_POLLING_MODE) && (cb_data->user_sess != 0)) {
        num = get_page_nums((uint64_t)(sess + 8), (uint32_t)24);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)(sess + 8), 24, num, p_info);
        if (ret != 0) {
            LOG_ERROR(">>> do user_to_kernel error 000 \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_sess_page_info = (uint64_t)p_info;
        cb_data->user_sess_page_num = num;
    }

    cb_data->user_sess_cb = sess_cb;
    cb_data->user_sess_cb_param = sess_cb_param;
    cb_data->pkg_id = pkg_id;
    cb_data->ctx = ctx;
    cb_data->ring_handle = ring_handle;
    cb_data->algo = ctx->algo;
    cb_data->mode = ctx->mode;
    cb_data->dir = ctx->dir;

    // set up fin flag
    cb_data->update_final = hash_final;
    cb_data->pkg_mode = ctx->pkg_mode;
    cb_data->op_type = HMAC_OP;

    if (hash_final == 1) // just final need out data
    {
        num = get_page_nums((uint64_t)dst, (uint32_t)dst_len);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)dst, dst_len, num, p_info);
        if (ret != 0) {
            LOG_ERROR(">>> do user_to_kernel error 111 \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_dst = (uint64_t)p_info;
        cb_data->user_dst_page_num = num;
    }

    ctx->total_len += src_len;
    build_hash_req_msg(req, cb_data->src_phy, cb_data->src_len, cb_data->dst_phy, cb_data->dst_data_len,
                       ctx->hash_key_len, iv_len, 0, ctx->total_len,
                       cb_data, ctx->algo, HMAC_MODE, ctx->padding, ctx->pkg_mode);

    ctx->ring_handle = ring_handle;

    ret = rpu_cmd_send(ring_handle, ctx, req, cb_data->src_virt);
    if (ret == 0) {
        ctx->hash_block_len += src_len;
    } else {
        printk(">>> HX_RET_DEVICE_BUSY \n");
        ret = HX_RET_DEVICE_BUSY;
        goto err;
    }
err:
    if (ret != 0) {
        LOG_ERROR(">>> goto err \n");
        // send failed , we need to free all memory
        put_cookie(s_cookie);
        put_cookie(d_cookie);
        if ((void *)cb_data->user_dst != NULL) {
            p_info = (hx_page_info_t *)cb_data->user_dst;
            for (int i = 0; i < cb_data->user_dst_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_dst);
        }

        if ((cb_data->sess_mode == 1) && ((void *)cb_data->user_sess_page_info != NULL)) {
            p_info = (hx_page_info_t *)cb_data->user_sess_page_info;
            for (int i = 0; i < cb_data->user_sess_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_sess_page_info);
        }

        if (cb_data != NULL)
            kfree(cb_data);
        if (req != NULL)
            kfree(req);
    }
    return ret;
}

int rpu_prf(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from,
            void *src, uint32_t src_len,
            void *dst, uint32_t dst_len,
            uint32_t aad_len, uint64_t pkg_id, ioctl_item_t *item,
            void *sync_wait, int hash_final)
{
    uint64_t sess = item->sess;
    int pid = item->pid;
    int sess_mode = item->mode;
    uint64_t sess_cb = item->cb;
    uint64_t sess_cb_param = item->cb_param;
    int ret = 0;
    int num = 0;

    uint8_t *p;
    uint64_t *q;
    hx_page_info_t *p_info = NULL;

    cb_data_t *cb_data = NULL;
    struct cipher_req_st *req = NULL;
    hx_cookies_t *s_cookie = NULL;
    hx_cookies_t *d_cookie = NULL;
    ring_handle_t *ring = &(ring_handle->com_ring);

    if (ring_handle == NULL)
        return HX_RET_PARAM_ERROR;

    if (ring->time_out)
        return HX_RET_TIMEOUT;

    if ((hash_final == 1) && (dst == NULL)) // hash final must out data
        return HX_RET_PARAM_ERROR;

    if (src_len <= 0) {
        LOG_ERROR("hash src_len=%d a\n", src_len);
        return HX_RET_PARAM_ERROR;
    }
    // pre check
    if (in_flight_pre_check(ring_handle)) {
        return HX_RET_DEVICE_BUSY;
    }

    cb_data = kzalloc(sizeof(cb_data_t), GFP_KERNEL);
    req = kzalloc(sizeof(struct cipher_req_st), GFP_KERNEL);
    if ((req == NULL) ||
        (cb_data == NULL)) {
        LOG_ERROR("alloc failed req+cb_data \n");
        ret = HX_RET_NO_MEM;
        goto err;
    }

    ctx->hash_len_update = ((ctx->hash_len_update + (15)) & (~0xf));

    s_cookie = get_cookie(ring_handle);
    if (s_cookie == NULL) {
        LOG_ERROR("alloc failed s_cookie \n");
        ret = HX_RET_NO_MEM;
        goto err;
    } else {
        cb_data->src_virt = s_cookie->virt;
        cb_data->src_phy = s_cookie->phy;
        cb_data->src_cookie = s_cookie;

        ret = build_prf_src_data(ctx, cb_data->src_virt, src, src_len);
        if (ret != 0) {
            LOG_ERROR("do build_prf_src_data error! \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->src_len = ctx->actual_src_len;
    }

    if (hash_final == 0)
        cb_data->dst_data_len = ctx->hash_len_update;
    else
        cb_data->dst_data_len = ctx->hash_dgst_len;

    d_cookie = get_cookie(ring_handle);
    if (d_cookie == NULL) {
        LOG_ERROR("alloc failed d_cookie \n");
        ret = HX_RET_NO_MEM;
        goto err;
    } else {
        cb_data->dst_len = (cb_data->dst_data_len + 15) & (~0xf);
        cb_data->dst_virt = d_cookie->virt;
        cb_data->dst_phy = d_cookie->phy;
        cb_data->dst_cookie = d_cookie;
        memset(cb_data->dst_virt, 0x00, 8192);
        cb_data->mark_len = sizeof(cb_data->mark_data);
        // get_random_bytes(cb_data->mark_data, cb_data->mark_len);
        memcpy(cb_data->mark_data, cb_data, cb_data->mark_len);
        cb_data->mark_pos = cb_data->dst_virt + cb_data->dst_data_len - cb_data->mark_len; // assert hash len >=mark_len
        memcpy(cb_data->mark_pos, cb_data->mark_data, cb_data->mark_len);
    }

    cb_data->pkg_from = pkg_from;
    cb_data->sync_wait = (uint64_t)sync_wait;
    cb_data->sess_mode = sess_mode;
    cb_data->pid = pid;
    cb_data->user_sess = sess;
    if ((cb_data->sess_mode == HX_ASYNC_POLLING_MODE) && (cb_data->user_sess != 0)) {
        num = get_page_nums((uint64_t)(sess + 8), (uint32_t)24);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)(sess + 8), 24, num, p_info);
        if (ret != 0) {
            LOG_ERROR(">>> do user_to_kernel error 000 \n");
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_sess_page_info = (uint64_t)p_info;
        cb_data->user_sess_page_num = num;
    }

    cb_data->user_sess_cb = sess_cb;
    cb_data->user_sess_cb_param = sess_cb_param;
    cb_data->pkg_id = pkg_id;
    cb_data->ctx = ctx;
    cb_data->ring_handle = ring_handle;
    cb_data->algo = ctx->algo;
    cb_data->mode = ctx->mode;
    cb_data->dir = ctx->dir;
    // set up fin flag
    cb_data->update_final = hash_final;
    cb_data->pkg_mode = ctx->pkg_mode;
    cb_data->op_type = PRF_OP;

    if (hash_final == 1) // just final need out data
    {
        num = get_page_nums((uint64_t)dst, (uint32_t)dst_len);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)dst, dst_len, num, p_info);
        if (ret != 0) {
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_dst = (uint64_t)p_info;
        cb_data->user_dst_page_num = num;
    }

    ctx->total_len += src_len - ctx->hash_key_len;
    build_hash_req_msg(req, cb_data->src_phy, cb_data->src_len, cb_data->dst_phy, cb_data->dst_data_len,
                       ctx->hash_key_len, 0, aad_len, ctx->total_len,
                       cb_data, ctx->algo, PRF_MODE, ctx->padding, ctx->pkg_mode);

    ctx->ring_handle = ring_handle;

    ret = rpu_cmd_send(ring_handle, ctx, req, cb_data->src_virt);
    if (ret == 0) {
        ctx->total_len += src_len;
    } else {
        ret = HX_RET_DEVICE_BUSY;
        goto err;
    }
err:
    if (ret != 0) {
        // send failed , we need to free all memory
        put_cookie(s_cookie);
        put_cookie(d_cookie);
        if ((void *)cb_data->user_dst != NULL) {
            p_info = (hx_page_info_t *)cb_data->user_dst;
            for (int i = 0; i < cb_data->user_dst_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_dst);
        }

        if ((cb_data->sess_mode == 1) && ((void *)cb_data->user_sess_page_info != NULL)) {
            p_info = (hx_page_info_t *)cb_data->user_sess_page_info;
            for (int i = 0; i < cb_data->user_sess_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_sess_page_info);
        }

        if (cb_data != NULL)
            kfree(cb_data);
        if (req != NULL)
            kfree(req);
    }
    return ret;
}

int pub_queue_send(hx_ring_handle_t *ring_handle, session_t *ctx, cb_data_t *cb_data)
{
    int ret = 0;
    int retry = 0;
    request_node_t *req_node;

    if (ring_handle->busy != 0) {
        return 1;
    }
    // get req lock
    mutex_lock(&ctx->request_queue_lock);

    LOG_DEBUG("pub_queue_send\n");

    req_node = kzalloc(sizeof(request_node_t), GFP_KERNEL);
    req_node->req_handle = (void *)cb_data;
    //req_node->request_type = REQUEST_TYPE_CIPHER;

    if (ctx->request_queue_tail != NULL) {
        // queue non-empty
        ctx->request_queue_tail->next = req_node;
    } else {
        // queue empty
        ctx->request_queue_head = req_node;
    }
    ctx->request_queue_tail = req_node;
    ctx->request_queue_tail->next = NULL;

    mutex_unlock(&ctx->request_queue_lock);

    return ret;
}

int rpu_pub(session_t *ctx, hx_ring_handle_t *ring_handle, int pkg_from, uint32_t bus, uint32_t algo, uint32_t mode,
               void *src, uint32_t src_len, void *dst, uint32_t dst_len,
               uint64_t pkg_id, ioctl_item_t *item, void *sync_wait, uint8_t final)
{
    uint64_t sess = item->sess;
    int pid = item->pid;
    int sess_mode = item->mode;
    uint64_t sess_cb = item->cb;
    uint64_t sess_cb_param = item->cb_param;
    uint32_t iv_len = ctx->iv_len;
    char *iv = (char *)ctx->iv;
    int ret = 0;
    int num = 0;
    int i = 0;
    hx_page_info_t *p_info = NULL;
    cb_data_t *cb_data = NULL;
    hx_cookies_t *s_cookie = NULL;
    ring_handle_t *ring = &(ring_handle->com_ring);
    int nr_pages = 1;
    uint64_t offset = 0;

    if (ring_handle == NULL)
        return HX_RET_PARAM_ERROR;

    if (ring->time_out)
        return HX_RET_TIMEOUT;

    cb_data = kzalloc(sizeof(cb_data_t), GFP_KERNEL);
    if (cb_data == NULL) {
        LOG_ERROR("alloc failed cb_data \n");
        ret = HX_RET_NO_MEM;
        goto err;
    }

    cb_data->pkg_from = pkg_from;
    cb_data->sync_wait = (uint64_t)sync_wait;
    cb_data->sess_mode = sess_mode;
    cb_data->pid = pid;
    cb_data->user_sess = sess;

    if ((cb_data->sess_mode == HX_ASYNC_POLLING_MODE) && (cb_data->user_sess != 0)) {
        num = get_page_nums((uint64_t)(sess + 8), (uint32_t)24);
        p_info = kzalloc(num * sizeof(hx_page_info_t), GFP_KERNEL);
        ret = user_to_kernel((uint64_t)(sess + 8), 24, num, p_info);
        if (ret != 0) {
            ret = HX_RET_PARAM_ERROR;
            goto err;
        }
        cb_data->user_sess_page_info = (uint64_t)p_info;
        cb_data->user_sess_page_num = num;
    }

    cb_data->user_sess_cb = sess_cb;
    cb_data->user_sess_cb_param = sess_cb_param;
    cb_data->pkg_id = pkg_id;
    cb_data->ctx = ctx;
    cb_data->ring_handle = ring_handle;
    cb_data->algo = algo;
    cb_data->mode = mode;
    cb_data->pkg_mode = ctx->pkg_mode;
    cb_data->update_final = final;
    
    cb_data->user_src = (uint64_t)src;
    cb_data->src_len = src_len;
    cb_data->dst_len = dst_len;
    cb_data->dst_index = 0;

    cb_data->op_type = PUB_OP;

    if (dst_len != 0) {
        offset = ((uint64_t)dst) & (PAGE_SIZE-1);
        cb_data->nr_pages = DIV_ROUND_UP(offset + dst_len, PAGE_SIZE);
        cb_data->pages = (struct page **) kzalloc(sizeof(struct page) * cb_data->nr_pages, GFP_KERNEL);
        ret = get_user_pages_fast((uint64_t)dst & PAGE_MASK, cb_data->nr_pages, 1, cb_data->pages);
        if(ret != cb_data->nr_pages)
        {
            for(i=0; i<ret; i++) {
                put_page(cb_data->pages[i]);
            }
            kfree(cb_data->pages);
            pr_err("get_user_pages_fast failed\n");
            goto err;
        }
        cb_data->vmap_dst = vmap(cb_data->pages, cb_data->nr_pages, VM_MAP, PAGE_KERNEL);
        cb_data->kernel_dst = cb_data->vmap_dst + offset;
    }

    if(cb_data->sess_mode == HX_ASYNC_POLLING_MODE)
    {
        ring->sess_mode = HX_ASYNC_POLLING_MODE;

        s_cookie = get_cookie(ring_handle);
        if (s_cookie == NULL) {
            LOG_ERROR("alloc failed s_cookie, pkg_id = %d\n", cb_data->pkg_id);
            ret = HX_RET_NO_MEM;
            goto err;
        } else {
            cb_data->src_virt = s_cookie->virt;
            cb_data->src_phy = s_cookie->phy;
            cb_data->src_cookie = s_cookie;

            ctx->ring_handle = ring_handle;

            copy_from_user(cb_data->src_virt, src, src_len);

            ret = pub_queue_send(ring_handle, ctx, cb_data);    
        }
    }
    else
    {
        ring->sess_mode = HX_SYNC_MODE;

        if(algo == HX_PQC)
            ret = build_pqc_request(ring_handle, (void *)cb_data, bus, mode, src, src_len, dst, dst_len);
        else if(algo == HX_TRNG)
            ret = build_trng_request(ring_handle, (void *)cb_data, dst_len);
        else
            ret = build_pub_request(ring_handle, (void *)cb_data, algo, mode, src, src_len, dst, dst_len);
    }
 
err:
    if (ret != 0) {
        vunmap(cb_data->vmap_dst);
        for(i=0; i < cb_data->nr_pages; i++) {
            set_page_dirty(cb_data->pages[i]);
            put_page(cb_data->pages[i]);
        }
        kfree(cb_data->pages);

        if ((cb_data->sess_mode == 1) && ((void *)cb_data->user_sess_page_info != NULL)) {
            p_info = (hx_page_info_t *)cb_data->user_sess_page_info;
            for (int i = 0; i < cb_data->user_sess_page_num; ++i) {
                put_page((struct page *)p_info[i].page);
            }
            kfree((void *)cb_data->user_sess_page_info);
        }

        if (cb_data != NULL)
            kfree(cb_data);
    }
    return ret;
}

int user_to_kernel(uint64_t user_virt, uint32_t len, uint32_t page_num, hx_page_info_t *k_virt)
{
    int i = 0;
    int rc = 0;
    struct page **user_pages;
    if (page_num <= 0)
        return -1;
    user_pages = kzalloc(page_num * sizeof(struct page *), GFP_KERNEL);
    // rcu_read_lock();
    rc = get_user_pages_fast((unsigned long)(user_virt), page_num, 1, user_pages);
    // rcu_read_unlock();
    if (rc != page_num) {
        kfree(user_pages);
        return -1;
    }
    for (i = 0; i < page_num; i++) {
        k_virt[i].addr = (uint64_t)page_address(user_pages[i]);
        k_virt[i].page = user_pages[i];
        if (i == 0) {
            k_virt[i].offset = (uint32_t)offset_in_page(user_virt);
            k_virt[i].size = page_num > 1 ? (uint32_t)(PAGE_SIZE - offset_in_page(user_virt)) : len;
            len -= k_virt[i].size;
        } else if (i == page_num - 1) {
            k_virt[i].offset = 0;
            k_virt[i].size = len;
            len -= k_virt[i].size;
        } else {
            k_virt[i].offset = 0;
            k_virt[i].size = PAGE_SIZE;
            len -= k_virt[i].size;
        }

        //    LOG_DEBUG("k_virt[%d]=%p offset=%d size=%d len=%d page=%p \n", i,(void *)k_virt[i].addr,k_virt[i].offset, k_virt[i].size,len,(void *)k_virt[i].page);
    }
    kfree(user_pages);
    return 0;
}

int get_page_nums(uint64_t user_virt, uint32_t len)
{
    int page_num = 0;
    int first = (user_virt & PAGE_MASK) >> PAGE_SHIFT;
    int last = ((user_virt + len - 1) & PAGE_MASK) >> PAGE_SHIFT;
    page_num = last - first + 1;
    // LOG_DEBUG("first=%x last=%x page_num = %d \n",first, last, page_num);
    return page_num;
}
