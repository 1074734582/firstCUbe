#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h> 
#include <sys/syscall.h> 

#include "log.h"
#include "api.h"
#include "dev.h"

#define HX_POLL_MAX_SIZE       HX_MAX_POLL_ITEMS

#define O_RDWR		     02

int hx_open_dev( const char *dev, pthread_t *ptid)
{
    poll_thread_param_t *poll_thread_param;
    dev_name_t name_info;
    int fd = open("/dev/hx-drv", O_RDWR);
    if (fd < 0) 
    {
        printf("#FAIL open hx-drv failed\n");
        return HX_RET_NO_DEVICE;
    }
    memset(&name_info,0x00,sizeof(dev_name_t));
    memcpy(name_info.dev_name,dev,strlen(dev));
    if(ioctl(fd, IOCTL_OPEN_DEV, &name_info) < 0 )
    {
        printf("#FAIL OPEN failed\n");
        hx_close_dev(fd, NULL);
        return HX_RET_NO_DEVICE;
    }
    if(ptid != NULL)
    {
        poll_thread_param=malloc(sizeof(poll_thread_param_t));
        poll_thread_param->fd = fd;
        poll_thread_param->poll_wait_us = 10;
        poll_thread_param->poll_thread_flag = 0;
        if(0 != pthread_create(ptid, NULL, hx_poll_pthread, (void *)poll_thread_param))
        {
            printf("#FAIL create thread failed\n");
            free(poll_thread_param);
            hx_close_dev(fd, NULL);
            return HX_RET_NO_DEVICE;
        }

        while(!poll_thread_param->poll_thread_flag)
        {
            usleep(1000*10);
            //printf("Wait poll thread ready\r\n");
        }
    }
    return fd;
}

int hx_close_dev(int fd, pthread_t *ptid)
{
    void *status;
   
    if(ptid != NULL)
    {
        pthread_cancel(*ptid);
        pthread_join(*ptid, &status);
    }
   
    if(close(fd) < 0)
    {
        printf("#FAIL close hx-drv failed\n");
        return HX_RET_NO_DEVICE;
    }
    return HX_RET_SUCCESS;
}

static int hx_ioctl_sym_get_ctx(int fd, uint64_t *drv_ctx)
{
    ioctl_param_t param;
    hx_ret_code_t ret = HX_RET_TIMEOUT;

    hx_assert((ret = ioctl(fd, IOCTL_CTX_ALLOC, &param)) == HX_RET_SUCCESS, -errno);
    *drv_ctx = param.ctx;
    
    return HX_RET_SUCCESS;
}

static int hx_ioctl_sym_free(int fd, uint64_t drv_ctx)
{
    ioctl_param_t param;
    param.ctx = drv_ctx;
    hx_ret_code_t ret = HX_RET_TIMEOUT;
    hx_assert((ret = ioctl(fd, IOCTL_CTX_FREE, &param)) == HX_RET_SUCCESS, -errno);

    return HX_RET_SUCCESS;
}

static int hx_ioctl_cipher_status(hx_rpu_ctx_t *ctx)
{
    hx_cipher_t *hx_cipher = (hx_cipher_t *)(ctx->cipher);

    ioctl(hx_cipher->fd, IOCTL_CIPHER_STATUS, NULL);

    return -errno;
}

static int hx_ioctl_cipher_do(hx_cipher_t *ctx)
{
    ioctl_param_t param;
    hx_ret_code_t ret = HX_RET_TIMEOUT;
    memset(&param, 0x00, sizeof(ioctl_param_t));
    
    param.ctx = ctx->drv_ctx;
    param.force_update = ctx->force_update;

    param.algo = ctx->algo;
    param.mode = ctx->mode;
    param.dir = ctx->enc;

    param.key_len = ctx->key_len;
    param.iv_len = ctx->iv_len;
    param.aad_len = ctx->aad_len;
    param.tag_len = ctx->tag_len;
    param.key = (uint64_t)(ctx->key);
    param.iv = (uint64_t)(ctx->iv);
    param.aad = (uint64_t)(ctx->aad);
    param.tag = (uint64_t)(ctx->tag);

    param.src_len = ctx->srclen;
    param.dst_len = ctx->dstlen;
    param.src = (uint64_t)(ctx->src);
    param.dst = (uint64_t)(ctx->dst);
    
    param.item.sess = (uint64_t)(ctx->sess);
    param.item.pid  = getpid();
    param.item.mode = ctx->sess->mode;
    param.item.pack_id = ctx->sess->pack_id;
    param.kek = 0;
    param.key_index = ctx->key_index;
    param.final = ctx->final;
    param.total_len = ctx->total_len;
    param.pkg_mode = ctx->pkg_mode;

    ret = ioctl(ctx->fd, IOCTL_CIPHER_OP, &param);
    if(ret == HX_RET_SUCCESS)
    {
        ctx->force_update = 0;
        ctx->sess->pack_id = param.item.pack_id;
        return HX_RET_SUCCESS;
    }

    return -errno;
}

int hx_cipher_init(hx_rpu_ctx_t *ctx)
{
    hx_cipher_t *hx_cipher = (hx_cipher_t *)malloc(sizeof(hx_cipher_t));
    if(hx_cipher == NULL)
    {
        return HX_RET_NO_MEM;
    }

    hx_cipher->fd = ctx->fd;
    hx_cipher->algo = ctx->algo_id;
    hx_cipher->mode = ctx->algo_mode;

    hx_cipher->sess = &ctx->sess;
    hx_cipher->sess->mode = ctx->api_mode;
    hx_cipher->enc = ctx->algo_dir;
    hx_cipher->key_len = ctx->keylen;
    hx_cipher->iv_len = ctx->ivlen;
    hx_cipher->aad_len = ctx->aadlen;
    hx_cipher->tag_len = ctx->taglen;
    hx_cipher->key_set = 0;
    hx_cipher->iv_gen = 0;
    hx_cipher->final =0;   

    hx_ret_code_t ret = HX_RET_TIMEOUT;
    hx_assert((ret = hx_ioctl_sym_get_ctx(ctx->fd, &hx_cipher->drv_ctx)) == HX_RET_SUCCESS, ret);

    if(ctx->keylen)
        memcpy(hx_cipher->key, ctx->key, ctx->keylen);

    if(ctx->ivlen)
        memcpy(hx_cipher->iv, ctx->iv, ctx->ivlen);
    
    if(ctx->aadlen)
        memcpy(hx_cipher->aad, ctx->aad, ctx->aadlen);

    if(ctx->taglen)
    {
        memcpy(hx_cipher->tag, ctx->tag, ctx->taglen);
    }

    ctx->cipher = (uint8_t *)hx_cipher;

    return HX_RET_SUCCESS;
}

int hx_cipher_update(hx_rpu_ctx_t *ctx, uint8_t *in, uint32_t inlen, uint8_t *out, uint8_t final, 
    hx_sess_package_e package, uint64_t pack_id)
{
    hx_cipher_t *hx_cipher = (hx_cipher_t *)(ctx->cipher);
    hx_ret_code_t ret = HX_RET_TIMEOUT;
    uint32_t dstlen = 0;

    if(final)
        hx_cipher->final = 1;
    
    if(package == HX_FULL_PACKAGE)
    {
        if(pack_id == 0)
            hx_cipher->pkg_mode = HX_PACKAGE_START;
        else if(final)
            hx_cipher->pkg_mode = HX_PACKAGE_END;
        else
            hx_cipher->pkg_mode = HX_PACKAGE_MIDDLE;
    }   
    else
        hx_cipher->pkg_mode = HX_PACKAGE_COMPLETE;

    hx_cipher->sess->pack_id = pack_id;

    if(package == HX_FULL_PACKAGE && hx_cipher->mode == HX_CIPHER_CTR)
    {
        memset(&hx_cipher->iv, 0, hx_cipher->iv_len);
        uint64_t *id = (uint64_t *)&hx_cipher->iv;
        *id = pack_id;
        //Change iv from little endian to big endian to match rpu
        for(int i=0; i<8; i++)
        {
            hx_cipher->iv[15-i] =  hx_cipher->iv[i];
            hx_cipher->iv[i] = 0;
        }
        hx_cipher->force_update = 1;
    }

    if((hx_cipher->mode == HX_CIPHER_CMAC) || (hx_cipher->mode == HX_CIPHER_CBC_MAC))
        dstlen = ctx->dstlen;
    else
        dstlen = inlen;

    hx_cipher->src = in;
    hx_cipher->dst = out;
    hx_cipher->srclen = inlen;
    hx_cipher->dstlen = dstlen;

    if(package == HX_FULL_PACKAGE)
        hx_cipher->total_len = ctx->srclen;
    else
        hx_cipher->total_len = inlen;

    ret = hx_ioctl_cipher_do(hx_cipher);

    if((hx_cipher->sess->mode == HX_SYNC_MODE) && (ret == HX_RET_SUCCESS))
    {
        hx_log_dump(out, inlen, "HX CIPHER OUT[%d]:", inlen);
    }
    return ret;
}

int hx_cipher_cleanup(hx_rpu_ctx_t *ctx)
{
    hx_cipher_t *hx_cipher = (hx_cipher_t *)(ctx->cipher);

    hx_ret_code_t ret = HX_RET_TIMEOUT;

    while((ret = hx_ioctl_sym_free(hx_cipher->fd, hx_cipher->drv_ctx) != HX_RET_SUCCESS))
        usleep(100);

    hx_cipher->final = 0;

    free(hx_cipher);

    return HX_RET_SUCCESS;
}

int hx_cipher_onetime(hx_rpu_ctx_t *ctx)
{
    hx_cipher_t cipher;
    memset(&cipher, 0, sizeof(hx_cipher_t));
    hx_cipher_t *hx_cipher = &cipher;
    hx_ret_code_t ret = HX_RET_TIMEOUT;

    hx_cipher->fd = ctx->fd;
    hx_cipher->algo = ctx->algo_id;
    hx_cipher->mode = ctx->algo_mode;

    hx_cipher->sess = &ctx->sess;
    hx_cipher->sess->mode = ctx->api_mode;
    hx_cipher->enc = ctx->algo_dir;
    hx_cipher->key_len = ctx->keylen;
    hx_cipher->iv_len = ctx->ivlen;
    hx_cipher->aad_len = ctx->aadlen;
    hx_cipher->tag_len = ctx->taglen;
    hx_cipher->iv_gen = 0;
    hx_cipher->drv_ctx = 0;
    hx_cipher->total_len = ctx->srclen;
    hx_cipher->force_update = 1;
    hx_cipher->pkg_mode = HX_PACKAGE_COMPLETE;

    hx_cipher->final =1;   
 
    if(ctx->keylen)
        memcpy(hx_cipher->key, ctx->key, ctx->keylen);

    if(ctx->ivlen)
        memcpy(hx_cipher->iv, ctx->iv, ctx->ivlen);
    
    if(ctx->aadlen)
        memcpy(hx_cipher->aad, ctx->aad, ctx->aadlen);

    if(ctx->taglen)
        memcpy(hx_cipher->tag, ctx->tag, ctx->taglen);

    hx_cipher->sess->state = HX_RET_DEVICE_BUSY;
    hx_cipher->sess->flag = 0;

    hx_cipher->src = ctx->src;
    hx_cipher->dst = ctx->dst;
    hx_cipher->srclen = ctx->srclen;
    hx_cipher->dstlen = ctx->dstlen;

    ret = hx_ioctl_cipher_do(hx_cipher);

    hx_cipher->sess->flag = 1;

    return ret;
}

static int hx_ioctl_md_do(hx_md_t *ctx)
{
    ioctl_param_t param;
    hx_ret_code_t ret = HX_RET_TIMEOUT;

    memset(&param, 0x00, sizeof(ioctl_param_t));

    param.ctx = ctx->drv_ctx;
    param.algo = ctx->algo;
    param.mode = ctx->mode;

    param.src_len = ctx->srclen;
    param.dst_len = ctx->dstlen;
    param.src = (uint64_t)(ctx->src);
    param.dst = (uint64_t)(ctx->dst);

    param.item.sess = (uint64_t)(ctx->sess);
    param.item.mode = ctx->sess->mode;
    param.item.pid  = getpid();
    param.item.state = ctx->sess->state;
    param.item.pack_id = ctx->sess->pack_id;

    param.pkg_mode = ctx->pkg_mode;
    param.final = ctx->final;
    param.total_len = ctx->total_len;
    param.key_len = ctx->key_len;
    
    if(ctx->mode == HX_HASH_MODE)
        ret = ioctl(ctx->fd, IOCTL_HASH_OP, &param);
    else if(ctx->mode == HX_HMAC_MODE)
    {
        param.key = (uint64_t)ctx->key;
        ret = ioctl(ctx->fd, IOCTL_HMAC_OP, &param);
    }
    else if(ctx->mode == HX_PRF_MODE)
    {
        param.src_len = ctx->srclen + param.key_len;
        param.aad_len = ctx->dstlen;
        param.key = (uint64_t)ctx->key;
        ret = ioctl(ctx->fd, IOCTL_PRF_OP, &param);  
    }

    if(ret == HX_RET_SUCCESS)
    {
        ctx->sess->pack_id = param.item.pack_id;
        return HX_RET_SUCCESS;
    }

    return -errno;
}

int hx_md_init(hx_rpu_ctx_t *ctx)
{
    hx_md_t *hx_md = (hx_md_t *)malloc(sizeof(hx_md_t));

    hx_md->fd = ctx->fd;
    hx_md->algo = ctx->algo_id;
    hx_md->mode = ctx->algo_mode;

    hx_md->sess = &ctx->sess;
    hx_md->sess->mode = ctx->api_mode;
    hx_md->sess->state = HX_RET_DEVICE_BUSY;

    hx_md->final = 0;
    hx_md->total_len = 0;
    hx_md->num = 0;
    
    if(ctx->algo_mode == HX_HMAC_MODE)
    {
        memcpy(hx_md->key, ctx->key, ctx->keylen);
        hx_md->key_len = ctx->keylen;
    }

    hx_ret_code_t ret = HX_RET_TIMEOUT;
    hx_assert((ret = hx_ioctl_sym_get_ctx(ctx->fd, &hx_md->drv_ctx)) == HX_RET_SUCCESS, ret);

    ctx->cipher = (uint8_t *)hx_md;

    return ret;
}

int hx_md_update(hx_rpu_ctx_t *ctx, uint8_t *in, uint32_t in_len, uint8_t *out, uint8_t final, 
    hx_sess_package_e package, uint64_t pack_id)
{
    hx_md_t *hx_md = (hx_md_t *)(ctx->cipher);

    hx_ret_code_t ret = HX_RET_TIMEOUT;

    if(final)
        hx_md->final = 1;

    if(package == HX_FULL_PACKAGE)
    {
        if(pack_id == 0)
            hx_md->pkg_mode = HX_PACKAGE_START;
        else if(final)
            hx_md->pkg_mode = HX_PACKAGE_END;
        else
            hx_md->pkg_mode = HX_PACKAGE_MIDDLE;
    }   
    else
        hx_md->pkg_mode = HX_PACKAGE_COMPLETE;

    hx_md->sess->pack_id = pack_id;
    hx_md->sess->flag = 0;
    hx_md->sess->state = HX_RET_DEVICE_BUSY;

    hx_md->total_len += in_len;
    hx_md->num = in_len;

    hx_md->srclen = in_len;
    hx_md->dstlen = HX_HASH_HMAC_OUT_SIZE;
    hx_md->src = in;
    hx_md->dst = out; 

    ret = hx_ioctl_md_do(hx_md);
    
    return ret;
}

int hx_md_cleanup(hx_rpu_ctx_t *ctx)
{
    hx_md_t *hx_md = (hx_md_t *)(ctx->cipher);

    hx_ret_code_t ret = HX_RET_TIMEOUT;

    while((ret = hx_ioctl_sym_free(hx_md->fd, hx_md->drv_ctx) != HX_RET_SUCCESS))
        usleep(100);

    hx_md->final = 0;

    free(hx_md);

    return ret;
}

int hx_md_onetime(hx_rpu_ctx_t *ctx)
{
    hx_md_t md;
    memset(&md, 0, sizeof(hx_md_t));
    hx_md_t *hx_md = &md;

    hx_ret_code_t ret = HX_RET_TIMEOUT;

    hx_md->fd = ctx->fd;
    hx_md->algo = ctx->algo_id;
    hx_md->mode = ctx->algo_mode;

    hx_md->sess = &ctx->sess;
    hx_md->sess->mode = ctx->api_mode;
    hx_md->sess->flag = 0;
    hx_md->sess->state = HX_RET_DEVICE_BUSY;
    hx_md->sess->pack_id = 0;

    hx_md->pkg_mode = HX_PACKAGE_COMPLETE;
    hx_md->final = 1;   
    hx_md->total_len = ctx->srclen;

    if(hx_md->mode == HX_HMAC_MODE || hx_md->mode == HX_PRF_MODE) 
    {
        memcpy(hx_md->key, ctx->key, ctx->keylen);
        hx_md->key_len = ctx->keylen;
    }

    hx_md->srclen = ctx->srclen;
    hx_md->dstlen = ctx->dstlen;
    hx_md->src = ctx->src;
    hx_md->dst = ctx->dst; 

    ret = hx_ioctl_md_do(hx_md);

    hx_md->sess->flag = 1;
    return ret;
}

int hx_rpu_md_once(hx_rpu_ctx_t *rpu_ctx)
{
    int ret = 0;

    while((ret = hx_md_onetime(rpu_ctx)) != HX_RET_SUCCESS)
    {
        if(ret == HX_RET_TIMEOUT)
            break;
        usleep(1);
    } 

    return ret;
}

int hx_rpu_md_package(hx_rpu_ctx_t *ctx)
{
    uint8_t final = 0;
    uint8_t *indata = NULL;
    uint8_t *outdata = NULL;
    int ret = 0;
    uint32_t srclen = ctx->srclen;
    uint32_t steplen = ctx->steplen;
    uint32_t times = 0;
    uint32_t mod = 0;
    
    times = srclen / steplen;
    mod = srclen % steplen;
    if(mod)
        times += 1;

    indata = ctx->src;
    outdata = ctx->dst;

    hx_md_init(ctx);

    for(int i = 0; i < times; i++)
    {
        if(i == times -1)
        {
            final = 1;
            if(mod)
                steplen = mod;
        }

        while((ret = hx_md_update(ctx, indata, steplen, outdata, final, HX_FULL_PACKAGE, i)) != HX_RET_SUCCESS)
        {
            if(ret == HX_RET_TIMEOUT)
                break;
            usleep(1);
        } 
            
        indata += steplen;
    }

    hx_md_cleanup(ctx);

    return ret;
}

int hx_rpu_cipher_once(hx_rpu_ctx_t *ctx)
{
    int ret = 0;

    while((ret = hx_cipher_onetime(ctx)) != HX_RET_SUCCESS)
    {
        if(ret == HX_RET_TIMEOUT)
            break;
        usleep(1);
    }
        
    return ret;
}

int hx_rpu_cipher_stream(hx_rpu_ctx_t *ctx)
{
    uint8_t final = 0;
    uint8_t *indata = NULL;
    uint8_t *outdata = NULL;
    int ret = 0;
    uint32_t srclen = ctx->srclen;
    uint32_t steplen = ctx->steplen;
    uint32_t times = 0;
    uint32_t mod = 0;
    
    times = srclen / steplen;
    mod = srclen % steplen;
    if(mod)
        times += 1;

    indata = ctx->src;
    outdata = ctx->dst;

    hx_cipher_init(ctx);

    for(int i = 0; i < times; i++)
    {
        if(i == times -1)
        {
            final = 1;
            if(mod)
                steplen = mod;
        }

        while((ret = hx_cipher_update(ctx, indata, steplen, outdata, final, HX_INDEPENDENT_PACKAGE, i)) != HX_RET_SUCCESS)
        {
            if(ret == HX_RET_TIMEOUT)
                break;
            usleep(1);
        }
            
        indata += steplen;
        outdata += steplen;
    }

    if(ctx->api_mode == HX_ASYNC_POLLING_MODE)
    {
        while(ctx->sess.state != HX_RET_SUCCESS || ctx->sess.pack_count < times)
        {
            if(hx_ioctl_cipher_status(ctx) == HX_RET_TIMEOUT)
            {
                ret = HX_RET_TIMEOUT;
                break;
            }       
            usleep(10);
        }
        printf("hx_cipher.sess.state = %lu, pack_count = %lu\n", ctx->sess.state, ctx->sess.pack_count);       
    }

    if(ret != HX_RET_TIMEOUT)
        hx_cipher_cleanup(ctx);

    return ret;
}

int hx_rpu_cipher_package(hx_rpu_ctx_t *ctx)
{
    uint8_t final = 0;
    uint8_t *indata = NULL;
    uint8_t *outdata = NULL;
    int ret = 0;
    int mode = ctx->algo_mode;
    uint32_t srclen = ctx->srclen;
    uint32_t steplen = ctx->steplen;
    uint32_t times = 0;
    uint32_t mod = 0;
    int pack_id = 0;

    times = srclen / steplen;
    mod = srclen % steplen;
    if(mod)
        times += 1;

    indata = ctx->src;
    outdata = ctx->dst;

    hx_cipher_init(ctx);

    for(int i = 0; i < times; i++)
    {
        if(i == times -1)
        {
            final = 1;
            if(mod)
                steplen = mod;
        }

        if(mode != HX_CIPHER_CTR)
            pack_id = i;

        while((ret = hx_cipher_update(ctx, indata, steplen, outdata, final, HX_FULL_PACKAGE, pack_id)) != HX_RET_SUCCESS)
        {
            if(ret == HX_RET_TIMEOUT)
                break;
            usleep(1);
        }

        indata += steplen;
        if((mode != HX_CIPHER_CMAC)&&(mode != HX_CIPHER_CBC_MAC))
            outdata += steplen;

        if(mode == HX_CIPHER_CTR)
            pack_id += steplen / 16;
    }

    hx_cipher_cleanup(ctx);

    return ret;
}

int hx_rpu_cipher(hx_rpu_ctx_t *rpu_ctx)
{
    int ret = HX_RET_SUCCESS;
    
    if(rpu_ctx->algo_id >= HX_ALGO_SM3)
    {
        if(rpu_ctx->cipher_mode == HX_CIPHER_ONCE)
            ret = hx_rpu_md_once(rpu_ctx);
        else if(rpu_ctx->cipher_mode == HX_CIPHER_PACKAGE)
            ret = hx_rpu_md_package(rpu_ctx);
    }
    else
    {
        if(rpu_ctx->cipher_mode == HX_CIPHER_ONCE)
            ret = hx_rpu_cipher_once(rpu_ctx);       
        else if(rpu_ctx->cipher_mode == HX_CIPHER_PACKAGE)
            ret = hx_rpu_cipher_package(rpu_ctx);
        else if(rpu_ctx->cipher_mode == HX_CIPHER_STREAM)
            ret = hx_rpu_cipher_stream(rpu_ctx);
    }

    return ret;
}

int hx_pub_init(hx_cipher_t *ctx)
{  
    hx_ret_code_t ret = HX_RET_TIMEOUT;
    hx_assert((ret = hx_ioctl_sym_get_ctx(ctx->fd, &ctx->drv_ctx)) == HX_RET_SUCCESS, ret);

    return HX_RET_SUCCESS;
}

int hx_pub_cleanup(hx_cipher_t *ctx)
{
    hx_ret_code_t ret = HX_RET_TIMEOUT;

    while((ret = hx_ioctl_sym_free(ctx->fd, ctx->drv_ctx) != HX_RET_SUCCESS))
        usleep(100);

    free(ctx);

    return HX_RET_SUCCESS;
}

int hx_pub_status(hx_cipher_t *ctx)
{
    ioctl(ctx->fd, IOCTL_CIPHER_STATUS, NULL);

    return -errno;
}

int hx_ioctl_pub_do(hx_cipher_t *ctx)
{
    ioctl_param_t param;
    hx_ret_code_t ret = HX_RET_TIMEOUT;
    memset(&param, 0x00, sizeof(ioctl_param_t));
    
    param.ctx = ctx->drv_ctx;
    param.force_update = ctx->force_update;

    param.algo = ctx->algo;
    param.mode = ctx->mode;

    param.src_len = ctx->srclen;
    param.dst_len = ctx->dstlen;
    param.src = (uint64_t)(ctx->src);
    param.dst = (uint64_t)(ctx->dst);
    
    param.item.sess = (uint64_t)(ctx->sess);
    param.item.pid  = getpid();
    param.item.mode = ctx->sess->mode;
    param.item.pack_id = ctx->pack_id;
    param.final = ctx->final;
    param.total_len = ctx->total_len;
    param.pkg_mode = ctx->pkg_mode;
    param.bus = ctx->bus;

    ret = ioctl(ctx->fd, IOCTL_PUB_OP, &param);
    if(ret == HX_RET_SUCCESS)
    {
        ctx->force_update = 0;
        return HX_RET_SUCCESS;
    }

    return -errno;
}

void *hx_poll_pthread(void *poll_thread_param)       
{
    poll_thread_param_t *temp = (poll_thread_param_t *)poll_thread_param;
    ioctl_item_t item[HX_POLL_MAX_SIZE];
    memset(item, 0, sizeof(ioctl_item_t) * HX_POLL_MAX_SIZE);
    hx_session_t *sess=NULL;
    poll_param_t poll_param;
    poll_param.item_addr = (uint64_t)item;
    poll_param.pid = getpid();

    showTaskTid(__FUNCTION__);
    attach_cpu(HX_POLL_BIND);
    temp->poll_thread_flag = 1;

    for (;;)
    {
        pthread_testcancel();
        if(ioctl(temp->fd, IOCTL_POLLING_ALL, &poll_param) == HX_RET_SUCCESS)
        {
            for (int i = 0; i < HX_POLL_MAX_SIZE; ++i)
            {
                if(item[i].sess)
                {
                    sess = (hx_session_t *)item[i].sess;
                    sess->state = item[i].state;
                    while(!sess->flag);
                    sess->cb(sess->cb_param);
                    item[i].sess = 0;
                    printf("--->>> do callback function  %d times !\r\n", i);
                }
            }
        }
    }
    
    return NULL;
}

void hx_dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    printf("%s[%d]", info, len);
    for (int i = 0; i < len; i++) {
        printf("%s0x%02X%s", i % 16 == 0 ? "\n     ":" ", buf[i], i == len - 1 ? "\n":"");
    }
}

void hx_dump4b_buf(char *info, uint32_t *buf, uint32_t len)
{
    printf("%s[%d]", info, len);
    for (int i = 0; i < len; i++) {
        printf("%s0x%08X%s", i % 8 == 0 ? "\n     ":" ", buf[i], i == len - 1 ? "\n":"");
    }
}

void hx_dump_data(char *info, uint8_t *buf, uint32_t len)
{
    printf("uint8_t %s[%d] = {\r\n", info, len);
    for(int i=0; i<len; i++)
    {
        printf("0x%02x,", buf[i]);
        if((i+1) % 16 == 0)
            printf("\r\n");
    }
    printf("};\r\n");
}

void hx_dump_data32(char *info, uint32_t *buf, uint32_t len)
{
    printf("int %s[%d] = {\r\n", info, len/4);
    for(int i=0; i<len/4; i++)
    {
        printf("0x%08x,", buf[i]);
        //if((i+1) % 16 == 0)
            printf("\r\n");
    }
    printf("};\r\n");
}

int attach_cpu(int cpu_index)
{
    int cpu_num = sysconf(_SC_NPROCESSORS_CONF);
    if (cpu_index < 0 || cpu_index >= cpu_num)
    {
        printf("cpu index ERROR!\n");
        return -1;
    }
    
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu_index, &mask);

    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        printf("set affinity np ERROR!\n");
        return -1;
    }

    return 0;
}

void showTaskTid(const char *s)
{
  pid_t tid = (pid_t) syscall (SYS_gettid);
  printf("%s, tid = %d\n", s, tid);
}

