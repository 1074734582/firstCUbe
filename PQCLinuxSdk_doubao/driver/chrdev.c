#include <asm/cacheflush.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/param.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <generated/uapi/linux/version.h>

#include "algo.h"
#include "chrdev.h"
#include "common.h"
#include "ioctl_cmds.h"
#include "ring.h"

#include "debug.h"
atomic64_t ctx_cnt;
extern int g_rpu_ring_process;
extern hx_wait_t *dequeue_wait;

static hx_ring_handle_t *hx_cur_next_rpu_ring(struct file *filp)
{
    uint32_t index = 0;
    fp_private_t *fp_priv = filp->private_data;
    index = atomic64_inc_return(&fp_priv->rpu_sel);
    return fp_priv->rpu_ring_handle[(index - 1) % fp_priv->valid_rpu_ring_num];
}

/* open device ,malloc private data */
static int hx_dev_open(struct inode *inode, struct file *filp)
{
    int i = 0;
    fp_private_t *fp_priv;
    LOG_DEBUG("%s \n", __func__);
    fp_priv = kzalloc(sizeof(fp_private_t), GFP_KERNEL);
    filp->private_data = fp_priv;
    return 0;
}

/* close device free private data */
static int hx_dev_close(struct inode *inode, struct file *filp)
{
    fp_private_t *fp_priv;
    LOG_DEBUG("%s \n\n", __func__);
    fp_priv = filp->private_data;

    kfree(filp->private_data);
    return 0;
}

/* ioctl interface */
static long hx_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    int op = 0;
    int i = 0;
    int state = 0;
    static int tmp_count = 0;
    static int tmp_hash_op_count = 0;
    static int tmp_hmac_op_count = 0;
    static int tmp_prf_op_count = 0;
    struct hx_accel_dev *accel_dev = NULL;
    uint32_t *reg_data;
    int model = 0;
    ioctl_reg_t reg;
    ioctl_dev_info_t dev_info;
    dev_name_t name_info;
    char *names;
    session_t *ctx = NULL;
    session_t *ctx_d = NULL;
    ioctl_param_t param;
    poll_param_t poll_param;
    ioctl_common_t comm_param;
    hx_dev_rp_info_t *rp_info;
    ioctl_ring_info_t ring_info;
    ring_info_t *pinfo = NULL;
    ring_info_t sinfo;
    ioctl_performance_test_t perf_param;

    hx_ring_handle_t *ring_handle;
    uint8_t *data;
    hx_wait_t *sync_wait = NULL;
    fp_private_t *fp_priv = filp->private_data;
    ring_handle_t *ring;

    switch (cmd) {
    /*
        get special name device's ring handle and save to privata data
    */
    case IOCTL_OPEN_DEV:
        ret = copy_from_user(&name_info, (void *)arg, sizeof(dev_name_t));
        if (ret != 0)
            return HX_RET_ARG_ADDR_ERROR; // bad address
        accel_dev = hx_devmgr_get_dev_by_name(name_info.dev_name);
        if (accel_dev == NULL) {
            LOG_ERROR("Open %s failed \n", name_info.dev_name);
            return HX_RET_NO_DEVICE; // no such device
        } else {
            LOG_DEBUG("open [%s] success\n", name_info.dev_name);
        }
        rp_info = accel_dev->rp_info;

        ret = try_module_get(accel_dev->owner);
        if (ret == 0) {
            printk("module init error\n");
        }

        // set fp_priv bulk ring
        fp_priv->valid_rpu_ring_num = g_rpu_ring_process;
        for (i = 0; i < fp_priv->valid_rpu_ring_num; i++) {
            fp_priv->rpu_ring_handle[i] = rp_info->rpu_ring_handle[i];
        }

        fp_priv->accel_dev = accel_dev;
        name_info.id = accel_dev->dev_id;
        ret = copy_to_user((void *)arg, &name_info, sizeof(dev_name_t));

        ctx_list_init();
        break;
    /*
        alloc CTX ,the CTX used for cipher/hash algo. for saving mid data
    */
    case IOCTL_CTX_ALLOC:
        ctx = kzalloc(sizeof(session_t), GFP_KERNEL);
        LOG_DEBUG("allc ctx=%p \n", ctx);
        if (ctx == NULL)
            return HX_RET_NO_MEM;
        ctx->pkg_count = 0;
        mutex_init(&ctx->request_queue_lock);
        ctx_list_add(ctx);
        ret = copy_to_user((void *)arg, &ctx, sizeof(ctx));
        atomic64_inc(&ctx_cnt);
        wake_up_interruptible(&dequeue_wait->wq);
        dequeue_wait->condition = 1;
        LOG_DEBUG("ctx_cnt=%d \n", atomic64_read(&ctx_cnt));
        break;

    case IOCTL_CTX_FREE:
        ret = copy_from_user(&param, (void *)arg, sizeof(ctx));
        if (ret != 0)
            return HX_RET_ARG_ADDR_ERROR;
        ctx = (session_t *)(param.ctx);
        if (IS_ERR(ctx) || (ctx == NULL)) {
            LOG_ERROR("ctx=%p error \n", ctx);
            return HX_RET_CTX_ERROR;
        }
        LOG_DEBUG("free ctx=%p \n", ctx);
        if (ctx->status != HX_RET_FAILED) {
            ctx_list_remove(ctx);
            kfree(ctx);
            atomic64_dec(&ctx_cnt);
            dequeue_wait->condition = 0;
            LOG_DEBUG("ctx_cnt=%d \n", atomic64_read(&ctx_cnt));
        } else {
            ret = HX_RET_DEVICE_BUSY;
            LOG_ERROR("ctx=%p inusing \n", ctx);
        }
        break;

    case IOCTL_CTX_INIT:
        printk(">>> do IOCTL_CTX_INIT \n");
        ret = copy_from_user(&param, (void *)arg, sizeof(ioctl_param_t));
        if (ret != 0)
            return HX_RET_ARG_ADDR_ERROR;
        ctx = (session_t *)(param.ctx);
        if (IS_ERR(ctx) || (ctx == NULL)) {
            LOG_ERROR("ctx=%p error \n", ctx);
            return HX_RET_CTX_ERROR;
        }

        LOG_DEBUG("init ctx=%p algo=%d mode=%d dir=%d \n", ctx, ctx->algo, ctx->mode, ctx->dir);
        break;

    case IOCTL_POLLING_ALL:
        ret = copy_from_user(&poll_param, (void *)arg, sizeof(poll_param_t));
        if (ret != 0) {
            printk(">>> poll failed : HX_RET_ARG_ADDR_ERROR! %d times \n", tmp_count);
            return HX_RET_ARG_ADDR_ERROR;
        }
        ret = -1;

        ret = check_state_all(fp_priv->rpu_ring_handle, fp_priv->valid_rpu_ring_num,
                              poll_param.pid, fp_priv->item);
        if (ret > 0) {
            ret = copy_to_user((void *)poll_param.item_addr, fp_priv->item, sizeof(ioctl_item_t) * ret);
            return 0;
        } else if (ret == 0) {
            return HX_RET_DEVICE_BUSY;
        }

        break;

    case IOCTL_CIPHER_STATUS:
        ring_handle = fp_priv->rpu_ring_handle[0];
        ring = &(ring_handle->com_ring);

        if (ring->time_out)
            return HX_RET_TIMEOUT;
        else
            return HX_RET_SUCCESS;

        break;

    case IOCTL_PUB_OP:
        ring_handle = hx_cur_next_rpu_ring(filp);
        ret = copy_from_user(&param, (void *)arg, sizeof(ioctl_param_t));
        if (ret != 0)
            return HX_RET_ARG_ADDR_ERROR;

        ctx = (session_t *)(param.ctx);
        if (IS_ERR(ctx) || (ctx == NULL)) {
            ctx = kzalloc(sizeof(session_t), GFP_KERNEL);
            LOG_DEBUG("\r\n");
            LOG_DEBUG(">>> allc ctx=%p \n", ctx);
            if (ctx == NULL)
                return HX_RET_NO_MEM;
            mutex_init(&ctx->request_queue_lock);
            ctx->internal = 1;
        }

        if (param.item.mode == HX_SYNC_MODE) {
            sync_wait = kzalloc(sizeof(hx_wait_t), GFP_KERNEL);
            init_waitqueue_head(&sync_wait->wq);
            sync_wait->condition = 0;
        }

        ctx->status = HX_RET_FAILED;

        ret = rpu_pub(ctx, ring_handle, HX_USER_PKG, param.bus, param.algo, param.mode, 
                        (void *)(param.src), param.src_len, (void *)(param.dst), param.dst_len, 
                        param.item.pack_id, &param.item, sync_wait, param.final);
        if (ret == 0) {
            if (param.item.mode == HX_SYNC_MODE) {
                // sync mode block
                if (0 == wait_event_interruptible_timeout(sync_wait->wq, sync_wait->condition, msecs_to_jiffies(10000))) {
                    ret = HX_RET_TIMEOUT;
                }
                if (wait_condition_timeout(sync_wait->condition == 2, HZ) != 0) {
                    state = sync_wait->state;
                    kfree(sync_wait);
                } else {
                    ctx->status = HX_RET_FAILED;
                    printk("leak %d \n", sizeof(hx_wait_t));
                    kfree(sync_wait);
                    return HX_RET_FAILED;
                }
            }
        } else {
            ctx->status = HX_RET_SUCCESS;

            if (param.item.mode == HX_SYNC_MODE)
                kfree(sync_wait);
            if (ctx->internal)
                kfree(ctx);
        }
        return ret;

    case IOCTL_REG_READ:
        printk(">>> do IOCTL_REG_READ \n");
        ret = copy_from_user(&reg, (void *)arg, sizeof(ioctl_reg_t));
        if (ret != 0)
            return HX_RET_ARG_ADDR_ERROR; // bad address
        if ((reg.bar != 0) && (reg.bar != 2))
            return HX_RET_PARAM_ERROR;
        if ((reg.addr % 4) != 0)
            return HX_RET_PARAM_ERROR;
        if (reg.num <= 0)
            return HX_RET_SUCCESS;

        accel_dev = hx_devmgr_get_dev_by_name(reg.dev_name);
        if (accel_dev == NULL) {
            LOG_ERROR("Open %s failed \n", reg.dev_name);
            return -ENXIO;
        } else {
            LOG_DEBUG("open [%s] success\n", reg.dev_name);
        }
        LOG_DEBUG("bar=%d \n", reg.bar);
        LOG_DEBUG("num=%d \n", reg.num);
        LOG_DEBUG("addr=0x%x \n", reg.addr);
        LOG_DEBUG("data=0x%x \n", reg.data);

        reg_data = kzalloc(reg.num * 4, GFP_KERNEL);
        ret = copy_to_user((void *)(reg.data), reg_data, reg.num * 4);
        kfree(reg_data);
        return HX_RET_SUCCESS;
    case IOCTL_REG_WRITE:
        printk(">>> do IOCTL_REG_WRITE \n");
        ret = copy_from_user(&reg, (void *)arg, sizeof(ioctl_reg_t));
        if (ret != 0)
            return HX_RET_ARG_ADDR_ERROR; // bad address
        if ((reg.bar != 0) && (reg.bar != 2))
            return HX_RET_PARAM_ERROR;
        if ((reg.addr % 4) != 0)
            return HX_RET_PARAM_ERROR;
        if (reg.num <= 0)
            return HX_RET_SUCCESS;
        accel_dev = hx_devmgr_get_dev_by_name(reg.dev_name);
        if (accel_dev == NULL) {
            LOG_ERROR("Open %s failed \n", reg.dev_name);
            return -ENXIO;
        } else {
            LOG_DEBUG("open [%s] success\n", reg.dev_name);
        }
        LOG_DEBUG("bar=%d \n", reg.bar);
        LOG_DEBUG("num=%d \n", reg.num);
        LOG_DEBUG("addr=0x%x \n", reg.addr);
        LOG_DEBUG("data=0x%x \n", reg.data);

        reg_data = kzalloc(reg.num * 4, GFP_KERNEL);
        ret = copy_from_user(reg_data, (void *)reg.data, reg.num * 4);
        if (ret != 0) {
            kfree(reg_data);
            return HX_RET_ARG_ADDR_ERROR; // bad address
        }
        for (i = 0; i < reg.num; i++) {
            //                HX_REG_WRITE(accel_dev->accel_pci.bars[reg.bar==0? 0 : 1].virt_addr + reg.addr + i*4, reg_data[i]);
            LOG_DEBUG("reg_data[%d]=0x%x \n", i, reg_data[i]);
        }
        kfree(reg_data);
        return HX_RET_SUCCESS;

    case IOCTL_PERGORMANCE_HARDWARE:
        ring_handle = hx_cur_next_rpu_ring(filp);
        ret = copy_from_user(&perf_param, (void *)arg, sizeof(ioctl_performance_test_t));
        if (ret != 0)
            return HX_RET_ARG_ADDR_ERROR;

        ret = hx_performance_main(fp_priv->accel_dev, ring_handle, &perf_param);
        if (ret != 0)
            return ret;

        ret = copy_to_user((void *)arg, &perf_param, sizeof(ioctl_performance_test_t));
        if (ret != 0)
            return HX_RET_ARG_ADDR_ERROR;
        return 0;

    default:
        return HX_RET_ARG_CMD_ERROR;
    }
    return ret;
}

static struct file_operations hx_dev_fops = {
    .owner = THIS_MODULE,
    .open = hx_dev_open,
    // .read             = hx_dev_read,
    // .write             = hx_dev_write,
    .unlocked_ioctl = hx_dev_ioctl,
    //.mmap             = hx_dev_mmap,
    .release = hx_dev_close,
};

static char *hx_devnode(struct device *dev, mode_t *mode)
{
    if (mode != NULL)
        *mode = 0666;
    return NULL;
}

int hx_chrdev_setup(drv_ctrl_info_t *drv_info)
{
    dev_t chrdev_id;
    struct device *drv_device;
    if (alloc_chrdev_region(&chrdev_id, 0, 1, DRIVER_NAME)) {
        LOG_ERROR("alloc chrdev region fail\n");
        return -EFAULT;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    drv_info->drv_class = class_create(THIS_MODULE, DRIVER_NAME);
#else
    drv_info->drv_class = class_create(DRIVER_NAME);
#endif
    
    if (IS_ERR(drv_info->drv_class)) {
        LOG_ERROR("create class fail\n");
        goto CLASS_CREATE_FAIL;
    }

    drv_info->major = MAJOR(chrdev_id);
    cdev_init(&drv_info->drv_cdev, &hx_dev_fops);

    if (cdev_add(&drv_info->drv_cdev, chrdev_id, 1)) {
        LOG_ERROR("alloc chrdev region fail\n");
        goto CDEV_ADD_FAIL;
    }
    drv_info->drv_class->devnode = (void *)hx_devnode;
    drv_device = device_create(drv_info->drv_class, NULL,
                               MKDEV(drv_info->major, 0),
                               NULL, DRIVER_NAME);
    if (IS_ERR(drv_device)) {
        LOG_ERROR("failed to create device\n");
        goto DEV_CRT_FAIL;
    }
    drv_info->drv_device = drv_device;

    LOG_INFO("chrdev_setup ok\n");
    return 0;

DEV_CRT_FAIL:
    cdev_del(&drv_info->drv_cdev);
CDEV_ADD_FAIL:
    class_destroy(drv_info->drv_class);
CLASS_CREATE_FAIL:
    unregister_chrdev_region(chrdev_id, 1);
    return EFAULT;
}

void hx_chrdev_cleanup(drv_ctrl_info_t *drv_info)
{
    device_destroy(drv_info->drv_class, MKDEV(drv_info->major, 0));
    cdev_del(&drv_info->drv_cdev);
    class_destroy(drv_info->drv_class);
    unregister_chrdev_region(MKDEV(drv_info->major, 0), 1);
}