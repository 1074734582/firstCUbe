#ifndef __CHRDEV_H__
#define __CHRDEV_H__

#include <linux/cdev.h>

#include "ioctl_cmds.h"
#include "debug.h"
#include "dev_mgr.h"
#include "ring.h"

#define DRIVER_NAME "hx-drv"
#define dma_addr_t  uint64_t

typedef struct drv_ctrl_info_s {
    unsigned int major;
    struct cdev drv_cdev;
    struct class *drv_class;
    struct device *drv_device;

} drv_ctrl_info_t;

typedef struct fp_private_s {

    struct hx_ring_handle_s *rpu_ring_handle[4];
    int valid_rpu_ring_num;

    struct hx_accel_dev *accel_dev;
    atomic64_t rpu_sel;

    ioctl_item_t item[HX_MAX_POLL_ITEMS * 2];
} fp_private_t;

int hx_chrdev_setup(drv_ctrl_info_t *drv_info);
void hx_chrdev_cleanup(drv_ctrl_info_t *drv_info);

extern atomic64_t ctx_cnt;

#endif