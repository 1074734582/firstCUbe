#ifndef _DEV_MGR_H_
#define _DEV_MGR_H_

#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/uio_driver.h>

#include "chrdev.h"
#include "debug.h"
#include "ioctl_cmds.h"

#define HX_MAX_DEV_NAME_LEN 128
#define HX_SEC_ZONE_SIZE    4096

struct hx_addr_base {
    void __iomem *virtaddr;
    uint64_t physaddr;
};

struct hx_bar {
    resource_size_t base_addr;
    void __iomem *virt_addr;
    resource_size_t size;
};

struct hx_accel_pci {
    struct module *owner;
    struct pci_dev *pci_dev;
    struct hx_bar bars[6];
    int vf_num;
    int linkdown;
};

struct hx_accel_dev {

    struct module *owner;
    atomic_t ref_count;
    struct list_head list;
    uint8_t dev_name[128];
    void *rp_info;
    int dev_id;
    drv_ctrl_info_t drv_info;
    struct hx_accel_pci accel_pci;
    struct platform_device *platform_dev;
};

void hx_table_lock_init(void);
int hx_devmgr_add_dev(struct hx_accel_dev *accel_dev);
int hx_devmgr_rm_dev(struct hx_accel_dev *accel_dev);
void hx_devmgr_get_num_dev(uint32_t *num);
struct hx_accel_dev *hx_devmgr_get_dev_by_name(char *name);
void hx_devmgr_get_all_dev_name(char *names, int num);
static int get_free_dev_id(void);
static void free_dev_id(int dev_id);

int hx_accel_dev_init(drv_ctrl_info_t ctrl_dev);

int hx_accel_destroy(void);

#endif // _DEV_MGR_H_
