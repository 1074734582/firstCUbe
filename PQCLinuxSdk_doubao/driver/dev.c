#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/platform_device.h>

#include "common.h"
#include "chrdev.h"
#include "debug.h"
#include "dev_mgr.h"
#include "ioctl_cmds.h"
#include "ring.h"

#if PCIE_ENABLE

#define HX_VENDER        0x10ee
#define HX_NORMAL_DEVICE 0x8024
#define DEVICE_NAME      "hx-dev"

extern int cpa_log_level;

static const struct pci_device_id hx_ids[] =
    {
        {PCI_DEVICE(HX_VENDER, HX_NORMAL_DEVICE)},
        {0},
};

module_param(cpa_log_level, int, 0644);
MODULE_PARM_DESC(cpa_log_level, "log level value : 0~4");
MODULE_DEVICE_TABLE(pci, hx_ids);

static int hx_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    int ret = 0, bar_mask, bar_nr;
    int err = 0;
    struct hx_accel_dev *accel_dev;
    int totalvfs = 0;
    int i = 0;
    uint32_t config = 0;
    if (num_possible_nodes() > 1 && dev_to_node(&pdev->dev) < 0) {
        dev_err(&pdev->dev, "Invalid NUMA configuration \n");
        return -EINVAL;
    }

    LOG_INFO("insmode success\n");

    accel_dev = kzalloc_node(sizeof(struct hx_accel_dev), GFP_KERNEL, dev_to_node(&pdev->dev));
    if (!accel_dev)
        return -ENOMEM;
    accel_dev->rp_info = kzalloc_node(sizeof(struct hx_dev_rp_info_s), GFP_KERNEL, dev_to_node(&pdev->dev));

    accel_dev->accel_pci.pci_dev = pdev;
    accel_dev->accel_pci.owner = THIS_MODULE;
    if (pci_enable_device(pdev)) {
        ret = -EFAULT;
        goto err;
    }
    if (pci_request_regions(pdev, DEVICE_NAME)) {
        ret = -EFAULT;
        goto err;
    }

    pci_set_master(pdev);
    /* Find and map all the device's BARS */
    bar_mask = pci_select_bars(pdev, IORESOURCE_MEM);
    for_each_set_bit(bar_nr, (const unsigned long *)&bar_mask, 6)
    {
        struct hx_bar *bar = &accel_dev->accel_pci.bars[i++];
        bar->base_addr = pci_resource_start(pdev, bar_nr);
        if (!bar->base_addr)
            break;
        bar->size = pci_resource_len(pdev, bar_nr);
        bar->virt_addr = pci_iomap(pdev, bar_nr, 0);

        LOG_DEBUG("bar->base_addr = %p, bar->size = %d, bar->virt_addr = %p\n", bar->base_addr, bar->size, bar->virt_addr);

        if (!bar->virt_addr) {
            dev_err(&pdev->dev, "Failed to map BAR %d\n", bar_nr);
            ret = -EFAULT;
            goto err;
        }
    }
    // add PF to device list
    hx_table_lock_init();
    hx_devmgr_add_dev(accel_dev);
    pci_set_drvdata(pdev, accel_dev);

#if 0
    // enable msi interrupt
    ret = pci_enable_msi(pdev);
    if (unlikely(ret)) {
        dev_err(&pdev->dev, "Can not enable msi \n");
    } else {
        LOG_INFO("msi don't set\n");
    }
#endif

    if (hx_chrdev_setup(&(accel_dev->drv_info)) != 0) {
        LOG_ERROR("Create Character Device(/dev/hx-dev) Fail\n");
        return -EFAULT;
    }
    hx_ctrl_init();
    hx_ring_init(accel_dev);

    //hx_self_test(accel_dev);
err:
    return ret;
}

static void hx_remove(struct pci_dev *pdev)
{
    struct hx_accel_dev *accel_dev = NULL;
    struct drv_ctrl_info_s drv_info;
    int i = 0;

    accel_dev = pci_get_drvdata(pdev);
    if (IS_ERR(accel_dev)) {
        dev_err(&pdev->dev, "Invalid Pointer of struct adapter\n");
        return;
    }
    // hx_irq_free(pdev);

    hx_ring_free(accel_dev);
    /*  close dequeue   */
    hx_ctrl_destroy();

    hx_chrdev_cleanup(&(accel_dev->drv_info));

    for (i = 0; i < 6; i++) {
        struct hx_bar *bar = &accel_dev->accel_pci.bars[i++];
        if (bar->virt_addr)
            pci_iounmap(accel_dev->accel_pci.pci_dev, bar->virt_addr);
    }

    pci_disable_msi(pdev);
    // rm device from device list
    hx_devmgr_rm_dev(accel_dev);
    kfree(accel_dev->rp_info);
    kfree(accel_dev);

    pci_release_regions(pdev);
    pci_disable_device(pdev);
    LOG_INFO("rmmod success\n\n");
    return;
}

static pci_ers_result_t hx_io_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
    dev_err(&pdev->dev, " hx_io_resume. state=%d \n", state);
    return PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t hx_io_slot_reset(struct pci_dev *pdev)
{
    dev_err(&pdev->dev, " hx_io_slot_reset. \n");
    return PCI_ERS_RESULT_RECOVERED;
}

static void hx_io_resume(struct pci_dev *pdev)
{
    dev_err(&pdev->dev, " hx_io_resume. \n");
}

static const struct pci_error_handlers hx_err_handler = {
    .error_detected = hx_io_error_detected,
    .slot_reset = hx_io_slot_reset,
    .resume = hx_io_resume,
};

static struct pci_driver hx_drv = {
    .name = DEVICE_NAME,
    .id_table = hx_ids,
    .probe = hx_probe,
    .remove = hx_remove,
    //    .sriov_configure = hx_sriov_configure,
    .err_handler = &hx_err_handler,
};

static int __init hx_drv_init(void)
{
    return pci_register_driver(&hx_drv);
}

static void __exit hx_drv_exit(void)
{
    pci_unregister_driver(&hx_drv);
    return;
}

#else

static int hx_probe(struct platform_device *pdev)
{
    struct hx_accel_dev *accel_dev;

    LOG_INFO("insmode success\n");

    accel_dev = kzalloc_node(sizeof(struct hx_accel_dev), GFP_KERNEL, 0);
    if (!accel_dev)
        return -ENOMEM;
    accel_dev->rp_info = kzalloc_node(sizeof(struct hx_dev_rp_info_s), GFP_KERNEL, 0);
    if (!accel_dev->rp_info)
        return -ENOMEM;

    accel_dev->platform_dev = pdev;

    hx_devmgr_add_dev(accel_dev);
    platform_set_drvdata(pdev, accel_dev);

    if (hx_chrdev_setup(&(accel_dev->drv_info)) != 0) {
        LOG_ERROR("Create Character Device(/dev/hx-drv) Fail\n");
        return -EFAULT;
    }

    hx_ctrl_init();
    hx_ring_init(accel_dev);

    //hx_self_test(accel_dev);
    
    return 0;
}

static int hx_remove(struct platform_device *pdev)
{
    struct hx_accel_dev *accel_dev = NULL;

    accel_dev = platform_get_drvdata(pdev);
    if (IS_ERR(accel_dev)) {
        dev_err(&pdev->dev, "Invalid Pointer of struct adapter\n");
        return -EFAULT;
    }

    hx_ring_free(accel_dev);
    hx_ctrl_destroy();
    hx_chrdev_cleanup(&(accel_dev->drv_info));
    hx_devmgr_rm_dev(accel_dev);
    kfree(accel_dev->rp_info);
    kfree(accel_dev);

    LOG_INFO("rmmod success\n\n");

    return 0;
}

struct of_device_id hx_ids[] = {
    {.compatible = "hx_dev"},
};

struct platform_driver hx_drv = {
    .probe = hx_probe,
    .remove = hx_remove,
    .driver = {
        .name = "hx_dev",
        .of_match_table = hx_ids,
    },
};

static int __init hx_drv_init(void)
{
    return platform_driver_register(&hx_drv);
}

static void __exit hx_drv_exit(void)
{
    platform_driver_unregister(&hx_drv);
}

#endif

module_init(hx_drv_init);
module_exit(hx_drv_exit);
MODULE_AUTHOR("hx");
MODULE_DESCRIPTION("Driver for hx");
MODULE_VERSION("v1.0.0");
MODULE_LICENSE("Dual BSD/GPL");