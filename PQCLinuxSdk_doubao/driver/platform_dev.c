#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>

static void hx_dev_release(struct device *dev)
{
}

struct platform_device hx_dev =
    {
        .name = "hx_dev",
        .id = -1,
        .dev = {
            .release = hx_dev_release,
        },
};

static int __init hx_dev_init(void)
{
    return platform_device_register(&hx_dev);
}

static void __exit hx_dev_exit(void)
{
    platform_device_unregister(&hx_dev);
}

module_init(hx_dev_init);
module_exit(hx_dev_exit);
MODULE_AUTHOR("hx");
MODULE_DESCRIPTION("Driver for hx");
MODULE_VERSION("v1.0.0");
MODULE_LICENSE("Dual BSD/GPL");