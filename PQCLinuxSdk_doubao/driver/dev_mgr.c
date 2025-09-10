#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>

#include "common.h"
#include "dev_mgr.h"

#include "debug.h"

static LIST_HEAD(accel_table);
// static struct list_head accel_table = { &accel_table, &accel_table};

uint8_t accel_id[4] = {0};
static struct mutex table_lock;
static uint32_t num_devices = 0;

void hx_table_lock_init(void)
{
    mutex_init(&table_lock);
}
// thread unsafe ,it must be call under table_lock
static int get_free_dev_id(void)
{
    int i = 0;
    int total = sizeof(accel_id);
    for (i = 0; i < total; i++) {
        if (accel_id[i] == 0) {
            accel_id[i] = 1; // mark used
            return (i + 1);
        }
    }
    return 0;
}
// thread unsafe ,it must be call under table_lock
static void free_dev_id(int dev_id)
{
    if (dev_id <= 0)
        return;
    accel_id[dev_id - 1] = 0;
}

int hx_devmgr_add_dev(struct hx_accel_dev *accel_dev)
{
    int ret = 0;
    int bus_num = 0;
    int dev_num = 0;
    int fun_num = 0;
    struct hx_accel_dev *dev_node = NULL;
    struct hx_accel_dev *next = NULL;

    mutex_lock(&table_lock);
    atomic_set(&accel_dev->ref_count, 0);

    list_for_each_entry_safe(dev_node, next, &accel_table, list)
    {
        if (dev_node == accel_dev) {
            ret = -EEXIST;
            goto unlock;
        }
    }

    list_add(&accel_dev->list, &accel_table);
    num_devices++;
    accel_dev->dev_id = get_free_dev_id();
    sprintf(accel_dev->dev_name, "hx_dev_%02d", accel_dev->dev_id);

unlock:
    mutex_unlock(&table_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(hx_devmgr_add_dev);

int hx_devmgr_rm_dev(struct hx_accel_dev *accel_dev)
{
    int ret = 0;
    struct hx_accel_dev *dev_node = NULL;
    struct hx_accel_dev *next = NULL;
    mutex_lock(&table_lock);
    atomic_set(&accel_dev->ref_count, 0);

    list_for_each_entry_safe(dev_node, next, &accel_table, list)
    {
        if (dev_node == accel_dev) {
            num_devices--;
            free_dev_id(accel_dev->dev_id);
            LOG_DEBUG("num_devices=%d accel_dev->dev_name=%s accel_dev->dev_id=%d \n",
                      num_devices, accel_dev->dev_name, accel_dev->dev_id);
            list_del(&accel_dev->list);
        }
    }
    mutex_unlock(&table_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(hx_devmgr_rm_dev);

struct hx_accel_dev *hx_devmgr_get_dev_by_name(char *name)
{
    struct hx_accel_dev *dev_node = NULL;
    struct hx_accel_dev *next = NULL;
    mutex_lock(&table_lock);

    list_for_each_entry_safe(dev_node, next, &accel_table, list)
    {
        if (strncmp(dev_node->dev_name, name, max(strlen(dev_node->dev_name), strlen(name))) == 0) {
            mutex_unlock(&table_lock);
            return dev_node;
        }
    }
    mutex_unlock(&table_lock);
    return NULL;
}

EXPORT_SYMBOL_GPL(hx_devmgr_get_dev_by_name);

void hx_devmgr_get_num_dev(uint32_t *num)
{
    *num = num_devices;
}
EXPORT_SYMBOL_GPL(hx_devmgr_get_num_dev);

void hx_devmgr_get_all_dev_name(char *names, int num)
{
    int i = 0;

    struct hx_accel_dev *dev_node = NULL;
    struct hx_accel_dev *next = NULL;
    mutex_lock(&table_lock);

    list_for_each_entry_safe(dev_node, next, &accel_table, list)
    {
        memcpy(names + (i++ * 32), dev_node->dev_name, strlen(dev_node->dev_name));
        if (i >= num)
            break;
    }
    mutex_unlock(&table_lock);
}
EXPORT_SYMBOL_GPL(hx_devmgr_get_all_dev_name);