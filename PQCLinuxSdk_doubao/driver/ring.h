#ifndef _RING_H_
#define _RING_H_

#include "dev_mgr.h"
#include "ioctl_cmds.h"
#include "reg.h"
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/time.h>

/*
    call back function when get resp from  card
*/
typedef void (*ring_callback_func_ptr)(void *, uint32_t);

typedef void (*user_cb_func)(void *);
typedef struct hx_cookies_s {
    uint32_t state;
    struct timespec64 stamp;
    void *virt;
    uint64_t phy;
} hx_cookies_t;
typedef struct hx_op_cookie_s {
    uint32_t count;
    uint32_t size;
    uint32_t offset;
    spinlock_t lock;
    hx_cookies_t *cookies;
} hx_op_cookie_t;

/*
    ring data struct, descript a ring info
*/
typedef struct ring_handle_s {

    hx_op_cookie_t op_cookies;

    void *ring_cmd_req_queue_virt_addr;
    uint64_t ring_cmd_req_queue_phy_addr;

    void *ring_cmd_resp_queue_virt_addr;
    uint64_t ring_cmd_resp_queue_phy_addr;

    void *ring_req_queue_virt_addr;
    uint64_t ring_req_queue_phy_addr;

    void *ring_resp_queue_virt_addr;
    uint64_t ring_resp_queue_phy_addr;

    uint32_t ring_queue_size; // queue depth
    uint32_t message_size;   
    uint32_t resp_size;      
    uint32_t cmd_resp_size;    
    uint32_t cmd_req_size;

    uint64_t enq;
    uint64_t deq;
    uint64_t enq_size;
    uint64_t deq_size;
    atomic_t in_flight; // req num in queue
    uint32_t max_flight;
    uint32_t wait_count;
    uint8_t time_out;
    ring_callback_func_ptr callback;

    /* usehxace shadow values */
    struct mutex req_lock;
    spinlock_t req_spin_lock;
    uint32_t req_head;
    uint32_t req_tail;

    struct mutex resp_lock;
    spinlock_t resp_spin_lock;
    uint32_t resp_head;
    uint32_t resp_tail;

    struct mutex cmd_resp_lock;
    spinlock_t cmd_resp_spin_lock;
    uint32_t cmd_resp_head;
    uint32_t cmd_resp_tail;

    struct mutex cmd_req_lock;
    spinlock_t cmd_req_spin_lock;
    uint32_t cmd_req_head;
    uint32_t cmd_req_tail;

    struct mutex s_list_lock;
    spinlock_t s_list_spin_lock;
    struct list_head s_pkg_head;
    atomic_t s_list_node_num;

    struct mutex list_lock;
    spinlock_t list_spin_lock;

    struct mutex list_p_lock;
    spinlock_t list_spin_p_lock;

    struct list_head pkg_head;
    atomic_t list_node_num;

    void *cb_data;
    uint8_t rd_cmd_id;
    uint8_t sess_mode;
} ring_handle_t;

typedef struct hx_ring_handle_s {
    uint32_t status;
    void *ptr_base;
    uint32_t bank_id;
    uint32_t ring_id;
    ring_handle_t com_ring;
    atomic_t in_pro;
    uint32_t busy;

    struct hx_accel_dev *accel_dev;
} hx_ring_handle_t;

/*
    send list node
*/
typedef struct s_list_pkg_ {
    uint64_t pack_id;
    uint64_t opdata;
    struct list_head list;
} s_list_pkg_t;

typedef struct list_pkg_ {
    uint64_t pack_id;
    int state;
    uint64_t sess;
    uint64_t pid;
    uint64_t mode;
    struct list_head list;
} list_pkg_t;

typedef struct list_ctx_ {
    void *ctx;
    struct list_head list;
} list_ctx_t;
typedef struct poll_thread_pa_s {
    int num;
    int id[128];
    void *rp_info;
    hx_ring_handle_t *ring_handle[4];
} poll_thread_pa_t;

typedef struct hx_dev_rp_info_s {
    hx_ring_handle_t *rpu_ring_handle[4];
    int max_valid_rpu_ring_num;
    atomic_t in_rpu_polling;

    struct task_struct *poll_rpu_kthread[4];

    poll_thread_pa_t kthread_rpu_poll_data[4];
    int rpu_poll_thread_num;
} hx_dev_rp_info_t;

#define RPU_TOTAL_RING_NUM  1
#define RPU_TOTAL_VALID_NUM 1

#define RPU_TOTAL_POLL_NUM 1

#define HX_MAX_POLLING_ITEMS 512

#define HX_COOKIE_QUEUE_COUNT 700 //queue count larger than 800, pqc core would be dead. Setting 700 to protect core.

#define HX_COOKIE_FIFO_COUNT 1024 

#define HX_COOKIE_SIZE_BULK      7168
#define HX_BULK_RING_QUEUE_DEPTH 2048
#define HX_MAX_RESERVE           64 //(HX_RING_QUEUE_DEPTH/2)

#define HX_REQ_SIZE     2048
#define HX_RESP_SIZE    2048
#define HX_CMD_RESP_SIZE 16
#define HX_CMD_REQ_SIZE 16

#define HX_MAX_PKG_LIST_NODE (HX_RING_QUEUE_DEPTH / 4)

#define HX_MAX_POLLING_CNT         0xFFFFFFFF
#define HX_MAX_RETRY_TIMES         1000
#define HX_MAX_DEQUEUE_RETRY_TIMES 0
#define HX_RESP_INIT_CODE          0x5F5F5F5F
#define HX_RESP_MAGIC_CODE         0x7F7F7F7F
#define HX_RESP_ERROR_MAGIC_CODE   0x9F9F9F9F
#define HX_ID_MAGIC_CODE           0x5F

#define HX_MAX_WAIT_COUNT 1000 * 1000

int ring_put_msg(hx_ring_handle_t *ring_handle, void *msg, uint32_t algo);
int hx_ring_poll(hx_ring_handle_t *ring_handle, list_pkg_t **item);
int hx_ring_init(struct hx_accel_dev *accel_dev);

void hx_ctrl_init(void);
void hx_ctrl_destroy(void);
int hx_ring_free(struct hx_accel_dev *accel_dev);

int check_state_all(hx_ring_handle_t *rpu_handle[], int rpu_ring_num, int pid, ioctl_item_t *item);
hx_ring_handle_t *hx_get_next_rpu_ring(struct hx_accel_dev *accel_dev);
hx_ring_handle_t *hx_get_next_bulk_ring(struct hx_accel_dev *accel_dev);
hx_ring_handle_t *hx_get_next_pub_ring(struct hx_accel_dev *accel_dev);

int dequeue_thread_run(void);
int dequeue_thread_stop(void);

hx_cookies_t *get_cookie(hx_ring_handle_t *ring_handle);
void put_cookie(hx_cookies_t *cookie);
int in_flight_pre_check(hx_ring_handle_t *ring_handle);

int ctx_list_init(void);
int ctx_list_add(void *ctx);
int ctx_list_remove(void *ctx);

#define _ROUND_DOWN(val, align) ((val) & (~((align)-1)))
#define _ROUND_UP(val, align)   (((val) + ((align)-1)) & (~((align)-1)))

#endif //_RING_H_
