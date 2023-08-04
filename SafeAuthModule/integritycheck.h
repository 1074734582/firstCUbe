#ifndef __INTEGRITYCHECK_H__
#define __INTEGRITYCHECK_H__

#include <syslog.h>
#include <string.h>

typedef enum xw_ret_code_
{
    XW_RET_SUCCESS                 =0,
    XW_RET_FAILED                  =-1,
    XW_RET_NO_DEVICE               =-2,
    XW_RET_DEVICE_BUSY             =-3,
    XW_RET_NO_MEM                  =-3,
    XW_RET_ARG_ADDR_ERROR          =-5,
    XW_RET_ARG_CMD_ERROR           =-6,
    XW_RET_PARAM_ERROR             =-8,
    XW_RET_LEN_ERROR               =-10,
    XW_RET_KEY_ERROR               =-11,
    XW_RET_TIMEOUT                 =-12,
    XW_RET_UNSUPPORT_ALGO          =-13,
    // 待添加
} xw_ret_code_t;

typedef enum xw_guarantee_code_
{
    GUARANTEE_DATATRANSFER_ORDER             =0,
    GUARANTEE_RESET_ORDER                    =1,
    GUARANTEE_RECONSTRUCTION_ONE_ORDER       =2,
    GUARANTEE_RECONSTRUCTION_TWO_ORDER       =3,
} xw_guarantee_code_t;

struct primary_frame
{
    uint32_t version:2;       /* Fix 00 */
    uint32_t bypass_flag:1;
    uint32_t housekeeping_flag:1;
    uint32_t idle:2;
    uint32_t space_id:10;
    uint32_t channel_id:6;
    uint32_t frame_size:10;
    uint8_t  frame_id;
} __attribute__ ((packed));

struct hmac_remote_order_frame
{
    uint16_t sync_code;       /* Fix 0xEB90 */
    struct primary_frame  priframe;             
	uint32_t packet_head;     /* Fix 5D6FA98E */
	uint16_t data_size;         
	uint8_t  hmac[64];   
	uint16_t reserved;
	uint16_t checksum;      /*crc*/
} __attribute__ ((packed));

/* 包结构 */
struct hmac_guarantee_order_frame
{
    uint16_t sync_code;       /* Fix 0xEB90 */
    struct primary_frame  priframe;             
	uint32_t packet_head;     /* Fix 36A7574F */
	uint16_t order_type;      
	uint16_t param_size;
    uint8_t  hmac[64];   
	uint16_t checksum;      /*crc*/
} __attribute__ ((packed));

/* 前半部分包结构 */
struct hmac_guarantee_order_head_frame
{
    uint16_t sync_code;       /* Fix 0xEB90 */
    struct primary_frame  priframe;             
	uint32_t packet_head;     /* Fix 36A7574F */
	uint16_t order_type;      
	uint16_t param_size;
} __attribute__ ((packed));


unsigned short get_crc16(unsigned char *ptr,int len);

/* log */
#define cgra_log_printf(format, args...) \
{ \
        printf(format, ##args); \
        syslog(LOG_INFO, format, ##args); \
}

#define xw_assert(cond, ret) \
{ \
    if (!(cond)) \
    { \
        cgra_log_printf("!CGRA Assert Failed, ret = -0x%X, %s:%d\n", -ret, __func__, __LINE__); \
        return ret; \
    } \
}

int integrity_remote_control_handle(void *buf, uint32_t inlen, void *data);
int integrity_guarantee_control_handle(void *data, uint32_t inlen, uint16_t cmd_type, void *out);


#endif