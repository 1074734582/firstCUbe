#ifndef __SAFEAUTH_H__
#define __SAFEAUTH_H__

#include <stdio.h>
#include <syslog.h>
#include <stdint.h>
/* 遥测主导头 */

struct telemetry_primary_frame
{
    uint16_t version:2;       /* Fix 00 */
    uint16_t space_id:8;
    uint16_t vc_flag:6;
    uint32_t virtchannel_counter:24;
    uint32_t playback_flag:1;
    uint32_t reserve:7;
    uint16_t frame_crc;
} __attribute__ ((packed));

/* 遥控主导头 */
struct remotectl_primary_frame
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

/* 遥测 */
struct telemetry_authreq_common 
{
    uint8_t random[64];
    uint32_t  certificate;   
    uint8_t reserve[372];    
}__attribute__ ((packed));

struct telemetry_authrep_common 
{
    uint8_t random[64];
    uint32_t  certificate;   
    uint32_t active_time;   
    uint8_t  sign[64];
    uint8_t reserve[304];    
}__attribute__ ((packed));

struct telemetry_rcvrep_common 
{
    uint32_t response;   
    uint8_t reserve[436];    
}__attribute__ ((packed));

union telemetry_certify_pkg {
	struct telemetry_authreq_common authreq;
	struct telemetry_authrep_common authrep;
	struct telemetry_rcvrep_common rcvrep;
}__attribute__ ((packed));

/* 遥控 */
struct remotectl_authrep_common 
{
    uint8_t random[64];
    uint8_t  certificate[4];   
    uint8_t  sign[64];   
    uint32_t active_time;   
	uint8_t reserve[116];  
}__attribute__ ((packed));

struct remotectl_authrcv_common 
{
    uint8_t reserve0[48];  
    uint8_t sesskey0[8];
    uint8_t active_time[8];    
    uint8_t  sign[64];  
    uint8_t sesskey1[48];
    uint8_t sesskey2[16];
	uint8_t reserve1[60];      
}__attribute__ ((packed));

union remotectl_certify_pkg {
	struct remotectl_authrep_common authrep;
	struct remotectl_authrcv_common authrcv;
}__attribute__ ((packed));


/* 遥测包结构 */
struct telemetry_transfer_frame
{
    uint32_t sync_code;       /* Fix 0x352EF853 */
    struct  telemetry_primary_frame  priframe;             
	uint8_t insert_field[50] ;    
	uint32_t packet_head;      /* Fix 5B6C2A9D */
    union telemetry_certify_pkg certify_pkg;
    uint32_t control_field;
    uint16_t crc;         /* crc */
} __attribute__ ((packed));


/* 遥控包结构 */
struct remotectl_transfer_frame
{
    uint16_t sync_code;       /* Fix 0xEB90 */
    struct remotectl_primary_frame  priframe;             
	uint32_t packet_head;      /* Fix 1A2B3D4C */
    union remotectl_certify_pkg certify_pkg;
    uint16_t crc;         /* crc */
} __attribute__ ((packed));


/** xw 私有参数结构 */
typedef struct
{
    uint32_t indate0;                              
    uint32_t indate1;                              
    
    uint8_t random0[64];               // 模数
    uint8_t random1[64];               // 公开指数

} xw_privte_t;




typedef enum xw_ret_code_
{
    XW_RET_AUTH_COMPLETE           =1,
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
int start_accessauth();
void* thread_fun();
unsigned short get_crc16(unsigned char *ptr,int len);
int choose(xw_privte_t *pri, void *buf, uint32_t inlen, void *data, uint32_t outlen);
void reverseBits(unsigned char* buf, size_t length);
unsigned short swapHex(unsigned short num);
unsigned int reverse_bit(unsigned int value, unsigned int num);
void swapBytes(unsigned char* array, int size);
unsigned short get_IDX_Index(unsigned char* buf,int size,int flag);
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

send(unsigned char * buf, int size);

#endif