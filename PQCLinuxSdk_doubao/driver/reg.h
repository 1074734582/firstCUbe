#ifndef _REG_H_
#define _REG_H_
#include "dev_mgr.h"

//npub
#define NPUB_RING_BASE               0x00000000
#define NPUB_RING_REG_SIZE           0x100
#define NPUB_RING_REQUEST_BASE_LO(n) (NPUB_RING_BASE + NPUB_RING_REG_SIZE * ((n)) + 0x00)
#define NPUB_RING_REQUEST_BASE_HI(n) (NPUB_RING_BASE + NPUB_RING_REG_SIZE * ((n)) + 0x10)
#define NPUB_RING_SIZE(n)            (NPUB_RING_BASE + NPUB_RING_REG_SIZE * ((n)) + 0x40)
#define NPUB_RING_PLUS(n)            (NPUB_RING_BASE + NPUB_RING_REG_SIZE * ((n)) + 0x60)
#define NPUB_RING_RESET(n)           (NPUB_RING_BASE + NPUB_RING_REG_SIZE * ((n)) + 0x70)

#define NPUB_RING_REQ_PTR(n)  (NPUB_RING_BASE + NPUB_RING_REG_SIZE * ((n)) + 0xc0)
#define NPUB_RING_RESP_PTR(n) (NPUB_RING_BASE + NPUB_RING_REG_SIZE * ((n)) + 0xd0)

#define NPUB_ALG_RESET_REG (NPUB_RING_BASE + 0x10100)

//sys ctrl
#define SYSCTL_BASE                 0x30007000 
#define SYSCTL_CRG_GRP3_SRST        (SYSCTL_BASE + 0x40)

//upif
#define UPIF_BASE_ADDR              0x00000000
#define UPIF_CTRL_REG_ADDR          (UPIF_BASE_ADDR + 0x00)
#define UPIF_TX_CFG_ADDR            (UPIF_BASE_ADDR + 0x04)
#define UPIF_RESP_ADDR_L_ADDR       (UPIF_BASE_ADDR + 0x08)
#define UPIF_RESP_ADDR_H_ADDR       (UPIF_BASE_ADDR + 0x0c)
#define UPIF_RING_ADDR_L_ADDR       (UPIF_BASE_ADDR + 0x10)
#define UPIF_RING_ADDR_H_ADDR       (UPIF_BASE_ADDR + 0x14)
#define UPIF_RING_PKG_ADDR          (UPIF_BASE_ADDR + 0x18)
#define UPIF_RING_START_ADDR        (UPIF_BASE_ADDR + 0x1c)
#define UPIF_RING_STATE_ADDR        (UPIF_BASE_ADDR + 0x20)
#define UPIF_RESPON_PKG_NUM_ADDR    (UPIF_BASE_ADDR + 0x24)
#define UPIF_CMD_RESP_ADDR_L_ADDR   (UPIF_BASE_ADDR + 0x28)
#define UPIF_CMD_RESP_ADDR_H_ADDR   (UPIF_BASE_ADDR + 0x2c)
#define UPIF_DATA_RESP_PKG_CNR      (UPIF_BASE_ADDR + 0x30)
#define UPIF_CMD_REQ_MODE_CTR       (UPIF_BASE_ADDR + 0x34)
#define UPIF_CMD_REQ_ADDR_L_ADDR    (UPIF_BASE_ADDR + 0x38)
#define UPIF_CMD_REQ_ADDR_H_ADDR    (UPIF_BASE_ADDR + 0x3c)
#define UPIF_CMD_REQ_TRIG           (UPIF_BASE_ADDR + 0x40)

#define UPIF_IFIFO_ADDR             (UPIF_BASE_ADDR + 0x00000100)
#define PUB_IFIFO_ADDR              0x40040100
#define PUB_OFIFO_ADDR              0x40040200
#define ESRAM_ADDR                  0x40080000

//pqc
#define PQC_BASE_ADDR               0x50000000
#define PQC_MEM_IN_ADDR             (PQC_BASE_ADDR)
#define PQC_MEM_IN2_ADDR            (PQC_BASE_ADDR + 0x00002000)
#define PQC_MEM_IN3_ADDR            (PQC_BASE_ADDR + 0x00004000)
#define PQC_MEM_IN4_ADDR            (PQC_BASE_ADDR + 0x00002900)
#define PQC_MEM_IN5_ADDR            (PQC_BASE_ADDR + 0x00010900)
#define PQC_MEM_IN6_ADDR            (PQC_BASE_ADDR + 0x00010940)
#define PQC_MEM_IN7_ADDR            (PQC_BASE_ADDR + 0x00010980)
#define PQC_MEM_IN8_ADDR            (PQC_BASE_ADDR + 0x00002300)
#define PQC_MEM_IN9_ADDR            (PQC_BASE_ADDR + 0x000026C0)
#define PQC_MEM_IN10_ADDR           (PQC_BASE_ADDR + 0x00002980)


#define PQC_MEM_OUT_ADDR            (PQC_BASE_ADDR)
#define PQC_MEM_OUT1_ADDR           (PQC_BASE_ADDR + 0x00000040)
#define PQC_MEM_OUT2_ADDR           (PQC_BASE_ADDR + 0x00001900)
#define PQC_MEM_OUT3_ADDR           (PQC_BASE_ADDR + 0x00001C00)
#define PQC_MEM_OUT4_ADDR           (PQC_BASE_ADDR + 0x00001400)
#define PQC_MEM_OUT5_ADDR           (PQC_BASE_ADDR + 0x00002000)
#define PQC_MEM_OUT6_ADDR           (PQC_BASE_ADDR + 0x00000080)
#define PQC_MEM_OUT7_ADDR           (PQC_BASE_ADDR + 0x00010000)
#define PQC_MEM_OUT8_ADDR           (PQC_BASE_ADDR + 0x00008000)
#define PQC_MEM_OUT9_ADDR           (PQC_BASE_ADDR + 0x00010040)
#define PQC_MEM_OUT10_ADDR          (PQC_BASE_ADDR + 0x00020000)
#define PQC_MEM_OUT11_ADDR          (PQC_BASE_ADDR + 0x00003200)
#define PQC_MEM_OUT12_ADDR          (PQC_BASE_ADDR + 0x00000200)

#define PQC_ESRAM_ADDR              (PQC_BASE_ADDR + 0x00040000)
#define PQC_ESRAM2_ADDR             (PQC_BASE_ADDR + 0x00050000)
#define PQC_ESRAM3_ADDR             (PQC_BASE_ADDR)

#define PQC_STARTCONTROL_TASKADDR   (PQC_BASE_ADDR + 0x00065004)
#define PQC_STARTCONTROL_START      (PQC_BASE_ADDR + 0x00065008)

#define PQC_ESRAM_INNER_ADDR         0x00040000
#define PQC_ESRAM2_INNER_ADDR        0x00050000

#define write_reg(reg, val) iowrite32(val, reg)
#define read_reg(reg)       ioread32(reg)

#define HX_REG_READ(addr)       *(volatile uint32_t *)(addr)
#define HX_REG_WRITE(addr, val) *((volatile uint32_t *)(addr)) = val
#define HX_REG_READQ(addr)      *(volatile uint64_t *)(addr)

#define _ROUND_DOWN(val, align) ((val) & (~((align)-1)))
#define _ROUND_UP(val, align)   (((val) + ((align)-1)) & (~((align)-1)))

#endif
