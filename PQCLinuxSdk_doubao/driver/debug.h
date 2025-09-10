
#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef __KERNEL__

#define mcsip_dump(array, len)                               \
    do {                                                     \
        int i;                                               \
        for (i = 0; i < len;) {                              \
            pr_cont("%02X ", *((unsigned char *)array + i)); \
            if (0 == ((++i) % 16))                           \
                printk("\n");                                \
        }                                                    \
        if (i % 16)                                          \
            printk("\n");                                    \
    } while (0)

#ifdef DEBUG
#define mcsip_dbg(fmt, args...)  pr_info("%s():%d:" fmt, __func__, __LINE__, ##args)
#define mcsip_err(fmt, args...)  pr_info("%s():%d:" fmt, __func__, __LINE__, ##args)
#define mcsip_info(fmt, args...) pr_info(fmt, ##args)
#define mcsip_array(array, len)                              \
    do {                                                     \
        int i;                                               \
        for (i = 0; i < len;) {                              \
            pr_cont("%02X ", *((unsigned char *)array + i)); \
            if (0 == ((++i) % 16))                           \
                printk("\n");                                \
        }                                                    \
        if (i % 16)                                          \
            printk("\n");                                    \
    } while (0)
#define mcsip_ring_info(ring)                                        \
    do {                                                             \
        pr_info("id:0x%x\n", ring.id);                               \
        pr_info("block_num:0x%x\n", ring.block_num);                 \
        pr_info("block_size:0x%x\n", ring.block_size);               \
        pr_info("tail:0x%x, head:0x%x\n", ring.tail, ring.head);     \
        pr_info("dma_addr:0x%lx\n", (unsigned long)ring.bus_addr);   \
        pr_info("base_addr:0x%lx\n", (unsigned long)ring.virt_addr); \
    } while (0)
#else
#define mcsip_dbg(fmt, ...)
#define mcsip_err(fmt, args...) pr_info("%s():%d:" fmt, __func__, __LINE__, ##args)
#define mcsip_info(fmt, ...)
#define mcsip_array(array, len)
#define mcsip_ring_info(ring)
#endif

#define memdump(array, len)                                  \
    do {                                                     \
        int i;                                               \
        for (i = 0; i < len;) {                              \
            pr_cont("%02x ", *((unsigned char *)array + i)); \
            if (0 == ((++i) % 16))                           \
                pr_cont("\n");                               \
        }                                                    \
        if (i % 16)                                          \
            pr_cont("\n");                                   \
    } while (0)

#else //!__KERNEL__

#define DATA_INFO(str, buff, len)                          \
    do {                                                   \
        printf("%s\n", str);                               \
        int i;                                             \
        for (i = 0; i < len;) {                            \
            if (i % 16 == 0)                               \
                printf("    ");                            \
            printf("%02x ", *((unsigned char *)buff + i)); \
            if ((++i) % 16 == 0)                           \
                printf("\n");                              \
        }                                                  \
        if (i % 16)                                        \
            printf("\n");                                  \
    } while (0)

#define INFO(leval, str, buff, len)    \
    do {                               \
        if (leval) {                   \
            DATA_INFO(str, buff, len); \
        }                              \
    } while (0)

#define memdump(array, len)                                 \
    do {                                                    \
        int i;                                              \
        for (i = 0; i < len;) {                             \
            printf("%02x ", *((unsigned char *)array + i)); \
            if (0 == ((++i) % 16))                          \
                printf("\n");                               \
        }                                                   \
        if (i % 16)                                         \
            printf("\n");                                   \
    } while (0)

#define memdump_line(array, len)                           \
    do {                                                   \
        int i;                                             \
        for (i = 0; i < len; i++) {                        \
            printf("%02x", *((unsigned char *)array + i)); \
        }                                                  \
        printf("\n");                                      \
    } while (0)

#define dumparray(str, array, len)                                   \
    do {                                                             \
        int dumpindex;                                               \
        printf(str);                                                 \
        for (dumpindex = 0; dumpindex < len; dumpindex++) {          \
            printf("%02x", *(((unsigned char *)array) + dumpindex)); \
        }                                                            \
        printf("\n");                                                \
    } while (0)

#define memdump32(array, len)                          \
    do {                                               \
        int i;                                         \
        for (i = 0; i < len / 4;) {                    \
            printf("%08x ", *((uint32_t *)array + i)); \
            if (0 == ((++i) % 16))                     \
                printf("\n");                          \
        }                                              \
        if (i % 16)                                    \
            printf("\n");                              \
    } while (0)

#define LOG_ERR(format, ...)     printf("[XXX]" format, ##__VA_ARGS__)
#define LOG_LEVEL_0(format, ...) printf(format, ##__VA_ARGS__)
#define LOG_LEVEL_1(format, ...) printf("\t" format, ##__VA_ARGS__)
#define LOG_LEVEL_2(format, ...) printf("\t\t" format, ##__VA_ARGS__)
#define LOG_LEVEL_3(format, ...) printf("\t\t\t" format, ##__VA_ARGS__)
#define INFO(leval, str, buff, len)    \
    do {                               \
        if (leval) {                   \
            DATA_INFO(str, buff, len); \
        }                              \
    } while (0)

#define INFO_LOG(leval, str)   \
    do {                       \
        if (leval) {           \
            printf("%s", str); \
        }                      \
    } while (0)

#endif //__KERNEL__

#endif //_DEBUG_H_
