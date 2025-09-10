#ifndef __LOG_H_
#define __LOG_H_

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <syslog.h>

typedef enum 
{
    HX_LOG_LEVEL_DUMP = 0,
    HX_LOG_LEVEL_DEBUG,
    HX_LOG_LEVEL_INFO,
    HX_LOG_LEVEL_WARN,
    HX_LOG_LEVEL_ERROR
} hx_log_level_e;

#define filename(x) strrchr(x, '/') ? strrchr(x, '/') + 1 : x

int hx_log_get_level(void);
void hx_log_set_level(hx_log_level_e level);
char *hx_log_get_info(hx_log_level_e level);

extern char log_prex[];
#define HEADER_FORMAT   "%-30s ] : "
#define hx_log_printf(level, file, line, format, args...) \
{ \
    if (hx_log_get_level() <= level) \
    { \
        sprintf(log_prex, "[ %s %s:%d ", hx_log_get_info(level), filename(file), line);\
        printf(HEADER_FORMAT, log_prex); \
        printf(format, ##args); \
        syslog(LOG_INFO, HEADER_FORMAT, log_prex); \
        syslog(LOG_INFO, format, ##args); \
    } \
}

#define hx_log_dump(buf, len, format, args...) \
{ \
    uint8_t *temp = (uint8_t *)(buf); \
    hx_log_printf(HX_LOG_LEVEL_DUMP, __FILE__, __LINE__, format, ##args); \
    if(hx_log_get_level() <= HX_LOG_LEVEL_DUMP) \
    { \
        for (int i = 0; i < len; i++) \
        { \
            if (((i % 16) == 0)) \
                printf("\n  "); \
            printf("%02X ", temp[i]); \
        } \
        printf("\n\n"); \
    } \
}

#define hx_log_debug(format, args...) \
        hx_log_printf(HX_LOG_LEVEL_DEBUG, __FILE__, __LINE__, format, ##args);

#define hx_log_info(format, args...) \
        hx_log_printf(HX_LOG_LEVEL_INFO, __FILE__, __LINE__, format, ##args);

#define hx_log_warning(format, args...) \
        hx_log_printf(HX_LOG_LEVEL_WARN, __FILE__, __LINE__, format, ##args);

#define hx_log_error(format, args...) \
        hx_log_printf(HX_LOG_LEVEL_ERROR, __FILE__, __LINE__, format, ##args);



#define hx_assert(cond, ret) \
{ \
    if (!(cond)) \
    { \
        if(ret != -3) \
        { \
            hx_log_error("!HX Assert Failed, ret = -0x%X, %s:%d\n", -ret, __func__, __LINE__); \
        } \
        return ret; \
    } \
}


#endif
