#include "log.h"

static char *log_info[] = 
{
    "Dump",
    "Debug",
    "Info",
    "Warn",
    "Error",
"test"
};

char log_prex[128];
static int hx_log_level = HX_LOG_LEVEL_INFO;

void hx_log_set_level(hx_log_level_e level)
{
    hx_log_level = level;
}

int hx_log_get_level(void)
{
    return hx_log_level;
}

char *hx_log_get_info(hx_log_level_e level)
{
    return log_info[level];
}
