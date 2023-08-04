

#ifndef __UART_H__
#define __UART_H__


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>


extern int DI_uart_open(const char *p_path);
extern int DI_uart_set(int fd, int baudrate, int bits, char parity, int stop, char flow);
extern int DI_uart_read(int fd, char* r_buf, int lenth);
extern int DI_uart_close(int fd);


#endif 

