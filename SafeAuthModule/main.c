#include<string.h>
#include<stdint.h>
#include<stdio.h>
#include "safeauth.h"
#include "uart.h"
#define UART_DEV_PATH "/dev/ttyUSB7"
pthread_t read_thread; // 读取数据的线程
extern int serial_fd;// 串口文件描述符
int fd_write = 0;
 /*串口读取函数*/
void* read_serial_data(void* arg) {
	printf("lkb4 enter read_serial_data \n");
    char buffer[512];
    int num_bytes;
	int ret =0;
	printf("lkb5 enter while\n");
    while (1) {
		printf("lkb6\n");
		memset(buffer,0,sizeof(buffer));
        num_bytes = DI_uart_read(serial_fd, &buffer, sizeof(buffer));
		//printf("lkb7\n");
        if (num_bytes > 0) {
            printf("second  len: %d\n", num_bytes);
            printf("second  data: ");// 处理读取到的数据
			for (int i = 0; i < num_bytes; i++) {
                    printf("%02x ", buffer[i]);
                }
                printf("\n\n");
			ret=send(buffer, num_bytes);
			if(ret==XW_RET_AUTH_COMPLETE){
			printf("SUCCESS\n");
			break;
			}else{
			printf("NEXT STAGE\n");
			}
        } else if (num_bytes == -1) {
            printf("读取串口数据时发生错误");
            break;
        }
    }

    return NULL;
}
int main()
{
    int ret =-1;
	serial_fd = DI_uart_open(UART_DEV_PATH);
    if (serial_fd < 0) {
        printf("DI_uart_open %s failed\n", UART_DEV_PATH);
        return NULL;
    }

    /**
     * 配置串口：
     * 波特率：115200
     * 数据位：8
     * 校验  ：无校验
     * 停止位：1
     * 流控  ：无流控
     */
	  printf("lkb1\n");
	ret=DI_uart_set(serial_fd, 115200, 8, 'n', 1, 'n');
	 printf("lkb = %d\n",ret);
	if (ret == -1) {
        return 0;
    }
	 printf("lkb2\n");
    if (pthread_create(&read_thread, NULL, read_serial_data, NULL) != 0) {
        printf("can not creat the read_thread\n");
        return 0;
    }
printf("lkb3\n");
    // 这里可以进行其他操作，如写入数据到串口

    pthread_join(read_thread, NULL); // 等待读取线程结束
    
printf("lkb4\n");
    close(serial_fd);
close(fd_write);
    return 0;
}
