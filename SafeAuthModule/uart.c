#include "uart.h"
#include<errno.h>
#include <unistd.h>
int DI_uart_open(const char *p_path)
{
	printf("enter DI_uart_open\n");
    int fd = open(p_path, O_RDWR | O_NOCTTY | O_NONBLOCK);//以只读形式、不将此终端作为此进程的终端控制器、非阻塞的形式打开串口
	//printf("open failed fd=%d\n",fd);
    if (fd == -1)
    {
        return -1;
    }
    if (fcntl(fd, F_SETFL, 0) < 0)//设置串口非阻塞，因为这里是以非阻塞形式打开的，所以第三个参数为0，后面会详细介绍fcntl函数
	{ 
		return -1; 
	} 
	return fd; 
}

// 串口配置
int DI_uart_set(int fd, int baude, int bits, char parity, int stop, char flow)
{
    struct termios uart;
    if (tcgetattr(fd, &uart) != 0)
    {
        perror("tcgetattr failed!");
        return -1;
    }
    switch (baude)
    {
    case 4800:
        cfsetispeed(&uart, B4800);//设置输入波特率
        cfsetospeed(&uart, B4800);//设置输出波特率
        break;
    case 9600:
        cfsetispeed(&uart, B9600);
        cfsetospeed(&uart, B9600);
        break;
    case 19200:
        cfsetispeed(&uart, B19200);
        cfsetospeed(&uart, B19200);
        break;
    case 38400:
        cfsetispeed(&uart, B38400);
        cfsetospeed(&uart, B38400);
        break;
    case 115200:
        cfsetispeed(&uart, B115200);
        cfsetospeed(&uart, B115200);
        break;
    default:
        fprintf(stderr, "Unknown baude!\n");
        return -1;
    }
    switch (flow)
    {
    case 'N':
    case 'n':
        uart.c_cflag &= ~CRTSCTS;//不进行硬件流控制
        break;
    case 'H':
    case 'h':
        uart.c_cflag |= CRTSCTS;//进行硬件流控制
        break;
    case 'S':
    case 's':
        uart.c_cflag |= (IXON | IXOFF | IXANY);//进行软件流控制
        break;
    default:
        fprintf(stderr, "Unknown c_cflag");
        return -1;
    }
    switch (bits)
    {
    case 5:
        uart.c_cflag &= ~CSIZE;//屏蔽其他标志位
        uart.c_cflag |= CS5;//数据位为5位
        break;
    case 6:
        uart.c_cflag &= ~CSIZE;
        uart.c_cflag |= CS6;
        break;
    case 7:
        uart.c_cflag &= ~CSIZE;
        uart.c_cflag |= CS7;
        break;
    case 8:
        uart.c_cflag &= ~CSIZE;
        uart.c_cflag |= CS8;
        break;
    default:
        fprintf(stderr, "Unknown bits!");
        return -1;
    }
    switch (parity)
    {
    case 'n':
    case 'N':
        uart.c_cflag &= ~PARENB;//PARENB：产生奇偶校验
        uart.c_cflag &= ~INPCK;//INPCK：使奇偶校验起作用
        break;
    case 's':
    case 'S':
        uart.c_cflag &= ~PARENB;
        uart.c_cflag &= ~CSTOPB;//使用两位停止位
        break;
    case 'o':
    case 'O':
        uart.c_cflag |= PARENB;
        uart.c_cflag |= PARODD;//使用奇校验
        uart.c_cflag |= INPCK;
        uart.c_cflag |= ISTRIP;//使字符串剥离第八个字符，即校验位
        break;
    case 'e':
    case 'E':
        uart.c_cflag |= PARENB;
        uart.c_cflag &= ~PARODD;//非奇校验，即偶校验
        uart.c_cflag |= INPCK;
        uart.c_cflag |= ISTRIP;
        break;
    default:
        fprintf(stderr, "Unknown parity!\n");
        return -1;
    }
    switch (stop)
    {
    case 1:
        uart.c_cflag &= ~CSTOPB;//CSTOPB：使用两位停止位
        break;
    case 2:
        uart.c_cflag |= CSTOPB;
        break;
    default:
        fprintf(stderr, "Unknown stop!\n");
        return -1;
    }
    uart.c_oflag &= ~OPOST;//OPOST:表示数据经过处理后输出
    uart.c_cc[VTIME] = 0;//设置等待时间为0
    uart.c_cc[VMIN] = 1;//设置最小接受字符为1
    tcflush(fd, TCIFLUSH);//清空输入缓冲区
    if (tcsetattr(fd, TCSANOW, &uart) < 0)//激活配置
    {
        perror("tcgetattr failed!");
        return -1;
    }
    return 0;
}


// 读串口数据
int safe_read(int fd, char* vptr, size_t len) {
	printf("lkb8\n");
    size_t left;
    left = len;
    ssize_t nread;
    char* ptr;
    ptr = vptr;
    while (left > 0)
    {
        if ((nread = read(fd, ptr, left)) < 0)
        {
            /*
            if (errno == EINIR)
            {
                nread = 0;
            }
            else */
            if (nread == 0)
            {
                break;
            }
        }
        left -= nread;//read成功后，剩余要读取的字节自减
        ptr += nread;//指针向后移，避免后读到的字符覆盖先读到的字符
    }
    return (len - left);
}


// 读取串口数据
int DI_uart_read(int fd, char* r_buf, int lenth)
{
    fd_set rfds;
    struct timeval time;
    ssize_t cnt = 0;
    /*将读文件描述符加入描述符集合*/
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    /*设置超时为1s*/
    time.tv_sec = 3;
    time.tv_usec = 0;
    /*实现多路IO*/
    int ret = select(fd + 1, &rfds, NULL, NULL, &time);
	usleep(100000);
    switch (ret) {
    case -1:
        printf(stderr, "select error!\n");
        break;
    case 0:
        printf(stderr, "time over!\n");
        break;
    default:
        cnt = safe_read(fd, r_buf, lenth);
        if (cnt == -1)
        {
            printf(stderr, "safe read failed!\n");
            return -1;
        }
        break;
    }
    return cnt;
}


// 关闭串口
int DI_uart_close(int fd)
{
    if (fd <= 0)
        return 0;
    close(fd);
    fd = -1;
    return 0;
}

