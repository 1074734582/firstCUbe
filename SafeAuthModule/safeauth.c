#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#include "safeauth.h"
#include "uart.h"
#include "rsa.h"
//#include "crypto_api.h"
#include "data.h"
#define UART_DEV_PATH "/dev/ttyUSB5"
int serial_fd;
uint8_t pcrc[256];
/********************************************************************************/
//unsigned char byteArr[5] = {0x20, 0x89, 0x9d, 0x06, 0x00};
#define  CHANNEL_AUTH_ID    0x39   //0X27

/*********************************************/
#define   MAX_RX_LEN 512
#define   TELEMETRY_FRAME_SYNCODE           0x54F82E35
#define   REMOTECTL_FRAME_SYNCODE           0x90EB

#define   TELEMETRY_REQ_PACK_HEAD           0x9D2A6C5B        
#define   TELEMETRY_AUTHREP_PACK_HEAD       0x7F7F6E5D                 
#define   TELEMETRY_SENDREP_PACK_HEAD       0xF95E6B25 
#define   TELEMETRY_REPSUCESS_PACK_HEAD      0x5ac3b1f6
#define   TELEMETRY_REPFAILED_PACK_HEAD      0xeed4a2e0                  
 
#define   REMOTECTL_AUTHREQ_PACK_HEAD       0x4C3D2B1A        
#define   REMOTECTL_AUTHREP_PACK_HEAD       0x0F5E6C7A   
#define LSB_MSB(a)  ( ((a&0x000000ff) << 24) | ((a&0x0000ff00) << 8) | ((a&0x00ff0000) >> 8) | ((a&0xff000000) >> 24) )
#define GET_ID0_INDEX 0
#define GET_ID1_INDEX 1
#define GET_ID2_INDEX 2
struct xw_privte_t *pri;
static int  run_flag = 1;
static unsigned char rx[MAX_RX_LEN];
unsigned char ID0[4];
unsigned char ID1[4];
unsigned char ID2[4];


unsigned short get_IDX_Index(unsigned char* buf,int size,int flag) {

     unsigned char IDX = 0x00;
     if(size>4){
		 
	printf("\n");
    ID2[0] = (((buf[5] >> 1) & 0x03))<<6 | (((buf[9] >> 1) & 0x03) << 4) | (((buf[4] >> 3) & 0x03) << 2) | ((buf[6] >> 6)& 0x03);  //R0[42:41],R0[74:73],R0[36:35],R0[55:54]
	printf("ID2[1]=%04x\n",ID2[0]);
    ID2[1] = (((buf[1]>>1)&0x01) <<7) | ((buf[1]&0x01)<<6) | (((buf[0]>>7)&0x01)<<5) | ((buf[5]&0x01)<<4) | (((buf[4]>>7)&0x01)<<3) | ((buf[8]>>4)&0x07); // R0[9:7],R0[40:39],R0[70:68]
    printf("ID2[1]=%04x\n",ID2[1]);
    ID2[2] = ((buf[11]&0x01)<<7) | (((buf[10] >> 7) & 0x01) <<6) | (((buf[13]&0x01)) <<5) | (((buf[12] >> 7) & 0x01) <<4) | (((buf[4] >> 5) & 0x03)<< 2) | ((buf[1] >>1)&0x03);//R0[88:87],R0[104:103],R0[38:37],R0[10:09]
    printf("ID2[2]=%04x\n",ID2[2]);
    ID2[3] = (((buf[0] >> 5) & 0x03) << 6) | ((buf[1]&0x01) << 5) | (((buf[0] >> 7) & 0x01) << 4) | ((buf[9]&0x01) << 3) | (((buf[8] >>7)&0x01)<<2)|((buf[9]>>3) &0x03); // //R0[06:05],R0[08:07],R0[72:71],R0[76:75]}
    printf("ID2[3]=%04x\n",ID2[3]);

     }else{
    switch(flag){

    case 0:
    IDX |= (buf[0] >> 4) & 0x01;
    IDX |= (buf[0] >> 2) & 0x02;
    IDX |= (buf[0] << 1) & 0x04;
    IDX |= (buf[1] >> 3) & 0x08;
    IDX |= (buf[1] >> 1) & 0x10;
    IDX |= (buf[2] << 6) & 0x20;
    IDX |= (buf[2] >> 1) & 0x40;
    IDX |= (buf[2] << 2) & 0x80;
    return (int)IDX;
    break;
    case 1:
    IDX |= (buf[0] >> 4) & 0x01;
    IDX |= (buf[0] >> 2) & 0x02;
    IDX |= (buf[0] << 1) & 0x04;
    IDX |= (buf[1] >> 3) & 0x08;
    IDX |= (buf[1] >> 1) & 0x10;
    IDX |= (buf[2] << 6) & 0x20;
    IDX |= (buf[2] >> 1) & 0x40;
    IDX |= (buf[2] << 2) & 0x80;
    return (int)IDX;
	case 2:
	IDX |= ((ID2[1] >> 3) & 0x01) << 0;
    IDX |= ((ID2[0] >> 7) & 0x01) << 1;
    IDX |= ((ID2[2] >> 5) & 0x01) << 2;
    IDX |= ((ID2[1] >> 6) & 0x01) << 3;
    IDX |= ((ID2[3] >> 3) & 0x01) << 4;
    IDX |= ((ID2[3] >> 7) & 0x01) << 5;
    IDX |= ((ID2[3] >> 1) & 0x01) << 6;
    IDX |= ((ID2[2] >> 4) & 0x01) << 7;
	return (int)IDX;
    break;
    default:

    printf("get ID index failed\n");
    }
     }
    return IDX;
}
void reverseBits(unsigned char* buf, size_t length) {
    for (size_t i = 0; i < length; i++) {
        unsigned char temp = 0;
        for (int j = 0; j < 8; j++) {
            if (buf[i] & (1 << j)) {
                temp |= 1 << (7 - j);
            }
        }
        buf[i] = temp;
    }
}
unsigned int reverse_bit(unsigned int value, unsigned int num)
{
    int i = 0;
    int bit = 0;
    int sum = 0;
    for(i = 0;i < num; i++)    //这里从0开始
    {
        sum = sum << 1;        //sum左移1位
        bit = value & 1;       //求出value的最后一位
        sum = sum | bit;       //sum | bit得到左移后的数即为将value最后一位数往前移动一位。.
        value = value >> 1;    //value右移一位，即最后一位被拿走了，放在sum中.
    }
    return sum;
}
/*swapBytes 可以使得一个数组r0[]={0x11,0x22,0x33,0x44},转换成r0[]={0x44,0x33,0x22,0x11}*/
void swapBytes(unsigned char* array, int size) {
    for (int i = 0; i < size / 2; i++) {
        unsigned char temp = array[i];
        array[i] = array[size - 1 - i];
        array[size - 1 - i] = temp;
    }
}
unsigned short swapHex(unsigned short num) {
    unsigned short high = (num >> 8) & 0xFF; // 获取高位
    unsigned short low = num & 0xFF; // 获取低位
    return (low << 8) | high; // 交换高低位并返回结果
}
uint32_t swap_uint32(uint32_t value) {
    return ((value >> 24) & 0x000000FF) |
           ((value >> 8) & 0x0000FF00) |
           ((value << 8) & 0x00FF0000) |
           ((value << 24) & 0xFF000000);
}
unsigned short get_crc16(unsigned char *ptr,int len)
{
	printf("enter get_crc16\n");
	unsigned short crc = 0xFFFF;
    unsigned char CH,CH0,CH1;
    unsigned short CH8,CH3,CH4;

    for( int i=0; i<len ;i++ ){
        CH =  ptr[i];
        CH0 = CH^(crc&0xFF);
        CH1 = CH0^(CH0<<4);
        CH8 = (CH1 << 8);
        CH3 = (CH1 << 3);
        CH4 = (CH1 >> 4);
        crc = (crc >> 8)^CH8^CH3^CH4;
        //printf("%02x  %02x  %02x ", CH, (crc >> 8), (crc&0xff));
    }
	crc = swapHex(crc);
	printf("crc=0x%02x\n",crc);
	printf("enter get_crc16 done\n");
    return(crc);
	
}

uint32_t get_time_sec()
{
	uint32_t time;
	struct timeval tv;
	gettimeofday(&tv,NULL);
	time = tv.tv_sec;

	printf("today data and time: %d,usec:  %d\n",tv.tv_sec,tv.tv_usec);
	return time;
}

int choose(xw_privte_t *pri, void *buf, uint32_t inlen, void *data, uint32_t outlen)
{
	printf("enter choose\n");
    int ret =0;
    struct remotectl_transfer_frame *send_frame = (struct remotectl_transfer_frame *)data;
    struct telemetry_transfer_frame *recv_frame = (struct telemetry_transfer_frame *)buf;
	printf("recv_frame->sync_code =%04x\n",recv_frame->sync_code);
	printf("recv_frame->sync_code =%04x\n",recv_frame->packet_head);
    if(recv_frame->sync_code == TELEMETRY_FRAME_SYNCODE && recv_frame->packet_head == TELEMETRY_REQ_PACK_HEAD)
    {
       ret = safeauth_req_send(pri, buf, inlen, data, outlen);
    }
    else if(recv_frame->sync_code == TELEMETRY_FRAME_SYNCODE && recv_frame->packet_head == TELEMETRY_AUTHREP_PACK_HEAD)
    {
        ret = safeauth_rep_send(pri, buf, inlen, data, outlen);
    }
    else if(recv_frame->sync_code == TELEMETRY_FRAME_SYNCODE && recv_frame->packet_head == TELEMETRY_SENDREP_PACK_HEAD)
    {
        ret = safeauth_ack_check(pri, buf, inlen, data, outlen);
    }else
    {
        printf("frame format error\n");
        return XW_RET_FAILED;
    }
    return ret;
}

int safeauth_req_send(xw_privte_t *pri, void *buf, uint32_t inlen, void *data, uint32_t outlen)
{
	int num_bytes;
	printf("enter safeauth_req_send\n");

	/* 
        xw_assert(inlen == sizeof(struct remotectl_transfer_frame), XW_RET_LEN_ERROR);
        printf("enter safeauth_req_send1\n");
        xw_assert(buf != NULL, XW_RET_NO_MEM);
        printf("enter safeauth_req_send2\n");
        xw_assert(data != NULL, XW_RET_NO_MEM);
        printf("enter safeauth_req_send3\n");
    */

    unsigned char id2_key;
	unsigned char R0[64]={0};
    struct remotectl_transfer_frame *send_frame = (struct remotectl_transfer_frame *)data;
    struct telemetry_transfer_frame *recv_frame = (struct telemetry_transfer_frame *)buf;
    uint8_t *pcrc = (uint8_t *)data;
	uint8_t *pcrc1 = (uint8_t *)data;
    memset(send_frame, 0, sizeof(struct remotectl_transfer_frame));

    send_frame->sync_code = 0x90EB;//帧同步码固定为EB90;
	send_frame->priframe.version =0x0;//版本号固定值0
    send_frame->priframe.bypass_flag =0x1;//旁路标志   固定值1
    send_frame->priframe.housekeeping_flag = 0x0;//内部命令标志，固定为0
    send_frame->priframe.idle =0x0;//空闲位 固定为0
    send_frame->priframe.space_id = 0x89;//航天器标识符
    send_frame->priframe.channel_id = 0x27;//虚拟信道标识 
    send_frame->priframe.frame_size =0x106;
	send_frame->priframe.frame_id = 0x0;
	
	printf("send_frame->priframe.version=%02x\n",send_frame->priframe.version);
	printf("send_frame->priframe.bypass_flag=%02x\n",send_frame->priframe.bypass_flag);
	printf("send_frame->priframe.housekeeping_flag=%02x\n",send_frame->priframe.housekeeping_flag);
	printf("send_frame->priframe.idle=%02x\n",send_frame->priframe.idle);
	printf("send_frame->priframe.space_id=%02x\n",send_frame->priframe.space_id);
	printf("send_frame->priframe.channel_id=%02x\n",send_frame->priframe.channel_id);
	printf("send_frame->priframe.frame_size=%d\n",send_frame->priframe.frame_size);
	printf("send_frame->priframe.frame_id=%02x\n",send_frame->priframe.frame_id);
	
	send_frame->priframe.space_id = reverse_bit(send_frame->priframe.space_id,10);
    send_frame->priframe.channel_id=reverse_bit(send_frame->priframe.channel_id,6);
    send_frame->priframe.frame_size=reverse_bit(send_frame->priframe.frame_size,10);
    send_frame->priframe.frame_id=reverse_bit(send_frame->priframe.frame_id,8);
    
	pcrc[sizeof(send_frame->sync_code)]=reverse_bit(pcrc[sizeof(send_frame->sync_code)],8);
	pcrc[sizeof(send_frame->sync_code)+1]=reverse_bit(pcrc[sizeof(send_frame->sync_code)+1],8);
	pcrc[sizeof(send_frame->sync_code)+2]=reverse_bit(pcrc[sizeof(send_frame->sync_code)+2],8);
	pcrc[sizeof(send_frame->sync_code)+3]=reverse_bit(pcrc[sizeof(send_frame->sync_code)+3],8);
	
    send_frame->packet_head = REMOTECTL_AUTHREQ_PACK_HEAD; //包头
    RAND_bytes(send_frame->certify_pkg.authrep.random, sizeof(send_frame->certify_pkg.authrep.random));//产生随机数R1
    //memcpy(send_frame->certify_pkg.authrep.random,bufR1,sizeof(send_frame->certify_pkg.authrep.random));
	memcpy(R0, recv_frame->certify_pkg.authrep.random,sizeof(R0));
	swapBytes(R0, sizeof(R0));
	get_IDX_Index(R0,sizeof(R0),GET_ID2_INDEX);//获取4BYTE  ID2
	for (int i=0; i<sizeof(ID2); ++i)
    {
        send_frame->certify_pkg.authrep.certificate[i] =ID2[i];//证书ID2
        printf("%02x\n", send_frame->certify_pkg.authrep.certificate[i]);
    }
    printf("\n");
	id2_key=get_IDX_Index(ID2,sizeof(ID2),GET_ID2_INDEX);//从4BYTE取8BIT组成一个BYTE
	printf("%d\n",id2_key);
    rsa_sign(recv_frame->certify_pkg.authreq.random + 48, send_frame->certify_pkg.authrep.sign+48, 1); //用地面的私钥D0对收到的随机数RO做签名，产生签名值S0
	printf("after rsa_sign end\n");
    send_frame->certify_pkg.authrep.active_time = get_time_sec();//0x7bb06a41;//有效期Indate0;
    printf("send_frame->certify_pkg.authrep.active_time=%02x\n",send_frame->certify_pkg.authrep.active_time);
    printf("send_frame->certify_pkg.authrep.active_time=%d\n",send_frame->certify_pkg.authrep.active_time);
	memset(send_frame->certify_pkg.authrep.reserve, 0, sizeof(send_frame->certify_pkg.authrep.reserve));//预留位116 0
    printf("before get_crc16\n");
	send_frame->crc = get_crc16(pcrc+sizeof(send_frame->sync_code), sizeof(struct remotectl_transfer_frame)-2-sizeof(send_frame->sync_code)); //
	printf("sizeof(struct remotectl_transfer_frame)=%d\n",sizeof(struct remotectl_transfer_frame)-2);
	for(int i =0;i<265;i++){
	printf(" %02x",*(pcrc+i));
	}
	printf("\n");
	memcpy(pri->random1, send_frame->certify_pkg.authrep.random, sizeof(send_frame->certify_pkg.authrep.random));
    printf("lkb111\n");
	pri->indate0 =(uint32_t) send_frame->certify_pkg.authrep.active_time;
    printf("pri->indate0=%02x\n",pri->indate0);
    pri->indate0=swap_uint32(pri->indate0);
    printf("pri->indate0=%d\n",sizeof(pri->indate0));
	printf("lkb222\n");
	printf("enter safeauth_req_send end\n");

	sleep(2);
	num_bytes=write(serial_fd,pcrc, outlen);
	//close(serial_fd);

	if (num_bytes == -1) {
        printf("safeauth_req_send write data failed\n");
		return  XW_RET_PARAM_ERROR;
    }
	 printf("\n");
    return 0;
}

//发送失败命令 实现
int safeauth_rep_send(xw_privte_t *pri, void *buf, uint32_t inlen, void *data, uint32_t outlen)
{
	/*
    xw_assert(inlen == sizeof(struct remotectl_transfer_frame), XW_RET_LEN_ERROR);
    xw_assert(buf != NULL, XW_RET_NO_MEM);
    xw_assert(data != NULL, XW_RET_NO_MEM);*/
    printf("enter the safeauth_rep_send\n");
    uint8_t out[16] = {0};
    uint32_t indate;
    uint8_t *pcrc = (uint8_t *)data;
	int num_bytes ;
    struct remotectl_transfer_frame *send_frame = (struct remotectl_transfer_frame *)data;
    struct telemetry_transfer_frame *recv_frame = (struct telemetry_transfer_frame *)buf;
    
    memset(send_frame, 0, sizeof(struct remotectl_transfer_frame));
	/* 暂时不加，后面要改
    printf("before rsa_verify\n ");
    rsa_verify(recv_frame->certify_pkg.authrep.sign, out, 1);                  //判定验签
	printf("after rsa_verify\n");
	printf("recv_frame->certify_pkg.authrep.active_time=%d\n",recv_frame->certify_pkg.authrep.active_time);
	printf("pri->indate0=%02x\n",pri->indate0);
	pri->indate0=get_time_sec();
    indate = recv_frame->certify_pkg.authrep.active_time - pri->indate0;    //判定时间 需要修改
	printf("after indate=%d\n",indate);
    if(memcmp(pri->random1, out, 64) ==0 || indate > 1000) 
    {
        return XW_RET_TIMEOUT;
    }
    */
    send_frame->sync_code = 0x90EB;//帧同步码固定为EB90;
	send_frame->priframe.version =0x0;//版本号固定值0
    send_frame->priframe.bypass_flag =0x1;//旁路标志   固定值1
    send_frame->priframe.housekeeping_flag = 0x0;//内部命令标志，固定为0
    send_frame->priframe.idle =0x0;//空闲位 固定为0
    send_frame->priframe.space_id = 0x89;//航天器标识符
    send_frame->priframe.channel_id = 0x27;//虚拟信道标识 
    send_frame->priframe.frame_size =0x106;//十进制是262
	send_frame->priframe.frame_id = 0x0;
	
	send_frame->priframe.space_id = reverse_bit(send_frame->priframe.space_id,10);
    send_frame->priframe.channel_id=reverse_bit(send_frame->priframe.channel_id,6);
    send_frame->priframe.frame_size=reverse_bit(send_frame->priframe.frame_size,10);
    send_frame->priframe.frame_id=reverse_bit(send_frame->priframe.frame_id,8);
    
	pcrc[sizeof(send_frame->sync_code)]=reverse_bit(pcrc[sizeof(send_frame->sync_code)],8);
	pcrc[sizeof(send_frame->sync_code)+1]=reverse_bit(pcrc[sizeof(send_frame->sync_code)+1],8);
	pcrc[sizeof(send_frame->sync_code)+2]=reverse_bit(pcrc[sizeof(send_frame->sync_code)+2],8);
	pcrc[sizeof(send_frame->sync_code)+3]=reverse_bit(pcrc[sizeof(send_frame->sync_code)+3],8);

    send_frame->packet_head = REMOTECTL_AUTHREP_PACK_HEAD;
	memset(send_frame->certify_pkg.authrcv.reserve0, 0, sizeof(send_frame->certify_pkg.authrcv.reserve0));//预留48B
	memset(send_frame->certify_pkg.authrcv.sesskey0, 0, sizeof(send_frame->certify_pkg.authrcv.sesskey0));//会话密钥8B
    RAND_bytes(send_frame->certify_pkg.authrcv.sesskey0, sizeof(send_frame->certify_pkg.authrcv.sesskey0));//产生会话密钥8B  
    //rsa_enc(send_frame->certify_pkg.authrcv.sesskey0, send_frame->certify_pkg.authrcv.sesskey0, 1);
	pri->indate0=0x7bb06a41; 
	memset(send_frame->certify_pkg.authrcv.active_time, 0, sizeof(send_frame->certify_pkg.authrcv.active_time));//有效期I1 I0
    memcpy(send_frame->certify_pkg.authrcv.active_time,&(recv_frame->certify_pkg.authrep.active_time),sizeof(recv_frame->certify_pkg.authrep.active_time));//I1
    memcpy(send_frame->certify_pkg.authrcv.active_time+sizeof(recv_frame->certify_pkg.authrep.active_time),&(pri->indate0),sizeof(pri->indate0));//I1+I0
     printf("lkb\n");
     printf("\n");
    //rsa_enc(send_frame->certify_pkg.authrcv.active_time,send_frame->certify_pkg.authrcv.active_time,1);
	//memcpy(send_frame->certify_pkg.authrcv.active_time,I0_I1,sizeof(I0_I1));//后面要改
    memcpy(out,send_frame->certify_pkg.authrcv.sesskey0,sizeof(send_frame->certify_pkg.authrcv.sesskey0));
    memcpy(out+sizeof(send_frame->certify_pkg.authrcv.sesskey0),send_frame->certify_pkg.authrcv.active_time,2*sizeof(recv_frame->certify_pkg.authrep.active_time));
     printf("\n");
	for(int i =0;i<16;i++){
	printf(" %02x",*(out+i));
	}
	printf("\n");
    rsa_enc(out,out,1);
    memcpy(send_frame->certify_pkg.authrcv.sesskey0,out,sizeof(send_frame->certify_pkg.authrcv.sesskey0));
    memcpy(send_frame->certify_pkg.authrcv.active_time,out+sizeof(send_frame->certify_pkg.authrcv.sesskey0),2*sizeof(recv_frame->certify_pkg.authrep.active_time));
     printf("\n");
	for(int i =0;i<16;i++){
	printf(" %02x",*(out+i));
	}
	printf("\n");
	rsa_sign(recv_frame->certify_pkg.authrep.random+ 48, send_frame->certify_pkg.authrcv.sign+48, 1); //签名值S2 64B
	memset(send_frame->certify_pkg.authrcv.sesskey1, 0, sizeof(send_frame->certify_pkg.authrcv.sesskey1));//会话密钥48B
   // RAND_bytes(send_frame->certify_pkg.authrcv.sesskey1, sizeof(send_frame->certify_pkg.authrcv.sesskey1));
	memset(send_frame->certify_pkg.authrcv.sesskey2, 0, sizeof(send_frame->certify_pkg.authrcv.sesskey2));//会话密钥16B
    //RAND_bytes(send_frame->certify_pkg.authrcv.sesskey2, sizeof(send_frame->certify_pkg.authrcv.sesskey2));
	memset(send_frame->certify_pkg.authrcv.reserve1, 0, sizeof(send_frame->certify_pkg.authrcv.reserve1));//预留60B
	send_frame->crc = get_crc16(pcrc+sizeof(send_frame->sync_code), sizeof(struct remotectl_transfer_frame)-2-sizeof(send_frame->sync_code)); //

    printf("\n");
	for(int i =0;i<265;i++){
	printf(" %02x",*(pcrc+i));
	}
	printf("\n");
	num_bytes=write(serial_fd,pcrc, outlen);
	//sleep(2);
	if (num_bytes == -1) {
        printf("safeauth_rep_send write data failed\n");
		return  XW_RET_PARAM_ERROR;
    }
	 printf("\n");
	 	printf("safeauth_rep_send done\n");
    return 0;
}

int safeauth_ack_check(xw_privte_t *pri, void *buf, uint32_t inlen, void *data, uint32_t outlen)
{
	/*xw_assert(inlen == sizeof(struct remotectl_transfer_frame), XW_RET_LEN_ERROR);
    xw_assert(buf != NULL, XW_RET_NO_MEM);
    xw_assert(data != NULL, XW_RET_NO_MEM);*/
	printf("enter safeauth_ack_check\n");
	int num_bytes;
    uint8_t *pcrc = (uint8_t *)data;

    struct remotectl_transfer_frame *send_frame = (struct remotectl_transfer_frame *)data;
    struct telemetry_transfer_frame *recv_frame = (struct telemetry_transfer_frame *)buf;
    
    memset(send_frame, 0, sizeof(struct remotectl_transfer_frame));
	if(recv_frame->certify_pkg.rcvrep.response == TELEMETRY_REPSUCESS_PACK_HEAD){
	printf("enter safeauth_ack_check successe=%d\n",XW_RET_AUTH_COMPLETE);
	return XW_RET_AUTH_COMPLETE;
	}else if(recv_frame->certify_pkg.rcvrep.response == TELEMETRY_REPSUCESS_PACK_HEAD){
		printf("enter safeauth_ack_check falie=%d\n",XW_RET_FAILED);
		return XW_RET_FAILED;
	}

}

//串口发送
int send(unsigned char * buf, int size)
{
	printf("enter send\n");
    uint32_t ret =0 ;
	unsigned char data[265] = {0};
	uint32_t outlen=sizeof(data);
	
	//memset(&pri, 0, sizeof(pri)); 
	if(size<MAX_RX_LEN){
		return XW_RET_LEN_ERROR;
	}else{
		memcpy(rx, buf,  size);
	}
        ret = choose(&pri,rx, size, data, outlen);
		printf("ret=%d\n",ret);
   return ret;
}
