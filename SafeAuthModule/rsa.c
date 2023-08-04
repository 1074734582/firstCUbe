#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/lhash.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/ossl_typ.h>
#include <openssl/obj_mac.h>

#include "rsa.h"
#include "safeauth.h"

#define RSA128_MODE_LENGTH   (16)

#define ID0_KEYFILE_FLAG	(0)
#define ID1_KEYFILE_FLAG	(1)
#define ID2_KEYFILE_FLAG	(2)


static void data_dump(const unsigned char* data, unsigned int data_len)
{
	int i;
	for( i=0; i<data_len; i++) {
		printf("0x%02x ",data[i]);
		if(((i+1)%16) == 0)
			printf("\r\n");
	}
	printf("\r\n");
}


int swap_4byte(unsigned char *data, unsigned int size)
{
    unsigned int i,j;
    unsigned char *p_tail = data;
    unsigned char *p_head = data;
    unsigned char temp;
    p_tail += (size-4);
    
    for(i = 0; i< size/8; i++)
    {
        for(j=0;j<4;j++)    
        {
            temp = p_tail[j];
            p_tail[j] = p_head[j];
            p_head[j] =temp;
        }
        p_tail-=4;
        p_head+=4;
    }
	return 0;
}

int get_key_from_file(char flag, uint8_t *n, uint8_t *d, uint8_t *e, uint32_t keyid)
{
	FILE *fp;
 	uint32_t key_offset;

	if(flag == ID0_KEYFILE_FLAG)
		fp = fopen("./test.bin", "rb");
	else if(flag == ID1_KEYFILE_FLAG)
		fp = fopen("./test.bin", "rb");
	else if(flag == ID2_KEYFILE_FLAG)
		fp = fopen("./test.bin", "rb");
		
    if (fp == NULL)
    {
        printf("open key file fail\n");
        return XW_RET_FAILED;
    }
    else
    {
        key_offset = keyid * (RSA128_MODE_LENGTH*3);
        fseek(fp, key_offset, SEEK_CUR);
		fread(n, 1, RSA128_MODE_LENGTH, fp);
		fread(d, 1, RSA128_MODE_LENGTH, fp);
		fread(e, 1, RSA128_MODE_LENGTH, fp);
        if (fread(n, 1, RSA128_MODE_LENGTH, fp) != RSA128_MODE_LENGTH )
        {
            printf("read rsa key n file failed\n");
            return XW_RET_FAILED;
        }
		 if (fread(d, 1, RSA128_MODE_LENGTH, fp) != RSA128_MODE_LENGTH )
        {
            printf("read rsa key d file failed\n");
            return XW_RET_FAILED;
        }
		 if (fread(e, 1, RSA128_MODE_LENGTH, fp) != RSA128_MODE_LENGTH )
        {
            printf("read rsa key e file failed\n");
            return XW_RET_FAILED;
        }
        fclose(fp);
//        data_dump(n, RSA128_MODE_LENGTH);   //测试
    }
}

int rsa_sign(uint8_t* in, uint8_t* out, uint32_t keyid)
{
    int ret = -1;
	uint8_t n_arr[32],d_arr[32],e_arr[32];

    BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	RSA* rsa = RSA_new();

	get_key_from_file(0, n_arr,d_arr,e_arr, keyid);

	swap_4byte(n_arr, RSA128_MODE_LENGTH);
	swap_4byte(d_arr, RSA128_MODE_LENGTH);
	swap_4byte(e_arr, RSA128_MODE_LENGTH);
	swap_4byte(in, RSA128_MODE_LENGTH);

	data_dump(n_arr, RSA128_MODE_LENGTH);
    data_dump(d_arr, RSA128_MODE_LENGTH);
	data_dump(e_arr, RSA128_MODE_LENGTH);
	data_dump(in, RSA128_MODE_LENGTH);

    BN_bin2bn(n_arr, RSA128_MODE_LENGTH, n);
	BN_bin2bn(d_arr, RSA128_MODE_LENGTH, d);
	BN_bin2bn(e_arr, RSA128_MODE_LENGTH, e);
	RSA_set0_key(rsa, n, e, d);

    // sign
	ret = RSA_private_encrypt(RSA128_MODE_LENGTH, in, out, rsa, RSA_NO_PADDING);
	printf("ret=%d\n", ret);
	if (ret != RSA128_MODE_LENGTH) {
		printf("RSA_private_encrypt sign error ret=%d\n", ret);
		return XW_RET_FAILED;
	}
	else {
		printf("RSA_private_encrypt sign pass ret=%d\n", ret);
	}
	swap_4byte(out, RSA128_MODE_LENGTH);
	
	data_dump(out, RSA128_MODE_LENGTH);

	RSA_free(rsa);
	printf("rsa_sign done\n");

    return XW_RET_SUCCESS;
}

int rsa_verify(uint8_t *in, uint8_t* out, uint32_t keyid)
{
	int ret = 0;
	uint8_t n_arr[32],d_arr[32],e_arr[32];

    BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	RSA* rsa = RSA_new();

	get_key_from_file(0, n_arr,d_arr,e_arr, keyid);

	swap_4byte(n_arr, RSA128_MODE_LENGTH);
	swap_4byte(d_arr, RSA128_MODE_LENGTH);
	swap_4byte(e_arr, RSA128_MODE_LENGTH);
	swap_4byte(in, RSA128_MODE_LENGTH);

	data_dump(n_arr, RSA128_MODE_LENGTH);
    data_dump(d_arr, RSA128_MODE_LENGTH);
	data_dump(e_arr, RSA128_MODE_LENGTH);
	data_dump(in, RSA128_MODE_LENGTH);

    BN_bin2bn(n_arr, RSA128_MODE_LENGTH, n);
	BN_bin2bn(d_arr, RSA128_MODE_LENGTH, d);
	BN_bin2bn(e_arr, RSA128_MODE_LENGTH, e);
	RSA_set0_key(rsa, n, e, d);

	ret = RSA_public_decrypt(RSA128_MODE_LENGTH, in, out, rsa, RSA_NO_PADDING);
	printf("after RSA_public_decrypt=%d\n",ret);
	if (ret != RSA128_MODE_LENGTH) {
		printf("RSA_public_decrypt ver error ret=%d\n", ret);
		XW_RET_FAILED;
	}
	swap_4byte(out, RSA128_MODE_LENGTH);
	data_dump(out, RSA128_MODE_LENGTH);
    RSA_free(rsa);
	return XW_RET_SUCCESS;
}


int rsa_enc(uint8_t* in, uint8_t* out, uint32_t keyid)
{
    int ret = -1;
	printf("enter rsa_enc\n");
	uint8_t n_arr[32],d_arr[32],e_arr[32];

    BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	RSA* rsa = RSA_new();

	get_key_from_file(0, n_arr,d_arr,e_arr, keyid);

	swap_4byte(n_arr, RSA128_MODE_LENGTH);
	swap_4byte(d_arr, RSA128_MODE_LENGTH);
	swap_4byte(e_arr, RSA128_MODE_LENGTH);
	swap_4byte(in, RSA128_MODE_LENGTH);

	data_dump(n_arr, RSA128_MODE_LENGTH);
    data_dump(d_arr, RSA128_MODE_LENGTH);
	data_dump(e_arr, RSA128_MODE_LENGTH);
	data_dump(in, RSA128_MODE_LENGTH);

    BN_bin2bn(n_arr, RSA128_MODE_LENGTH, n);
	BN_bin2bn(d_arr, RSA128_MODE_LENGTH, d);
	BN_bin2bn(e_arr, RSA128_MODE_LENGTH, e);
	RSA_set0_key(rsa, n, e, d);

    // enc
	ret = RSA_public_encrypt(RSA128_MODE_LENGTH, in, out, rsa, RSA_NO_PADDING);
	printf("ret=%d\n", ret);
	if (ret != RSA128_MODE_LENGTH) {
		printf("RSA_private_encrypt sign error ret=%d\n", ret);
		return XW_RET_FAILED;
	}
	else {
		printf("RSA_private_encrypt sign pass ret=%d\n", ret);
	}
	swap_4byte(out, RSA128_MODE_LENGTH);
	
	data_dump(out, RSA128_MODE_LENGTH);

	RSA_free(rsa);
	printf("rsa_enc done\n");

    return XW_RET_SUCCESS;
}

int rsa_dec(uint8_t *in, uint8_t* out, uint32_t keyid)
{
	int ret = 0;
	uint8_t n_arr[32],d_arr[32],e_arr[32];

    BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	RSA* rsa = RSA_new();

	get_key_from_file(0, n_arr,d_arr,e_arr, keyid);

	swap_4byte(n_arr, RSA128_MODE_LENGTH);
	swap_4byte(d_arr, RSA128_MODE_LENGTH);
	swap_4byte(e_arr, RSA128_MODE_LENGTH);
	swap_4byte(in, RSA128_MODE_LENGTH);

	data_dump(n_arr, RSA128_MODE_LENGTH);
    data_dump(d_arr, RSA128_MODE_LENGTH);
	data_dump(e_arr, RSA128_MODE_LENGTH);
	data_dump(in, RSA128_MODE_LENGTH);

    BN_bin2bn(n_arr, RSA128_MODE_LENGTH, n);
	BN_bin2bn(d_arr, RSA128_MODE_LENGTH, d);
	BN_bin2bn(e_arr, RSA128_MODE_LENGTH, e);
	RSA_set0_key(rsa, n, e, d);

	ret = RSA_private_decrypt(RSA128_MODE_LENGTH, in, out, rsa, RSA_NO_PADDING);
	printf("after RSA_public_decrypt=%d\n",ret);
	if (ret != RSA128_MODE_LENGTH) {
		printf("RSA_public_decrypt ver error ret=%d\n", ret);
		XW_RET_FAILED;
	}
	swap_4byte(out, RSA128_MODE_LENGTH);
	data_dump(out, RSA128_MODE_LENGTH);
    RSA_free(rsa);
	return XW_RET_SUCCESS;
}
