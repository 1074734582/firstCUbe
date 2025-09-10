#include "internal.h"

#define ECDH_KDF_MAX    (1 << 30)
#define AES128_BLOCK_SIZE 16
#define AES256_BLOCK_SIZE 32

const EVP_CIPHER *crypto_get_ssl_cipher(uint8_t algo, uint8_t mode, uint32_t key_len)
{
	const EVP_CIPHER *cipher;

	if(algo == CIPHER_AES)
	{ 
    	if((mode == CIPHER_MODE_XTS) && (key_len == 32))
    	{
			cipher = EVP_aes_128_xts();
			return cipher;
    	}
    	
    	if((mode == CIPHER_MODE_XTS) && (key_len == 64))
    	{
			cipher = EVP_aes_256_xts();
			return cipher;
    	}

		if(key_len == 16)
		{
			if(mode == CIPHER_MODE_ECB)
				cipher = EVP_aes_128_ecb();

			if(mode == CIPHER_MODE_CBC || mode == CIPHER_MODE_CMAC || mode == CIPHER_MODE_CBC_MAC)
				cipher = EVP_aes_128_cbc();
		
			if(mode == CIPHER_MODE_CFB)
                cipher = EVP_aes_128_cfb();

            if(mode == CIPHER_MODE_OFB)
                cipher = EVP_aes_128_ofb();

			if(mode == CIPHER_MODE_CTR)
				cipher = EVP_aes_128_ctr();

			if(mode == CIPHER_MODE_CCM)
				cipher = EVP_aes_128_ccm();

			if(mode == CIPHER_MODE_GCM)
				cipher = EVP_aes_128_gcm();
		}
		if(key_len == 24)
		{
			if(mode == CIPHER_MODE_ECB)
				cipher = EVP_aes_192_ecb();

			if(mode == CIPHER_MODE_CBC || mode == CIPHER_MODE_CMAC || mode == CIPHER_MODE_CBC_MAC)
				cipher = EVP_aes_192_cbc();
		
			if(mode == CIPHER_MODE_CFB)
				cipher = EVP_aes_192_cfb();
				
            if(mode == CIPHER_MODE_OFB)
                cipher = EVP_aes_192_ofb();

			if(mode == CIPHER_MODE_CTR)
				cipher = EVP_aes_192_ctr();
				
			if(mode == CIPHER_MODE_CCM)
				cipher = EVP_aes_192_ccm();

			if(mode == CIPHER_MODE_GCM)
				cipher = EVP_aes_192_gcm();

		}
		if(key_len == 32)
		{
			if(mode == CIPHER_MODE_ECB)
				cipher = EVP_aes_256_ecb();

			if(mode == CIPHER_MODE_CBC || mode == CIPHER_MODE_CMAC || mode == CIPHER_MODE_CBC_MAC)
				cipher = EVP_aes_256_cbc();

			if(mode == CIPHER_MODE_CFB)
                cipher = EVP_aes_256_cfb();

            if(mode == CIPHER_MODE_OFB)
                cipher = EVP_aes_256_ofb();

			if(mode == CIPHER_MODE_CTR)
				cipher = EVP_aes_256_ctr();

			if(mode == CIPHER_MODE_CCM)
				cipher = EVP_aes_256_ccm();

			if(mode == CIPHER_MODE_GCM)
				cipher = EVP_aes_256_gcm();
		}
	}

	if(algo == CIPHER_SM4)
	{ 
		if(mode == CIPHER_MODE_ECB)
			cipher = EVP_sms4_ecb();

		if(mode == CIPHER_MODE_CBC || mode == CIPHER_MODE_CMAC || mode == CIPHER_MODE_CBC_MAC)
			cipher = EVP_sms4_cbc();

	  	if(mode == CIPHER_MODE_CFB)
            cipher = EVP_sms4_cfb();

        if(mode == CIPHER_MODE_OFB)
            cipher = EVP_sms4_ofb();

		if(mode == CIPHER_MODE_XTS)
			cipher = EVP_sms4_xts();

		if(mode == CIPHER_MODE_CTR)
			cipher = EVP_sms4_ctr();

		if(mode == CIPHER_MODE_CCM)
			cipher = EVP_sms4_ccm();

		if(mode == CIPHER_MODE_GCM)
			cipher = EVP_sms4_gcm();

	}
	return cipher;
}

int crypto_cipher_cmac(uint8_t algo, uint8_t mode, uint8_t *key, uint32_t key_len, 
						uint8_t *src, uint32_t src_len, uint8_t *dst)
{
	int len = 0;
	const EVP_CIPHER *cipher = crypto_get_ssl_cipher(algo, mode, key_len);

	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, key, key_len, cipher, NULL);
	CMAC_Update(ctx, src, src_len);
	CMAC_Final(ctx, dst, (size_t *)&len);
	CMAC_CTX_free(ctx);
	return CRYPTO_RET_SUCCESS;	
}

int crypto_cipher_cbc_mac(uint8_t algo, uint8_t mode, uint8_t *key, uint32_t key_len, 
						uint8_t *src, uint32_t src_len, uint8_t *dst)
{
    int isSuccess = 0;
    unsigned char in[AES128_BLOCK_SIZE];  
    int outl = 0;   
    int outl_total = 0;
    int ret = 0;
    unsigned char out_buff_temp[8192] = {0};
    unsigned char iv_temp[16];
    memset(iv_temp, 0x0, 16);	

	const EVP_CIPHER *cipher = crypto_get_ssl_cipher(algo, mode, key_len);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv_temp);
//  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

	while(src_len >=AES128_BLOCK_SIZE)
	{
		memcpy(in, src, AES128_BLOCK_SIZE);  
		src_len -= AES128_BLOCK_SIZE;  
		src += AES128_BLOCK_SIZE;  
		isSuccess = EVP_EncryptUpdate(ctx, out_buff_temp + outl_total, &outl, in, AES128_BLOCK_SIZE);  
		if(!isSuccess)  
		{  
			printf("EVP_EncryptUpdate() failed");  
			EVP_CIPHER_CTX_free(ctx); 
			ret = -1;
			return ret;
		}  
		outl_total += outl;  
	}

	if(src_len > 0)  
	{  
		memcpy(in, src, src_len); 
		isSuccess = EVP_EncryptUpdate(ctx,out_buff_temp + outl_total, &outl, in, src_len);  
		outl_total += outl;  

		isSuccess = EVP_EncryptFinal_ex(ctx,out_buff_temp + outl_total,&outl);  
		if(!isSuccess)  
		{  
			printf("EVP_EncryptFinal_ex() failed");  
			EVP_CIPHER_CTX_free(ctx);  
			ret = -2;
			return ret;
		}  
		outl_total += outl;  
	}     

	memcpy(dst, &out_buff_temp[outl_total -16], 16);
//    BIO_dump_fp(stdout, sz_out_buff, 16);

	EVP_CIPHER_CTX_free(ctx); 
//		*sz_out_len = 16;
	return ret ;
}

int crypto_cipher(uint8_t algo, uint8_t mode, uint8_t enc, uint8_t *key, uint32_t key_len, 
            uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *src, uint32_t src_len, uint8_t *dst, uint8_t tag[16], uint32_t tag_len)
{
    int len = 0;
	int ret = 0;
    const EVP_CIPHER *cipher = crypto_get_ssl_cipher(algo, mode, key_len);

	if(mode == CIPHER_MODE_CMAC)
	{
		ret = crypto_cipher_cmac(algo, mode, key, key_len, src, src_len, dst);
		return ret;
	}
	else if(mode == CIPHER_MODE_CBC_MAC)
	{
		ret = crypto_cipher_cbc_mac(algo, mode, key, key_len, src, src_len, dst);
		return ret;
	}
	else{
		EVP_CIPHER_CTX *ctx;
		crypto_assert((ctx = EVP_CIPHER_CTX_new()) != 0);
		crypto_assert(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc) == 1);
		EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);

		if (mode == CIPHER_MODE_GCM || mode == CIPHER_MODE_CCM)
		{
			crypto_assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL) == 1);
			crypto_assert(EVP_CipherUpdate(ctx, NULL, &len, aad, aad_len) == 1);
			if ((mode == CIPHER_MODE_GCM || mode == CIPHER_MODE_CCM) && !enc)
				crypto_assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag) == 1);  //gcm tag len:16
			if(mode == CIPHER_MODE_CCM && enc)
				crypto_assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, NULL) == 1);
		}
			
		crypto_assert(EVP_CipherUpdate(ctx, dst, &len, src, src_len) == 1);
		crypto_assert(EVP_CipherFinal_ex(ctx, dst + len, &len) == 1);


		if ((mode == CIPHER_MODE_GCM || mode == CIPHER_MODE_CCM ) && (enc))
			crypto_assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag) == 1); //ok?

		EVP_CIPHER_CTX_free(ctx);
		
		if(mode == CIPHER_MODE_CBC_MAC)
		{
			memcpy(dst,&dst[src_len - 16], 16);
		}
		return CRYPTO_RET_SUCCESS;
	}
}

int crypto_cipher_ccm(uint8_t algo, uint8_t mode, uint8_t enc, uint8_t *key, uint32_t key_len, 
            uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *src, uint32_t src_len, uint8_t *dst, uint8_t tag[16], uint32_t tag_len)
{
//    int len = 0;
    const EVP_CIPHER *cipher = crypto_get_ssl_cipher(algo, mode, key_len);

    EVP_CIPHER_CTX *ctx;
	int outlen, tmplen;

	ctx = EVP_CIPHER_CTX_new();
	/* Set cipher type and mode */
   	EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
	/* Set nonce length if default 96 bits is not appropriate */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL);
	/* Set tag length */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL);
	/* Initialise key and IV */
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	/* Set plaintext length: only needed if AAD is used*/
	EVP_EncryptUpdate(ctx, NULL, &tmplen, NULL, src_len);
	/* Zero or one call to specify any AAD */
	EVP_EncryptUpdate(ctx, NULL, &tmplen, aad, aad_len);
	/* Encrypt plaintext: can only be called once */
	EVP_EncryptUpdate(ctx, dst, &outlen, src, src_len);
	/* Finalise: note get no output for CCM */
	EVP_EncryptFinal_ex(ctx, dst, &tmplen);  //0
	/* Get tag */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag);

	EVP_CIPHER_CTX_free(ctx);

	return CRYPTO_RET_SUCCESS;
}

int crypto_cipher_gcm(uint8_t algo, uint8_t mode, uint8_t enc, uint8_t *key, uint32_t key_len, 
            uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *src, uint32_t src_len, uint8_t *dst, uint8_t tag[16], uint32_t tag_len)
{
//    int len = 0;
    const EVP_CIPHER *cipher = crypto_get_ssl_cipher(algo, mode, key_len);

    EVP_CIPHER_CTX *ctx;
	int outlen, tmplen;

	ctx = EVP_CIPHER_CTX_new();
	/* Set cipher type and mode */
   	EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
	/* Set nonce length if default 96 bits is not appropriate */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
	/* Set tag length */
	//EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, NULL);
	/* Initialise key and IV */
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	/* Set plaintext length: only needed if AAD is used*/
	//EVP_EncryptUpdate(ctx, NULL, &tmplen, NULL, src_len);
	/* Zero or one call to specify any AAD */
	EVP_EncryptUpdate(ctx, NULL, &tmplen, aad, aad_len);
	/* Encrypt plaintext: can only be called once */
	EVP_EncryptUpdate(ctx, dst, &outlen, src, src_len);
	/* Finalise: note get no output for CCM */
	EVP_EncryptFinal_ex(ctx, dst, &tmplen);  //0
	/* Get tag */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

	EVP_CIPHER_CTX_free(ctx);

	return CRYPTO_RET_SUCCESS;
}
