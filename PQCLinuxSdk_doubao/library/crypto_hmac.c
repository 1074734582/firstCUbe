#include "internal.h"
#include "sha3.h"

int openssl_sm3_hmac(unsigned char *key, int keylen, unsigned char *in, int inlen, unsigned char *out, unsigned int* outlen)
{
//    sm3(in,inlen,out);
    const EVP_MD *md;
 
    md = EVP_sm3();
    HMAC(md, key, keylen, in, inlen, out, outlen);
    return 0;
}

int openssl_sha256_hmac(unsigned char *key, int keylen, unsigned char *in, int inlen, unsigned char *out, unsigned int* outlen)
{
//    sm3(in,inlen,out);
    const EVP_MD *md;
 
    md = EVP_sha256();
    HMAC(md, key, keylen, in, inlen, out, outlen);
    return 0;
}

int crypto_hmac(uint8_t algo, uint8_t *key, uint32_t keylen, uint8_t *src, uint32_t srclen, uint8_t *out, uint32_t *outlen)
{
	if(algo == MD_ALGO_SM3)
		openssl_sm3_hmac(key, keylen, src, srclen, out, outlen);
	else if(algo == MD_ALGO_SHA256)	
		openssl_sha256_hmac(key, keylen, src, srclen, out, outlen);
	else if(algo == MD_ALGO_SHA3)
		SHA3_SW_HMAC(key, keylen, src, srclen, out);
	else
		printf(">>> error algo!\r\n");	
	// if(algo == MD_ALGO_SHA3){
	// 	SHA3_SW_HMAC(key, keylen, src, srclen, mac);
	// 	return CRYPTO_RET_SUCCESS;
	// }else
	// {
	// 	uint32_t maclen;
	// 	crypto_assert(HMAC(get_ssl_md(algo), key, keylen, src, srclen, mac, &maclen) != NULL);
	// 	return CRYPTO_RET_SUCCESS;
	// }
	return 0;
}