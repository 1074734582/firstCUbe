#include "internal.h"
#include "sha3.h"


int openssl_sm3(unsigned char *in, int inlen, unsigned char *out, unsigned int* outlen)
{
//    sm3(in,inlen,out);
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
 
    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, in, inlen);
    EVP_DigestFinal_ex(md_ctx, out, outlen);
    EVP_MD_CTX_free(md_ctx);
    *outlen=32;
    return 0;
}

int openssl_sha256(unsigned char *in, int inlen, unsigned char *out)
{
    SHA256(in,inlen,out);
    return 0;
}

int crypto_hash(uint8_t algo, uint8_t *src, uint32_t len, uint8_t *digest, uint32_t *size)
{
	if(algo == MD_ALGO_SM3)
		openssl_sm3(src, len, digest, size);
	else if(algo == MD_ALGO_SHA256)	
		openssl_sha256(src, len, digest);
	else if(algo == MD_ALGO_SHA3)
		SHA3(SHA3_256, src, len, digest);
	else
		printf(">>> error algo!\r\n");
	// if(algo == MD_ALGO_SHA3){
	// 	SHA3(SHA3_256, src, len, digest);
	// 	*size = 32;
	// 	return CRYPTO_RET_SUCCESS;
	// }else
	// {
	// 	EVP_MD_CTX *ctx;
	// 	crypto_assert((ctx = EVP_MD_CTX_new()) != 0);
	// 	crypto_assert(EVP_DigestInit_ex(ctx, get_ssl_md(algo), NULL) == 1);
	// 	crypto_assert(EVP_DigestUpdate(ctx, src, len) == 1);
	// 	crypto_assert(EVP_DigestFinal_ex(ctx, digest, size) == 1);
	// 	EVP_MD_CTX_free(ctx);
		
	// 	return CRYPTO_RET_SUCCESS;
	// }

	return 0;
}

