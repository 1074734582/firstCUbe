

#ifndef __DATAINTERFACE_RSA_H__
#define __DATAINTERFACE_RSA_H__

extern int rsa_sign(unsigned char* in, unsigned char* out,uint32_t keyid);
extern int rsa_verify(unsigned char *in, unsigned char* out, uint32_t keyid);
extern int rsa_enc(uint8_t* in, uint8_t* out, uint32_t keyid);
extern int rsa_dec(uint8_t* in, uint8_t* out, uint32_t keyid);

#endif