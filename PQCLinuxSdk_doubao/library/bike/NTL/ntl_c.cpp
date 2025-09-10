
#include "ntl.h"

#ifdef __cplusplus
extern "C" {
#endif

void ntl_add_c(OUT uint8_t res_bin[R_SIZE],
        IN const uint8_t a_bin[R_SIZE],
        IN const uint8_t b_bin[R_SIZE])
{
    ntl_add(res_bin, a_bin, b_bin);
}

void ntl_mod_inv_c(OUT uint8_t res_bin[R_SIZE],
        IN const uint8_t a_bin[R_SIZE])
{
    ntl_mod_inv(res_bin, a_bin);
}

void ntl_mod_mul_c(OUT uint8_t res_bin[R_SIZE],
        IN const uint8_t a_bin[R_SIZE],
        IN const uint8_t b_bin[R_SIZE])
{
    ntl_mod_mul(res_bin, a_bin, b_bin);
}

void ntl_split_polynomial_c(OUT uint8_t e0[R_SIZE],
        OUT uint8_t e1[R_SIZE],
        IN const uint8_t e[2*R_SIZE])
{
    ntl_split_polynomial(e0, e1, e);
}

#ifdef __cplusplus
}
#endif