#include "internal.h"
#include "sha3.h"

int gmssl_tls1_prf_P_hash(const EVP_MD *md,
                           const unsigned char *sec, size_t sec_len,
                           const unsigned char *seed, size_t seed_len,
                           unsigned char *out, size_t olen)
{
    int chunk;
    EVP_MD_CTX *ctx = NULL, *ctx_tmp = NULL, *ctx_init = NULL;
    EVP_PKEY *mac_key = NULL;
    unsigned char A1[EVP_MAX_MD_SIZE];
    size_t A1_len;
    int ret = 0;

    chunk = EVP_MD_size(md);
    OPENSSL_assert(chunk >= 0);

    ctx = EVP_MD_CTX_new();
    ctx_tmp = EVP_MD_CTX_new();
    ctx_init = EVP_MD_CTX_new();
    if (ctx == NULL || ctx_tmp == NULL || ctx_init == NULL)
        goto err;
    EVP_MD_CTX_set_flags(ctx_init, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
    if (mac_key == NULL)
        goto err;
    if (!EVP_DigestSignInit(ctx_init, NULL, md, NULL, mac_key))
        goto err;
    if (!EVP_MD_CTX_copy_ex(ctx, ctx_init))
        goto err;
    if (seed != NULL && !EVP_DigestSignUpdate(ctx, seed, seed_len))
        goto err;
    if (!EVP_DigestSignFinal(ctx, A1, &A1_len))
        goto err;

    for (;;) {
        /* Reinit mac contexts */
        if (!EVP_MD_CTX_copy_ex(ctx, ctx_init))
            goto err;
        if (!EVP_DigestSignUpdate(ctx, A1, A1_len))
            goto err;
        if (olen > (size_t)chunk && !EVP_MD_CTX_copy_ex(ctx_tmp, ctx))
            goto err;
        if (seed && !EVP_DigestSignUpdate(ctx, seed, seed_len))
            goto err;

        if (olen > (size_t)chunk) {
            size_t mac_len;
            if (!EVP_DigestSignFinal(ctx, out, &mac_len))
                goto err;
            out += mac_len;
            olen -= mac_len;
            /* calc the next A1 value */
            if (!EVP_DigestSignFinal(ctx_tmp, A1, &A1_len))
                goto err;
        } else {                /* last one */

            if (!EVP_DigestSignFinal(ctx, A1, &A1_len))
                goto err;
            memcpy(out, A1, olen);
            break;
        }
    }
    ret = 1;
 err:
    EVP_PKEY_free(mac_key);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx_tmp);
    EVP_MD_CTX_free(ctx_init);
    OPENSSL_cleanse(A1, sizeof(A1));
    return ret;
}

int crypto_prf(uint8_t hash_algo, uint8_t *sec, uint32_t seclen, uint8_t *seed, uint32_t seedlen, uint8_t *out, uint32_t outlen)
{
    if(hash_algo == MD_ALGO_SHA3){
        SHA3_SW_PRF(sec, 136, seed, seedlen, out, outlen); //sha3 seclen:136
        return CRYPTO_RET_SUCCESS;
    }else
    {
        crypto_assert(gmssl_tls1_prf_P_hash(get_ssl_md(hash_algo), sec, seclen, seed, seedlen, out, outlen) == 1);
        return CRYPTO_RET_SUCCESS;
    }
}