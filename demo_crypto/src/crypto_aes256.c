/******************************************************************************
  *  文件名     : crypto_aes256.c
  *  负责人     : xupeng
  *  创建日期   : 20250123
  *  版本号     : v1.1 
  *  文件描述   : AES256加解密接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "logger.h"
#include "crypto_aes256.h"
#include "crypto_macro.h"

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 获取AES密钥.
*  输入参数  : infile - 指定加密的文件名.
*  输出参数  : key - 256位AES 密钥.
*             iv - AES 向量.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int read_openssl_aes256_key_info(uint8_t *key, uint8_t *iv, const char *infile)
{
    FILE *fp = NULL;
    char path[FULL_FILENAME_LEN] = {0};

    if (NULL == key || NULL == iv || NULL == infile)
    {
        APP_LOG_ERROR("Parameter is NULL[key: %p][iv: %p][infile: %p]", key, iv, infile);
        return -1;
    }

    snprintf(path, sizeof(path), "%s", infile);
    fp = fopen(path, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]", path);
        return -1;
    }

    fread(key, 1, AES_KEY_LEN, fp);
    fread(iv, 1, AES_IV_LEN, fp);

    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 构造随机的AES加密密钥，并将密钥作为文件保存至指定路径.
*  输入参数  : filename - 指定加密的文件名.
*             key_fullpath - 指定解密的密钥文件路径(包含文件名).
*             encrypt_path - 指定加密的文件路径.
*  输出参数  : key - 256位AES 密钥.
*             iv - AES 向量.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int read_or_create_random_openssl_aes256_key(uint8_t *key, 
                                             uint8_t *iv, 
                                             const char *key_fullpath, 
                                             const char *encrypt_path, 
                                             const char *filename)
{
    FILE *fp = NULL;
    char path[FULL_FILENAME_LEN] = {0};

    if (NULL == key || NULL == iv || NULL == key_fullpath || NULL == encrypt_path || NULL == filename)
    {
        APP_LOG_ERROR("Parameter is NULL[key: %p][iv: %p][key_fullpath: %p][encrypt_path: %p][filename: %p]", 
            key, iv, key_fullpath, encrypt_path, filename);
        return -1;
    }

    if (0 == strcmp(key_fullpath, ""))
    {
        /* 生成随机密钥 */
        if (0 == RAND_bytes(key, AES_KEY_LEN))
        {
            APP_LOG_ERROR("RAND_bytes failed");
            return -1;
        }

        if (0 == RAND_bytes(iv, AES_IV_LEN))
        {
            APP_LOG_ERROR("RAND_bytes failed");
            return -1;
        }

        snprintf(path, sizeof(path), "%s/%s.aes256.key", encrypt_path, filename);
        fp = fopen(path, "wb");
        if (NULL == fp)
        {
            APP_LOG_ERROR("fopen failed[%s]", path);
            return -1;
        }

        fwrite(key, 1, AES_KEY_LEN, fp);
        fwrite(iv, 1, AES_IV_LEN, fp);

        if (fp != NULL)
        {
            fclose(fp);
            fp = NULL;
        }
    }
    else 
    {
        if (read_openssl_aes256_key_info(key, iv, key_fullpath) != 0)
        {
            APP_LOG_ERROR("Failed to read openssl aes256 key info[%s]", key_fullpath);
            return -1;
        }
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期	 : 20250117
*  函数功能  : AES加密 - 根据指定的MMAP地址，进行文件加密操作.
*  输入参数  : addr - mmap对应的待加密文件地址.
*             datalen - 待加密的文件长度.
*             key_fullpath - 指定解密的密钥文件路径(包含文件名).
*             encrypt_path - 指定加密的文件路径.
*             filename - 指定加密的文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int aes256_encrypt_specified_mmap_addr(const char *addr, 
                                       int datalen, 
                                       const char *key_fullpath, 
                                       const char *encrypt_path, 
                                       const char *filename)
{
    int             ret                     = -1;
    int             sup_len                 = 0;
    int             outlen                  = 0;
    int             readlen                 = 0;
    FILE            *fp                     = NULL;
    EVP_CIPHER_CTX  *ctx                    = NULL;
    uint8_t         *plaintext              = NULL;
    uint8_t         *ciphertext             = NULL;
    uint8_t         key[AES_KEY_LEN]        = {0};
    uint8_t         iv[AES_IV_LEN]          = {0};
    char            path[FULL_FILENAME_LEN] = {0};

    if (NULL == addr ||  NULL == encrypt_path || NULL == filename)
    {
        APP_LOG_ERROR("Parameter is NULL[addr: %p][encrypt_path: %p][filename: %p]", addr, encrypt_path, filename);
        return -1;
    }

    /* 生成随机密钥 */
    if (read_or_create_random_openssl_aes256_key(key, iv, key_fullpath, encrypt_path, filename) != 0)
    {
        APP_LOG_ERROR("Failed to create random openssl aes256 key");
        return -1;
    }

    APP_MODULE_BYTE_LOG_DEBUG("key", key, sizeof(key));
    APP_MODULE_BYTE_LOG_DEBUG("iv", iv, sizeof(iv));

    /* 创建并初始化上下文 */
    if (NULL == (ctx = EVP_CIPHER_CTX_new())) 
    {
        APP_LOG_ERROR("EVP_CIPHER_CTX_new failed");
        goto CLEAN;
    }

    /* 设置为加密模式 */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) 
    {
        APP_LOG_ERROR("EVP_EncryptInit_ex failed");
        goto CLEAN;
    }

    /* 打开输入输出文件 */
    snprintf(path, sizeof(path), "%s/%s.tmp", encrypt_path, filename);
    fp = fopen(path, "wb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]", path);
        goto CLEAN;
    }

    /* 分块读取和加密数据 */
    sup_len = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    plaintext = (uint8_t *)calloc(1, BUFFER_SIZE + BUFFER_SIZE + sup_len);
    if (NULL == plaintext)
    {
        APP_LOG_ERROR("calloc failed");
        goto CLEAN;
    }

    ciphertext = plaintext + BUFFER_SIZE;
    while (readlen + BUFFER_SIZE < datalen)
    {
        memcpy(plaintext, addr + readlen, BUFFER_SIZE);
        if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, BUFFER_SIZE) != 1)
        {
            APP_LOG_ERROR("EVP_EncryptUpdate failed");
            goto CLEAN;
        }
        fwrite(ciphertext, 1, outlen, fp);
        readlen += BUFFER_SIZE;
    }

    memcpy(plaintext, addr + readlen, datalen - readlen);
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, datalen - readlen) != 1)
    {
        APP_LOG_ERROR("EVP_EncryptUpdate failed");
        goto CLEAN;
    }
    fwrite(ciphertext, 1, outlen, fp);

    /* 处理最后剩余的数据 */
    if (EVP_EncryptFinal_ex(ctx, ciphertext, &outlen) != 1)
    {
        APP_LOG_ERROR("EVP_EncryptFinal_ex failed");
        goto CLEAN;
    }
    fwrite(ciphertext, 1, outlen, fp);
    APP_LOG_DEBUG("readlen: %d, datalen: %d", readlen, datalen);

    ret = 0;

    /* 清理 */
CLEAN:
    if (plaintext != NULL)
    {
        free(plaintext);
        plaintext = NULL;
    }

    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }

    if (ctx != NULL)
    {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : AES解密 - 根据指定的MMAP地址，进行文件解密操作.
*  输入参数  : addr - mmap对应的待解密文件地址.
*             datalen - 待解密的文件长度.
*             key_fullpath - 指定解密的密钥文件路径(包含文件名).
*             decrypt_path - 指定解密的文件路径.
*             filename - 指定解密的文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int aes256_decrypt_specified_mmap_addr(const char *addr, 
                                       int datalen, 
                                       const char *key_fullpath, 
                                       const char *decrypt_path, 
                                       const char *filename)
{
    int             ret                     = -1;
    int             outlen                  = 0;
    int             readlen                 = 0;
    int             sup_len                 = 0;
    FILE            *fp                     = NULL;
    EVP_CIPHER_CTX  *ctx                    = NULL;
    uint8_t         *plaintext              = NULL;
    uint8_t         *ciphertext             = NULL;
    uint8_t         key[AES_KEY_LEN]        = {0};
    uint8_t         iv[AES_IV_LEN]          = {0};
    char            path[FULL_FILENAME_LEN] = {0};

    if (NULL == addr || NULL == decrypt_path || NULL == filename)
    {
        APP_LOG_ERROR("Parameter is NULL[addr: %p][decrypt_path: %p][filename: %p]", addr, decrypt_path, filename);
        return -1;
    }

    if (read_openssl_aes256_key_info(key, iv, key_fullpath) != 0)
    {
        APP_LOG_ERROR("Failed to read openssl aes256 key info");
        return -1;
    }

    APP_MODULE_BYTE_LOG_DEBUG("key", key, AES_KEY_LEN);
    APP_MODULE_BYTE_LOG_DEBUG("iv", iv, AES_IV_LEN);

    /* 创建并初始化上下文 */
    if (NULL ==(ctx = EVP_CIPHER_CTX_new()))
    {
        APP_LOG_ERROR("EVP_CIPHER_CTX_new failed");
        goto CLEAN;
    }

    /* 初始化解密操作 */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        APP_LOG_ERROR("EVP_DecryptInit_ex failed");
        goto CLEAN;
    }

    /* 打开输入输出文件 */
    snprintf(path, sizeof(path), "%s/%s.tmp", decrypt_path, filename);
    fp = fopen(path, "wb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]", path);
        goto CLEAN;
    }

    /* 分块读取和解密数据 */
    sup_len = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    plaintext = (uint8_t *)calloc(1, BUFFER_SIZE + sup_len + BUFFER_SIZE);
    if (NULL == plaintext)
    {
        APP_LOG_ERROR("calloc failed");
        goto CLEAN;
    }

    ciphertext = plaintext + BUFFER_SIZE + sup_len;
    while (readlen + BUFFER_SIZE < datalen)
    {
        memcpy(ciphertext, addr + readlen, BUFFER_SIZE);

        if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, BUFFER_SIZE) != 1)
        {
            APP_LOG_ERROR("EVP_DecryptUpdate failed");
            goto CLEAN;
        }

        fwrite(plaintext, 1, outlen, fp);
        readlen += BUFFER_SIZE;
    }

    memcpy(ciphertext, addr + readlen, datalen - readlen);
    if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, datalen - readlen) != 1)
    {
        APP_LOG_ERROR("EVP_DecryptUpdate failed");
        goto CLEAN;
    }
    fwrite(plaintext, 1, outlen, fp);

    /* 完成解密操作 */
    if (EVP_DecryptFinal_ex(ctx, plaintext, &outlen) != 1)
    {
        APP_LOG_ERROR("EVP_DecryptFinal_ex failed");
        goto CLEAN;
    }
    fwrite(plaintext, 1, outlen, fp);
    APP_LOG_DEBUG("readlen: %d, datalen: %d", readlen, datalen);

    ret = 0;

    /* 清理 */
CLEAN:
    if (plaintext != NULL)
    {
        free(plaintext);
        plaintext = NULL;
    }

    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }

    if (ctx != NULL)
    {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    return ret;
}
