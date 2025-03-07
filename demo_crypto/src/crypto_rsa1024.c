/******************************************************************************
  *  文件名     : crypto_rsa1024.c
  *  负责人     : xupeng
  *  创建日期   : 20250225
  *  版本号     : v1.1 
  *  文件描述   : RSA1024加解密接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "logger.h"
#include "crypto_rsa1024.h"
#include "crypto_macro.h"
#include "common_macro.h"

#define RSA1024_PUBKEY_FLIENAME "rsa1024_pub.key"
#define RSA1024_PRIVKEY_FLIENAME "rsa1024_priv.key"
#define RSA1024_ENCRYPT_LEN (128 - RSA_PKCS1_PADDING_SIZE)
#define RSA1024_DECRYPT_LEN (128)

/************************************************************************* 
*  负责人    : xupeng
*  创建日期	 : 20250225
*  函数功能  : RSA密钥生成.
*  输入参数  : key_path - 指定加密的密钥路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int rsa1024_crypto_key_generator(const char *key_path)
{
    int         ret                         = -1;
    RSA         *rsa                        = NULL;
    BIGNUM      *bne                        = NULL;
    FILE        *fp                         = NULL;
    char        pub_key[FULL_FILENAME_LEN]  = {0};
    char        priv_key[FULL_FILENAME_LEN] = {0};

    if (NULL == key_path)
    {
        APP_LOG_ERROR("key_path is NULL");
        return -1;
    }

    rsa = RSA_new();
    bne = BN_new();
    if (NULL == rsa || NULL == bne)
    {
        APP_LOG_ERROR("malloc failed");
        goto CLEAN;
    }

    /* Generate the RSA key pair (1024 bits) */
    if (0 == BN_set_word(bne, RSA_F4) || 0 == RSA_generate_key_ex(rsa, 1024, bne, NULL))
    {
        APP_LOG_ERROR("Failed to generate RSA keys");
        goto CLEAN;
    }

    /* Write public key to file */
    snprintf(priv_key, sizeof(priv_key), "%s"RSA1024_PRIVKEY_FLIENAME, key_path);
    fp = fopen(priv_key, "wb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[file: %s]", priv_key);
        goto CLEAN;
    }

    if (PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL) != 1)
    {
        APP_LOG_ERROR("Failed to write private key to file");
        goto CLEAN;
    }

    fclose(fp);
    fp = NULL;

    /* Write public key to file */
    snprintf(pub_key, sizeof(pub_key), "%s"RSA1024_PUBKEY_FLIENAME, key_path);
    fp = fopen(pub_key, "wb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[file: %s]", pub_key);
        goto CLEAN;
    }

    if (PEM_write_RSA_PUBKEY(fp, rsa) != 1)
    {
        APP_LOG_ERROR("Failed to write public key to file");
        goto CLEAN;
    }

    ret = 0;

CLEAN: 
    FREE_VARIATE_WITH_FUNC(fp, fclose);
    FREE_VARIATE_WITH_FUNC(rsa, RSA_free);
    FREE_VARIATE_WITH_FUNC(bne, BN_free);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250225
*  函数功能  : RSA加密 - 根据指定的MMAP地址，进行文件加密操作.
*  输入参数  : addr - mmap对应的待加密文件地址.
*             datalen - 待加密的文件长度.
*             key_path - 指定加密的密钥路径.
*             encrypt_file - 指定加密的文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int rsa1024_encrypt_specified_mmap_addr(const uint8_t *addr, 
                                       int datalen, 
                                       const char *key_path, 
                                       const char *encrypt_file)
{
    int         ret                         = -1;
    int         ciphertext_len              = 0;
    int         readlen                     = 0;
    FILE        *pubkeyfile                 = NULL;
    FILE        *outfile                    = NULL;
    RSA         *pubkey                     = NULL;
    uint8_t     *ciphertext                 = NULL;
    char        fullpath[FULL_FILENAME_LEN] = {0};

    if (NULL == addr || NULL == key_path || NULL == encrypt_file)
    {
        APP_LOG_ERROR("Parameter is NULL[addr: %p][key_path: %p][encrypt_file: %p]", addr, key_path, encrypt_file);
        return -1;
    }

    snprintf(fullpath, sizeof(fullpath), "%s/"RSA1024_PUBKEY_FLIENAME, key_path);
    pubkeyfile = fopen(fullpath, "rb");
    if (NULL == pubkeyfile)
    {
        APP_LOG_ERROR("Failed to open public key file");
        return -1;
    }

    pubkey = PEM_read_RSA_PUBKEY(pubkeyfile, NULL, NULL, NULL);
    if (NULL == pubkey)
    {
        APP_LOG_ERROR("Failed to read public key from file\n");
        goto CLEAN;
    }

    /* Encrypt data */
    ciphertext = calloc(1, RSA_size(pubkey));
    if (NULL == ciphertext)
    {
        APP_LOG_ERROR("calloc failed");
        goto CLEAN;
    }

    /* Write encrypted data to output file */
    outfile = fopen(encrypt_file, "wb");
    if (NULL == outfile)
    {
        APP_LOG_ERROR("Opening output file");
        goto CLEAN;
    }

    while (readlen + RSA1024_ENCRYPT_LEN < datalen)
    {
        ciphertext_len = RSA_public_encrypt(RSA1024_ENCRYPT_LEN, addr + readlen, ciphertext, pubkey, RSA_PKCS1_PADDING);
        if (-1 == ciphertext_len)
        {
            APP_LOG_ERROR("Encryption failed\n");
            goto CLEAN;
        }

        fwrite(ciphertext, 1, ciphertext_len, outfile);
        readlen += RSA1024_ENCRYPT_LEN;
    }

    ciphertext_len = RSA_public_encrypt(datalen - readlen, addr + readlen, ciphertext, pubkey, RSA_PKCS1_PADDING);
    if (-1 == ciphertext_len)
    {
        APP_LOG_ERROR("Encryption failed\n");
        goto CLEAN;
    }

    fwrite(ciphertext, 1, ciphertext_len, outfile);
    ret = 0;

CLEAN: 
    FREE_VARIATE_WITH_FUNC(ciphertext, free);
    FREE_VARIATE_WITH_FUNC(outfile, fclose);
    FREE_VARIATE_WITH_FUNC(pubkeyfile, fclose);
    FREE_VARIATE_WITH_FUNC(pubkey, RSA_free);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250225
*  函数功能  : RSA解密 - 根据指定的MMAP地址，进行文件解密操作.
*  输入参数  : addr - mmap对应的待解密文件地址.
*             datalen - 待解密的文件长度.
*             key_path - 指定解密的密钥路径.
*             decrypt_file - 指定解密的文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int rsa1024_decrypt_specified_mmap_addr(const uint8_t *addr, 
                                       int datalen, 
                                       const char *key_path, 
                                       const char *decrypt_file)
{
    int         ret                         = -1;
    int         plaintext_len               = 0;
    int         readlen                     = 0;
    FILE        *privkeyfile                = NULL;
    FILE        *outfile                    = NULL;
    RSA         *privkey                    = NULL;
    uint8_t     *plaintext                  = NULL;
    char        fullpath[FULL_FILENAME_LEN] = {0};

    if (NULL == addr || NULL == key_path || NULL == decrypt_file)
    {
        APP_LOG_ERROR("Parameter is NULL[addr: %p][key_path: %p][decrypt_file: %p]", addr, key_path, decrypt_file);
        return -1;
    }

    snprintf(fullpath, sizeof(fullpath), "%s/"RSA1024_PRIVKEY_FLIENAME, key_path);
    privkeyfile = fopen(fullpath, "rb");
    if (NULL == privkeyfile)
    {
        APP_LOG_ERROR("Opening private key file");
        return -1;
    }

    privkey = PEM_read_RSAPrivateKey(privkeyfile, NULL, NULL, NULL);
    if (NULL == privkey)
    {
        APP_LOG_ERROR("Failed to read private key from file");
        goto CLEAN;
    }

    /* Decrypt data */
    plaintext = calloc(1, RSA_size(privkey));
    if (NULL == plaintext)
    {
        APP_LOG_ERROR("calloc failed");
        goto CLEAN;
    }

    /* Write decrypted data to output file */
    outfile = fopen(decrypt_file, "wb");
    if (NULL == outfile)
    {
        APP_LOG_ERROR("Opening output file");
        goto CLEAN;
    }

    while (readlen + RSA1024_DECRYPT_LEN < datalen)
    {
        plaintext_len = RSA_private_decrypt(RSA1024_DECRYPT_LEN, addr + readlen, plaintext, privkey, RSA_PKCS1_PADDING);
        if (-1 == plaintext_len)
        {
            APP_LOG_ERROR("Decryption failed\n");
            goto CLEAN;
        }

        fwrite(plaintext, 1, plaintext_len, outfile);
        readlen += RSA1024_DECRYPT_LEN;
    }

    plaintext_len = RSA_private_decrypt(datalen - readlen, addr + readlen, plaintext, privkey, RSA_PKCS1_PADDING);
    if (-1 == plaintext_len)
    {
        APP_LOG_ERROR("Decryption failed\n");
        goto CLEAN;
    }

    fwrite(plaintext, 1, plaintext_len, outfile);
    ret = 0;

CLEAN: 
    FREE_VARIATE_WITH_FUNC(outfile, fclose);
    FREE_VARIATE_WITH_FUNC(privkeyfile, fclose);
    FREE_VARIATE_WITH_FUNC(plaintext, free);
    FREE_VARIATE_WITH_FUNC(privkey, RSA_free);
    return ret;
}
