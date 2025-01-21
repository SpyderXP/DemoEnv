/******************************************************************************
  *  文件名     : crypto_custom.c
  *  负责人     : xupeng
  *  创建日期   : 20250118
  *  版本号     : v1.1 
  *  文件描述   : 通用文件加密解密模块.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "logger.h"
#include "crypto_custom.h"

#define BUFFER_SIZE             (16 * 1024)             /* 每次处理 16KB 数据 */
#define FILENAME_LEN            256                     /* 文件名最大长度 */
#define PATHNAME_LEN            256                     /* 文件路径最大长度 */
#define FULL_FILENAME_LEN       512                     /* 文件路径 + 文件名 最大长度 */
#define CRYPTO_ALGO_NAMELEN     32                      /* 加密/解密算法名称最大长度 */

/* 加密/解密算法声明 */
#define AES_KEY_LEN             32                      /* AES对称加密密钥长度（256位AES加密） */
#define AES_IV_LEN              16                      /* AES对称加密向量长度 */
int aes256_encrypt_file(const char *infile);
int aes256_decrypt_file(const char *infile);

typedef int (*ENCRYPT_ALGO_FUNC)(const char *infile);
typedef int (*DECRYPT_ALGO_FUNC)(const char *infile);

typedef struct CRYPTO_FUNC_SET_S
{
    char algo_name[CRYPTO_ALGO_NAMELEN];                /* 加密/解密算法名称 */
    ENCRYPT_ALGO_FUNC encrypt;                          /* 加密算法 */
    DECRYPT_ALGO_FUNC decrypt;                          /* 解密算法 */
} CRYPTO_FUNC_SET_T;

char g_origin_path[PATHNAME_LEN]                = {0};  /* 初始文件路径 */
char g_encrypt_path[PATHNAME_LEN]               = {0};  /* 加密文件路径 */
char g_decrypt_path[PATHNAME_LEN]               = {0};  /* 解密文件路径 */
char g_specified_filename[FILENAME_LEN]         = {0};  /* 指定加密/解密的文件名称 */
char g_openssl_key_path[PATHNAME_LEN]           = {0};  /* 密钥文件路径 */
char g_crypto_algo_name[CRYPTO_ALGO_NAMELEN]    = {0};  /* 加密算法名称 */

/* 加密/解密方法集合 */
CRYPTO_FUNC_SET_T g_crypto_func_set[] = 
{
    /* 256位 AES 对称加密/解密 */
    {
        "aes256", 
        aes256_encrypt_file, 
        aes256_decrypt_file
    },
};

/* 命令行参数选项 */
struct option g_long_options[] = 
{
    {"oridir",      required_argument,  NULL, 'o'},
    {"encryptdir",  required_argument,  NULL, 'e'},
    {"decryptdir",  required_argument,  NULL, 'd'},
    {"keydir",      required_argument,  NULL, 'k'},
    {"file",        required_argument,  NULL, 'f'},
    {"algo",        required_argument,  NULL, 'a'},
    {"help",        no_argument,        NULL, 'h'},
};

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 命令行输入帮助信息.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void help_intro(void)
{
    fprintf(stdout, "\n****************************************************************************************\n");
    fprintf(stdout, "Parameter Instruction:\n");
    fprintf(stdout, "\t-a\t--algo\t\tCrypto Algorithm Name[Required arg]\n");
    fprintf(stdout, "\t\t\t\tSupported algorithms:\taes256,\n");
    fprintf(stdout, "\t-o\t--oridir\tOriginal file path[Required arg]\n");
    fprintf(stdout, "\t-e\t--encryptdir\tEncrypted file path[Required arg]\n");
    fprintf(stdout, "\t-d\t--decryptdir\tDecrypted file path[Required arg]\n");
    fprintf(stdout, "\t-k\t--keydir\tOpenssl AES key file path[Required arg]\n");
    fprintf(stdout, "\t-f\t--file\t\tFile to Encrypt/Decrypt[Required arg]\n");
    fprintf(stdout, "\t-h\t--help\t\tHelp Manual[No arg]\n");
    fprintf(stdout, "\nExample:\n");
    fprintf(stdout, "\tEncrypt: ./crypto_tool -a aes256 -o ./origin -e ./encrypt -k ./etc -f hscy.img\n");
    fprintf(stdout, "\tDecrypt: ./crypto_tool -a aes256 -e ./encrypt -d ./decrypt -k ./etc -f hscy.img\n");
    fprintf(stdout, "\tEncrypt && Decrypt: ./crypto_tool -a aes256 -o ./origin -e ./encrypt -d ./decrypt \
-k ./etc -f hscy.img\n");
    fprintf(stdout, "\n****************************************************************************************\n");
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 命令行参数处理.
*  输入参数  : argc - 命令行参数个数.
*             argv - 命令行参数内容.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int crypto_parse_command_line(int argc, char **argv)
{
    int ch = 0;
    int ret = 0;

    if (NULL == argv || 1 == argc)
    {
        APP_LOG_ERROR("Parameter is wrong[argc: %d][argv: %p]\n", argc, argv);
        help_intro();
        return -1;
    }

    while (1) 
    {
        ch = getopt_long_only(argc, argv, "o:e:d:k:f:a:h", g_long_options, NULL);
        if (ch == -1)
        {
            break;
        }

        switch (ch) 
        {
        case 'o':
            snprintf(g_origin_path, sizeof(g_origin_path), "%s", optarg);
            break;

        case 'e':
            snprintf(g_encrypt_path, sizeof(g_encrypt_path), "%s", optarg);
            break;

        case 'd':
            snprintf(g_decrypt_path, sizeof(g_decrypt_path), "%s", optarg);
            break;

        case 'k':
            snprintf(g_openssl_key_path, sizeof(g_openssl_key_path), "%s", optarg);
            break;

        case 'f':
            snprintf(g_specified_filename, sizeof(g_specified_filename), "%s", optarg);
            break;

        case 'a':
            snprintf(g_crypto_algo_name, sizeof(g_crypto_algo_name), "%s", optarg);
            break;

        case 'h':
        default:
            ret = -1;
            break;
        }
    }

    if (ret != 0)
    {
        help_intro();
    }

    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 检查必填参数(文件名/密钥路径/算法名).
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int crypto_check_required_param(void)
{
    if (0 == strcmp(g_specified_filename, "") || 
        0 == strcmp(g_openssl_key_path, "") || 
        0 == strcmp(g_crypto_algo_name, ""))
    {
        APP_LOG_ERROR("-a algo, -f filename and -k keypath are required\n");
        help_intro();
        return -1;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 确认是否为加密请求.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : true - 是  false - 否.
*************************************************************************/
bool is_encryption_request(void)
{
    if (strcmp(g_encrypt_path, "") != 0 && strcmp(g_origin_path, "") != 0)
    {
        return true;
    }

    return false;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 确认是否为解密请求.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : true - 是  false - 否.
*************************************************************************/
bool is_decryption_request(void)
{
    if (strcmp(g_decrypt_path, "") != 0 && strcmp(g_encrypt_path, "") != 0)
    {
        return true;
    }

    return false;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 构造随机的AES加密密钥，并将密钥作为文件保存至指定路径.
*  输入参数  : infile - 指定加密的文件名.
*  输出参数  : key - 256位AES 密钥.
*             iv - AES 向量.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int create_random_openssl_aes256_key(uint8_t *key, uint8_t *iv, const char *infile)
{
    FILE *fp = NULL;
    char path[FULL_FILENAME_LEN] = {0};

    if (NULL == key || NULL == iv || NULL == infile)
    {
        APP_LOG_ERROR("Parameter is NULL[key: %p][iv: %p][infile: %p]\n", key, iv, infile);
        return -1;
    }

    /* 生成随机密钥 */
    if (0 == RAND_bytes(key, AES_KEY_LEN))
    {
        APP_LOG_ERROR("RAND_bytes failed\n");
        return -1;
    }

    if (0 == RAND_bytes(iv, AES_IV_LEN))
    {
        APP_LOG_ERROR("RAND_bytes failed\n");
        return -1;
    }

    snprintf(path, sizeof(path), "%s/%s.aes256.key", g_openssl_key_path, infile);
    fp = fopen(path, "wb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]\n", path);
        return -1;
    }

    fwrite(key, 1, AES_KEY_LEN, fp);
    fwrite(iv, 1, AES_IV_LEN, fp);

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
*  函数功能  : 获取AES加密密钥.
*  输入参数  : infile - 指定加密的文件名.
*  输出参数  : key - 256位AES 密钥.
*             iv - AES 向量.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int get_openssl_aes256_key_info(uint8_t *key, uint8_t *iv, const char *infile)
{
    FILE *fp = NULL;
    char path[FULL_FILENAME_LEN] = {0};

    if (NULL == key || NULL == iv || NULL == infile)
    {
        APP_LOG_ERROR("Parameter is NULL[key: %p][iv: %p][infile: %p]\n", key, iv, infile);
        return -1;
    }

    snprintf(path, sizeof(path), "%s/%s.aes256.key", g_openssl_key_path, infile);
    fp = fopen(path, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]\n", path);
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
*  创建日期	 : 20250117
*  函数功能  : AES加密 - 根据指定的MMAP地址，进行文件加密操作.
*  输入参数  : addr - mmap对应的待加密文件地址.
*             datalen - 待加密的文件长度.
*             infile - 指定加密的文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int aes256_encrypt_specified_mmap_addr(const char *addr, int datalen, const char *infile)
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

    if (NULL == addr || NULL == infile)
    {
        APP_LOG_ERROR("Parameter is NULL[addr: %p][infile: %p]\n", addr, infile);
        return -1;
    }

    /* 生成随机密钥 */
    if (create_random_openssl_aes256_key(key, iv, infile) != 0)
    {
        APP_LOG_ERROR("Failed to create random openssl aes256 key\n");
        return -1;
    }

    APP_MODULE_BYTE_LOG_DEBUG("key", key, sizeof(key));
    APP_MODULE_BYTE_LOG_DEBUG("iv", iv, sizeof(iv));

    /* 创建并初始化上下文 */
    if (NULL == (ctx = EVP_CIPHER_CTX_new())) 
    {
        APP_LOG_ERROR("EVP_CIPHER_CTX_new failed\n");
        goto CLEAN;
    }

    /* 设置为加密模式 */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) 
    {
        APP_LOG_ERROR("EVP_EncryptInit_ex failed\n");
        goto CLEAN;
    }

    /* 打开输入输出文件 */
    snprintf(path, sizeof(path), "%s/%s.tmp", g_encrypt_path, infile);
    fp = fopen(path, "wb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]\n", path);
        goto CLEAN;
    }

    /* 分块读取和加密数据 */
    sup_len = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    plaintext = (uint8_t *)calloc(1, BUFFER_SIZE + BUFFER_SIZE + sup_len);
    if (NULL == plaintext)
    {
        APP_LOG_ERROR("calloc failed\n");
        goto CLEAN;
    }

    ciphertext = plaintext + BUFFER_SIZE;
    while (readlen + BUFFER_SIZE < datalen)
    {
        memcpy(plaintext, addr + readlen, BUFFER_SIZE);
        if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, BUFFER_SIZE) != 1)
        {
            APP_LOG_ERROR("EVP_EncryptUpdate failed\n");
            goto CLEAN;
        }
        fwrite(ciphertext, 1, outlen, fp);
        readlen += BUFFER_SIZE;
    }

    memcpy(plaintext, addr + readlen, datalen - readlen);
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, datalen - readlen) != 1)
    {
        APP_LOG_ERROR("EVP_EncryptUpdate failed\n");
        goto CLEAN;
    }
    fwrite(ciphertext, 1, outlen, fp);

    /* 处理最后剩余的数据 */
    if (EVP_EncryptFinal_ex(ctx, ciphertext, &outlen) != 1)
    {
        APP_LOG_ERROR("EVP_EncryptFinal_ex failed\n");
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
*             infile - 指定解密的文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int aes256_decrypt_specified_mmap_addr(const char *addr, int datalen, const char *infile)
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

    if (NULL == addr || NULL == infile)
    {
        APP_LOG_ERROR("Parameter is NULL[addr: %p][infile: %p]\n", addr, infile);
        return -1;
    }

    if (get_openssl_aes256_key_info(key, iv, infile) != 0)
    {
        APP_LOG_ERROR("Failed to get openssl aes256 key info\n");
        return -1;
    }

    APP_MODULE_BYTE_LOG_DEBUG("key", key, AES_KEY_LEN);
    APP_MODULE_BYTE_LOG_DEBUG("iv", iv, AES_IV_LEN);

    /* 创建并初始化上下文 */
    if (NULL ==(ctx = EVP_CIPHER_CTX_new()))
    {
        APP_LOG_ERROR("EVP_CIPHER_CTX_new failed\n");
        goto CLEAN;
    }

    /* 初始化解密操作 */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        APP_LOG_ERROR("EVP_DecryptInit_ex failed\n");
        goto CLEAN;
    }

    /* 打开输入输出文件 */
    snprintf(path, sizeof(path), "%s/%s.tmp", g_decrypt_path, infile);
    fp = fopen(path, "wb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]\n", path);
        goto CLEAN;
    }

    /* 分块读取和解密数据 */
    sup_len = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    plaintext = (uint8_t *)calloc(1, BUFFER_SIZE + sup_len + BUFFER_SIZE);
    if (NULL == plaintext)
    {
        APP_LOG_ERROR("calloc failed\n");
        goto CLEAN;
    }

    ciphertext = plaintext + BUFFER_SIZE + sup_len;
    while (readlen + BUFFER_SIZE < datalen)
    {
        memcpy(ciphertext, addr + readlen, BUFFER_SIZE);

        if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, BUFFER_SIZE) != 1)
        {
            APP_LOG_ERROR("EVP_DecryptUpdate failed\n");
            goto CLEAN;
        }

        fwrite(plaintext, 1, outlen, fp);
        readlen += BUFFER_SIZE;
    }

    memcpy(ciphertext, addr + readlen, datalen - readlen);
    if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, datalen - readlen) != 1)
    {
        APP_LOG_ERROR("EVP_DecryptUpdate failed\n");
        goto CLEAN;
    }
    fwrite(plaintext, 1, outlen, fp);

    /* 完成解密操作 */
    if (EVP_DecryptFinal_ex(ctx, plaintext, &outlen) != 1)
    {
        APP_LOG_ERROR("EVP_DecryptFinal_ex failed\n");
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

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : AES文件加密.
*  输入参数  : infile - 待加密的文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int aes256_encrypt_file(const char *infile)
{
    int         fd                          = -1;
    int         ret                         = 0;
    int         extra_size                  = 0;
    char        *addr                       = NULL;
    struct stat sb                          = {0};
    char        path[FULL_FILENAME_LEN]     = {0};
    char        new_file[FULL_FILENAME_LEN] = {0};

    if (NULL == infile)
    {
        APP_LOG_ERROR("Parameter is NULL[infile: %p]\n", infile);
        return -1;
    }

    /* 打开文件，读写方式 */
    snprintf(path, sizeof(path), "%s/%s", g_origin_path, infile);
    fd = open(path, O_RDONLY, (mode_t)0400);
    if (-1 == fd) 
    {
        APP_LOG_ERROR("Error opening file for writing[%s]\n", path);
        return -1;
    }

    /* 获取文件状态 */
    if (-1 == fstat(fd, &sb)) 
    {
        APP_LOG_ERROR("Error getting the file size[%s]\n", path);
        close(fd);
        return -1;
    }

    /* 防止源文件长度导致mmap对齐问题 */
    if (sb.st_size % 16 != 0)
    {
        extra_size = 16 - (sb.st_size % 16);
    }

    /* 映射文件 */
    addr = mmap(NULL, sb.st_size + extra_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == addr) 
    {
        close(fd);
        APP_LOG_ERROR("Error on mmap[%s]\n", path);
        return -1;
    }

    close(fd);

    ret = aes256_encrypt_specified_mmap_addr(addr, sb.st_size, infile);

    /* 解除映射 */
    if (-1 == munmap(addr, sb.st_size + extra_size)) 
    {
        APP_LOG_ERROR("Error un-mmapping the file[%s]\n", path);
        return -1;
    }

    /* 将临时文件重命名 */
    if (0 == ret)
    {
        snprintf(path, sizeof(path), "%s/%s.tmp", g_encrypt_path, infile);
        snprintf(new_file, sizeof(new_file), "%s/%s", g_encrypt_path, infile);
        rename(path, new_file);
    }

    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : AES文件解密.
*  输入参数  : infile - 待解密的文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int aes256_decrypt_file(const char *infile)
{
    int         fd                          = -1;
    int         ret                         = 0;
    char        *addr                       = NULL;
    struct stat sb                          = {0};
    char        path[FULL_FILENAME_LEN]     = {0};
    char        new_file[FULL_FILENAME_LEN] = {0};

    if (NULL == infile)
    {
        APP_LOG_ERROR("Parameter is NULL[infile: %p]\n", infile);
        return -1;
    }

    /* 打开文件，读写方式 */
    snprintf(path, sizeof(path), "%s/%s", g_encrypt_path, infile);
    fd = open(path, O_RDONLY, (mode_t)0400);
    if (-1 == fd) 
    {
        APP_LOG_ERROR("Error opening file for writing[%s]\n", path);
        return -1;
    }

    /* 获取文件状态 */
    if (-1 == fstat(fd, &sb)) 
    {
        APP_LOG_ERROR("Error getting the file size[%s]\n", path);
        close(fd);
        return -1;
    }

    /* 映射文件 */
    addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == addr) 
    {
        close(fd);
        APP_LOG_ERROR("Error on mmap[%s]\n", path);
        return -1;
    }

    close(fd);

    ret = aes256_decrypt_specified_mmap_addr(addr, sb.st_size, infile);

    /* 解除映射 */
    if (-1 == munmap(addr, sb.st_size)) 
    {
        APP_LOG_ERROR("Error un-mmapping the file[%s]\n", path);
        return -1;
    }

    /* 将临时文件重命名 */
    if (0 == ret)
    {
        snprintf(path, sizeof(path), "%s/%s.tmp", g_decrypt_path, infile);
        snprintf(new_file, sizeof(new_file), "%s/%s", g_decrypt_path, infile);
        rename(path, new_file);
    }

    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 文件加密/解密入口(仅在作为独立的加密/解密程序时调用).
*  输入参数  : argc - 命令行参数个数.
*             argv - 命令行参数内容.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void crypto_main(int argc, char **argv)
{
    if (crypto_parse_command_line(argc, argv) != 0)
    {
        return ;
    }

    if (crypto_check_required_param() != 0)
    {
        return ;
    }

    for (int i = 0; i < sizeof(g_crypto_func_set) / sizeof(CRYPTO_FUNC_SET_T); i++)
    {
        if (0 == strcmp(g_crypto_algo_name, g_crypto_func_set[i].algo_name))
        {
            if (is_encryption_request() && g_crypto_func_set[i].encrypt != NULL)
            {
                APP_LOG_DEBUG("Encryption start\n");
                if (g_crypto_func_set[i].encrypt(g_specified_filename) != 0)
                {
                    APP_LOG_ERROR("Encryption failed\n");
                }
                APP_LOG_DEBUG("Encryption over\n");
            }

            if (is_decryption_request() && g_crypto_func_set[i].decrypt != NULL)
            {
                APP_LOG_DEBUG("Decryption start\n");
                if (g_crypto_func_set[i].decrypt(g_specified_filename))
                {
                    APP_LOG_ERROR("Decryption failed\n");
                }
                APP_LOG_DEBUG("Decryption over\n");
            }

            break;
        }
    }

    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 文件加密接口.
*  输入参数  : filename - 待加密文件名.
*             algo - 加密算法名称字符串.
*             key_path - 密钥生成目录.
*             origin_path - 待加密文件路径.
*             encrypt_path - 指定的加密文件生成路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : 目前支持的加密算法 aes256.
*************************************************************************/
int crypto_encrypt_file(const char *filename, 
                        const char *algo, 
                        const char *key_path, 
                        const char *origin_path, 
                        const char *encrypt_path)
{
    if (NULL == filename || NULL == algo || NULL == key_path || NULL == origin_path || NULL == encrypt_path)
    {
        APP_LOG_ERROR("Parameter is NULL[filename: %p][algo: %p][key_path: %p][origin_path: %p][encrypt_path: %p]\n", 
                        filename, algo, key_path, origin_path, encrypt_path);
        return -1;
    }

    /* 参数传递 */
    snprintf(g_specified_filename, sizeof(g_specified_filename), "%s", filename);
    snprintf(g_crypto_algo_name, sizeof(g_crypto_algo_name), "%s", algo);
    snprintf(g_openssl_key_path, sizeof(g_openssl_key_path), "%s", key_path);
    snprintf(g_origin_path, sizeof(g_origin_path), "%s", origin_path);
    snprintf(g_encrypt_path, sizeof(g_encrypt_path), "%s", encrypt_path);

    /* 必要参数检验 */
    if (crypto_check_required_param() != 0)
    {
        return -1;
    }

    /* 调用适配算法 */
    for (int i = 0; i < sizeof(g_crypto_func_set) / sizeof(CRYPTO_FUNC_SET_T); i++)
    {
        if (0 == strcmp(g_crypto_algo_name, g_crypto_func_set[i].algo_name) && 
            is_encryption_request() && 
            g_crypto_func_set[i].encrypt != NULL)
        {
            APP_LOG_DEBUG("Encryption start\n");
            if (g_crypto_func_set[i].encrypt(g_specified_filename) != 0)
            {
                APP_LOG_ERROR("Encryption failed\n");
            }
            APP_LOG_DEBUG("Encryption over\n");
            break;
        }
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 文件解密接口.
*  输入参数  : filename - 待解密文件名.
*             algo - 解密算法名称字符串.
*             key_path - 密钥存放目录.
*             encrypt_path - 待解密文件路径.
*             decrypt_path - 指定的解密文件生成路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : 目前支持的解密算法 aes256.
*************************************************************************/
int crypto_decrypt_file(const char *filename, 
                        const char *algo, 
                        const char *key_path, 
                        const char *encrypt_path, 
                        const char *decrypt_path)
{
    if (NULL == filename || NULL == algo || NULL == key_path || NULL == encrypt_path || NULL == decrypt_path)
    {
        APP_LOG_ERROR("Parameter is NULL[filename: %p][algo: %p][key_path: %p][encrypt_path: %p][decrypt_path: %p]\n", 
                        filename, algo, key_path, encrypt_path, decrypt_path);
        return -1;
    }

    /* 参数传递 */
    snprintf(g_specified_filename, sizeof(g_specified_filename), "%s", filename);
    snprintf(g_crypto_algo_name, sizeof(g_crypto_algo_name), "%s", algo);
    snprintf(g_openssl_key_path, sizeof(g_openssl_key_path), "%s", key_path);
    snprintf(g_encrypt_path, sizeof(g_encrypt_path), "%s", encrypt_path);
    snprintf(g_decrypt_path, sizeof(g_decrypt_path), "%s", decrypt_path);

    /* 必要参数检验 */
    if (crypto_check_required_param() != 0)
    {
        return -1;
    }

    /* 调用适配算法 */
    for (int i = 0; i < sizeof(g_crypto_func_set) / sizeof(CRYPTO_FUNC_SET_T); i++)
    {
        if (0 == strcmp(g_crypto_algo_name, g_crypto_func_set[i].algo_name) && 
            is_decryption_request() && 
            g_crypto_func_set[i].decrypt != NULL)
        {
            APP_LOG_DEBUG("Decryption start\n");
            if (g_crypto_func_set[i].decrypt(g_specified_filename) != 0)
            {
                APP_LOG_ERROR("Decryption failed\n");
            }
            APP_LOG_DEBUG("Decryption over\n");
            break;
        }
    }

    return 0;
}
