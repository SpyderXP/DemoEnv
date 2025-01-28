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
#include "crypto_macro.h"
#include "crypto_aes256.h"
#include "common_macro.h"

typedef int (*ENCRYPT_ALGO_FUNC)(const char *addr, 
                                 int datalen, 
                                 const char *key_fullpath, 
                                 const char *encrypt_path, 
                                 const char *filename);

typedef int (*DECRYPT_ALGO_FUNC)(const char *addr, 
                                 int datalen, 
                                 const char *key_fullpath, 
                                 const char *decrypt_path, 
                                 const char *filename);

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
char g_crypto_key_fullpath[FULL_FILENAME_LEN]   = {0};  /* 密钥文件路径(包含文件名) */
char g_crypto_algo_name[CRYPTO_ALGO_NAMELEN]    = {0};  /* 加密算法名称 */

#define HELP_INFO_STR_SIZE 2048
char g_help_info_str[HELP_INFO_STR_SIZE]        = {0};  /* 帮助信息字符串 */

/* 加密/解密方法集合 */
CRYPTO_FUNC_SET_T g_crypto_func_set[] = 
{
    /* 256位 AES 对称加密/解密 */
    {
        "aes256", 
        aes256_encrypt_specified_mmap_addr, 
        aes256_decrypt_specified_mmap_addr
    },
};

/* 命令行参数选项 */
struct option g_long_options[] = 
{
    {"oridir",      required_argument,  NULL, 'o'},
    {"encryptdir",  required_argument,  NULL, 'e'},
    {"decryptdir",  required_argument,  NULL, 'd'},
    {"key",         required_argument,  NULL, 'k'},
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
    snprintf(g_help_info_str, sizeof(g_help_info_str), 
        "\n****************************************************************************************\n"
        "Parameter Instruction:\n"
        "\t-a\t--algo\t\tCrypto Algorithm Name[Required arg]\n"
        "\t\t\t\tSupported algorithms:\taes256,\n"
        "\t-o\t--oridir\tOriginal file path[Required arg]\n"
        "\t-e\t--encryptdir\tEncrypted file path[Required arg]\n"
        "\t-d\t--decryptdir\tDecrypted file path[Required arg]\n"
        "\t-k\t--key\t\tEncryption/Decryption key file[Required arg]\n"
        "\t-f\t--file\t\tFile to Encrypt/Decrypt[Required arg]\n"
        "\t-h\t--help\t\tHelp Manual[No arg]\n"
        "\nExample:\n"
        "\tEncrypt: ./crypto_tool -a aes256 -o ./origin -e ./encrypt -k ./etc/hscy.img.aes256.key -f hscy.img\n"
        "\tDecrypt: ./crypto_tool -a aes256 -e ./encrypt -d ./decrypt -k ./etc/hscy.img.aes256.key -f hscy.img\n"
        "\n****************************************************************************************\n"
    );
    APP_LOG_INFO("%s", g_help_info_str);
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
        APP_LOG_ERROR("Parameter is wrong[argc: %d][argv: %p]", argc, argv);
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
            snprintf(g_crypto_key_fullpath, sizeof(g_crypto_key_fullpath), "%s", optarg);
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
*  函数功能  : 检查必填加密参数(文件名/算法名).
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int crypto_check_required_encryption_param(void)
{
    if (0 == strcmp(g_specified_filename, "") || 
        0 == strcmp(g_crypto_algo_name, ""))
    {
        APP_LOG_ERROR("-a algo, -f filename are required to encrypt file");
        help_intro();
        return -1;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 检查必填解密参数(文件名/密钥路径/算法名).
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int crypto_check_required_decryption_param(void)
{
    if (0 == strcmp(g_specified_filename, "") || 
        0 == strcmp(g_crypto_key_fullpath, "") || 
        0 == strcmp(g_crypto_algo_name, ""))
    {
        APP_LOG_ERROR("-a algo, -f filename and -k key are required to decrypt file");
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
*  函数功能  : 通用文件加密处理.
*  输入参数  : algo - 加密算法名称.
*             origin_path - 待加密文件路径.
*             encrypt_path - 指定的加密文件生成路径.
*             filename - 待加密的文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int general_file_encrypt_process(const char *algo, 
                                 const char *key_fullpath, 
                                 const char *origin_path, 
                                 const char *encrypt_path, 
                                 const char *filename)
{
    int         fd                          = -1;
    int         ret                         = 0;
    char        *addr                       = NULL;
    struct stat sb                          = {0};
    char        path[FULL_FILENAME_LEN]     = {0};
    char        new_file[FULL_FILENAME_LEN] = {0};

    if (NULL == algo || NULL == key_fullpath || NULL == origin_path || NULL == encrypt_path || NULL == filename)
    {
        APP_LOG_ERROR("Parameter is NULL[algo: %p][key_fullpath: %p][origin_path: %p][encrypt_path: %p][filename: %p]", 
            algo, key_fullpath, origin_path, encrypt_path, filename);
        return -1;
    }

    /* 打开文件，读写方式 */
    snprintf(path, sizeof(path), "%s/%s", origin_path, filename);
    fd = open(path, O_RDONLY, (mode_t)0400);
    if (-1 == fd) 
    {
        APP_LOG_ERROR("Error opening file for writing[%s]", path);
        return -1;
    }

    /* 获取文件状态 */
    if (-1 == fstat(fd, &sb)) 
    {
        APP_LOG_ERROR("Error getting the file size[%s]", path);
        close(fd);
        return -1;
    }

    /* 映射文件 */
    addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == addr) 
    {
        APP_LOG_ERROR("Error on mmap[%s]", path);
        close(fd);
        return -1;
    }

    close(fd);

    for (int i = 0; i < sizeof(g_crypto_func_set) / sizeof(CRYPTO_FUNC_SET_T); i++)
    {
        if (0 == strcmp(algo, g_crypto_func_set[i].algo_name))
        {
            if (g_crypto_func_set[i].encrypt != NULL)
            {
                ret = g_crypto_func_set[i].encrypt(addr, sb.st_size, key_fullpath, encrypt_path, filename);
            }
            break;
        }
    }

    /* 解除映射 */
    if (-1 == munmap(addr, sb.st_size)) 
    {
        APP_LOG_ERROR("Error un-mmapping the file[%s]", path);
        return -1;
    }

    /* 将临时文件重命名 */
    if (0 == ret)
    {
        snprintf(path, sizeof(path), "%s/%s.tmp", encrypt_path, filename);
        snprintf(new_file, sizeof(new_file), "%s/%s", encrypt_path, filename);
        rename(path, new_file);
    }

    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 通用文件解密处理.
*  输入参数  : algo - 解密算法名称.
*             key_fullpath - 密钥文件.
*             encrypt_path - 待解密文件路径.
*             decrypt_path - 指定的解密文件生成路径.
*             filename - 待解密的文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int general_file_decrypt_process(const char *algo, 
                                 const char *key_fullpath, 
                                 const char *encrypt_path, 
                                 const char *decrypt_path, 
                                 const char *filename)
{
    int         fd                          = -1;
    int         ret                         = 0;
    char        *addr                       = NULL;
    struct stat sb                          = {0};
    char        path[FULL_FILENAME_LEN]     = {0};
    char        new_file[FULL_FILENAME_LEN] = {0};

    if (NULL == algo || NULL == key_fullpath || NULL == encrypt_path || NULL == decrypt_path || NULL == filename)
    {
        APP_LOG_ERROR("Parameter is NULL[algo: %p][key_fullpath: %p][encrypt_path: %p][decrypt_path: %p][filename: %p]", 
            algo, key_fullpath, encrypt_path, decrypt_path, filename);
        return -1;
    }

    /* 打开文件，读写方式 */
    snprintf(path, sizeof(path), "%s/%s", encrypt_path, filename);
    fd = open(path, O_RDONLY, (mode_t)0400);
    if (-1 == fd) 
    {
        APP_LOG_ERROR("Error opening file for writing[%s]", path);
        return -1;
    }

    /* 获取文件状态 */
    if (-1 == fstat(fd, &sb)) 
    {
        APP_LOG_ERROR("Error getting the file size[%s]", path);
        close(fd);
        return -1;
    }

    /* 映射文件 */
    addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == addr) 
    {
        APP_LOG_ERROR("Error on mmap[%s]", path);
        close(fd);
        return -1;
    }

    close(fd);

    for (int i = 0; i < sizeof(g_crypto_func_set) / sizeof(CRYPTO_FUNC_SET_T); i++)
    {
        if (0 == strcmp(algo, g_crypto_func_set[i].algo_name))
        {
            if (g_crypto_func_set[i].decrypt != NULL)
            {
                ret = g_crypto_func_set[i].decrypt(addr, sb.st_size, key_fullpath, decrypt_path, filename);
            }
            break;
        }
    }

    /* 解除映射 */
    if (-1 == munmap(addr, sb.st_size)) 
    {
        APP_LOG_ERROR("Error un-mmapping the file[%s]", path);
        return -1;
    }

    /* 将临时文件重命名 */
    if (0 == ret)
    {
        snprintf(path, sizeof(path), "%s/%s.tmp", decrypt_path, filename);
        snprintf(new_file, sizeof(new_file), "%s/%s", decrypt_path, filename);
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

    if (is_encryption_request() && 0 == crypto_check_required_encryption_param())
    {
        APP_LOG_DEBUG("Encryption start");
        if (general_file_encrypt_process(g_crypto_algo_name, 
                                         g_crypto_key_fullpath, 
                                         g_origin_path, 
                                         g_encrypt_path, 
                                         g_specified_filename) != 0)
        {
            APP_LOG_ERROR("Encryption failed");
        }
        APP_LOG_DEBUG("Encryption over");
    }

    if (is_decryption_request() && 0 == crypto_check_required_decryption_param())
    {
        APP_LOG_DEBUG("Decryption start");
        if (general_file_decrypt_process(g_crypto_algo_name, 
                                         g_crypto_key_fullpath, 
                                         g_encrypt_path, 
                                         g_decrypt_path, 
                                         g_specified_filename) != 0)
        {
            APP_LOG_ERROR("Decryption failed");
        }
        APP_LOG_DEBUG("Decryption over");
    }

    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 文件加密接口.
*  输入参数  : filename - 待加密文件名.
*             algo - 加密算法名称字符串.
*             key_path - 密钥目录(填空字符串则生成随机密钥至加密目录).
*             origin_path - 待加密文件路径.
*             encrypt_path - 指定的加密文件生成路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : 目前支持的加密算法(algo参数) aes256.
*************************************************************************/
int crypto_encrypt_file(const char *filename, 
                        const char *algo, 
                        const char *key_file, 
                        const char *origin_path, 
                        const char *encrypt_path)
{
    if (NULL == filename || NULL == algo || NULL == key_file || NULL == origin_path || NULL == encrypt_path)
    {
        APP_LOG_ERROR("Parameter is NULL[filename: %p][algo: %p][key_file: %p][origin_path: %p][encrypt_path: %p]", 
                        filename, algo, key_file, origin_path, encrypt_path);
        return -1;
    }

    /* 参数传递 */
    snprintf(g_specified_filename, sizeof(g_specified_filename), "%s", filename);
    snprintf(g_crypto_algo_name, sizeof(g_crypto_algo_name), "%s", algo);
    snprintf(g_crypto_key_fullpath, sizeof(g_crypto_key_fullpath), "%s", key_file);
    snprintf(g_origin_path, sizeof(g_origin_path), "%s", origin_path);
    snprintf(g_encrypt_path, sizeof(g_encrypt_path), "%s", encrypt_path);

    /* 必要参数检验 */
    if (!is_encryption_request() || crypto_check_required_encryption_param() != 0)
    {
        return -1;
    }

    APP_LOG_DEBUG("Encryption start");
    if (general_file_encrypt_process(g_crypto_algo_name, 
                                     g_crypto_key_fullpath,
                                     g_origin_path, 
                                     g_encrypt_path, 
                                     g_specified_filename) != 0)
    {
        APP_LOG_ERROR("Encryption failed");
    }
    APP_LOG_DEBUG("Encryption over");

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 文件解密接口.
*  输入参数  : filename - 待解密文件名.
*             algo - 解密算法名称字符串.
*             key_file - 密钥存放目录(包含文件名).
*             encrypt_path - 待解密文件路径.
*             decrypt_path - 指定的解密文件生成路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : 目前支持的解密算法(algo参数) aes256.
*************************************************************************/
int crypto_decrypt_file(const char *filename, 
                        const char *algo, 
                        const char *key_file, 
                        const char *encrypt_path, 
                        const char *decrypt_path)
{
    if (NULL == filename || NULL == algo || NULL == key_file || NULL == encrypt_path || NULL == decrypt_path)
    {
        APP_LOG_ERROR("Parameter is NULL[filename: %p][algo: %p][key_file: %p][encrypt_path: %p][decrypt_path: %p]", 
                        filename, algo, key_file, encrypt_path, decrypt_path);
        return -1;
    }

    /* 参数传递 */
    snprintf(g_specified_filename, sizeof(g_specified_filename), "%s", filename);
    snprintf(g_crypto_algo_name, sizeof(g_crypto_algo_name), "%s", algo);
    snprintf(g_crypto_key_fullpath, sizeof(g_crypto_key_fullpath), "%s", key_file);
    snprintf(g_encrypt_path, sizeof(g_encrypt_path), "%s", encrypt_path);
    snprintf(g_decrypt_path, sizeof(g_decrypt_path), "%s", decrypt_path);

    /* 必要参数检验 */
    if (!is_decryption_request() || crypto_check_required_decryption_param() != 0)
    {
        return -1;
    }

    APP_LOG_DEBUG("Decryption start");
    if (general_file_decrypt_process(g_crypto_algo_name, 
                                     g_crypto_key_fullpath, 
                                     g_encrypt_path, 
                                     g_decrypt_path, 
                                     g_specified_filename) != 0)
    {
        APP_LOG_ERROR("Decryption failed");
    }
    APP_LOG_DEBUG("Decryption over");

    return 0;
}
