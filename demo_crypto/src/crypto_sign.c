/******************************************************************************
  *  文件名     : crypto_sign.c
  *  负责人     : xupeng
  *  创建日期   : 20250305
  *  版本号     : v1.1 
  *  文件描述   : 数字签名接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#include <getopt.h>
#include <stdbool.h>
#include <openssl/cms.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "common_macro.h"
#include "crypto_sign.h"
#include "logger.h"
#include "crypto_macro.h"

#define HELP_INFO_STR_SIZE 2048

typedef int (*SIGN_GENERATE_FUNC)(const char *key_file, 
                                  const char *data_file, 
                                  const char *cert_file, 
                                  const char *signed_file);

typedef int (*SIGN_VERIFY_FUNC)(const char *cert_file, 
                                const char *data_file, 
                                const char *signed_file);

typedef struct SIGN_FUNC_SET_S
{
    char algo_name[CRYPTO_ALGO_NAMELEN];                /* 签名算法名称 */
    SIGN_GENERATE_FUNC generate;                        /* 生成签名 */
    SIGN_VERIFY_FUNC verify;                            /* 验证签名 */
} SIGN_FUNC_SET_T;

char g_sign_algo_name[CRYPTO_ALGO_NAMELEN]      = {0};  /* 签名算法名称 */
char g_key_file_name[FULL_FILENAME_LEN]         = {0};  /* 私钥文件 */
char g_data_file_name[FULL_FILENAME_LEN]        = {0};  /* 数据文件 */
char g_cert_file_name[FULL_FILENAME_LEN]        = {0};  /* 证书文件 */
char g_signed_file_name[FULL_FILENAME_LEN]      = {0};  /* 签名文件 */
char g_priv_key_passwd[CRYPTO_PASSWD_SIZE]      = {0};  /* 私钥密码 */
char g_sign_tool_help_info[HELP_INFO_STR_SIZE]  = {0};  /* 帮助信息字符串 */

/* 加密/解密方法集合 */
SIGN_FUNC_SET_T g_sign_func_set[] = 
{
    /* RSA 普通数字签名 */
    {
        "rsa", 
        generate_rsa_signature, 
        verify_rsa_signature
    }, 

    /* CMS */
    {
        "cms", 
        generate_cms_signature, 
        verify_cms_signature
    }, 

    /* PKCS #7 */
    {
        "pkcs7", 
        generate_pkcs7_signature, 
        verify_pkcs7_signature
    }
};

/* 命令行参数选项 */
struct option g_sign_tool_options[] = 
{
    {"algo",        required_argument,  NULL, 'a'},
    {"cert",        required_argument,  NULL, 'c'},
    {"key",         required_argument,  NULL, 'k'},
    {"data",        required_argument,  NULL, 'd'},
    {"sign",        required_argument,  NULL, 's'},
    {"passwd",      required_argument,  NULL, 'p'},
    {"help",        no_argument,        NULL, 'h'},
    {NULL,          0,                  0,      0},
};

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 命令行输入帮助信息.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void sign_tool_help_intro(void)
{
    snprintf(g_sign_tool_help_info, sizeof(g_sign_tool_help_info), 
        "\n****************************************************************************************\n"
        "Parameter Instruction:\n"
        "\t-a\t--algo\tSignature Algorithm Name[Required arg]\n"
        "\t\t\t\tSupported algorithms: rsa, cms, pkcs7\n"
        "\t-c\t--cert\tCertificate file[Required arg]\n"
        "\t-k\t--key\tPrivate key file[Required arg]\n"
        "\t-p\t--passwd\tPrivate key password[Required arg]\n"
        "\t-d\t--data\tData file[Required arg]\n"
        "\t-s\t--sign\tSignature file[Required arg]\n"
        "\t-h\t--help\tHelp Manual[No arg]\n"
        "\nExample:\n"
        "\tGenerate: ./sign_tool -a cms -c ./certificate.pem -k ./private.key -p 1234 -d ./hscy.img -s ./signature.pem\n"
        "\tVerify: ./sign_tool -a cms -c ./certificate.pem -d ./hscy.img -s ./signature.pem"
        "\n****************************************************************************************\n"
    );
    APP_LOG_INFO("%s", g_sign_tool_help_info);
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
int sign_parse_command_line(int argc, char **argv)
{
    int ch = 0;
    int ret = 0;

    if (NULL == argv || 1 == argc)
    {
        APP_LOG_ERROR("Parameter is wrong[argc: %d][argv: %p]", argc, argv);
        sign_tool_help_intro();
        return -1;
    }

    while (1) 
    {
        ch = getopt_long_only(argc, argv, "a:c:k:d:s:p:h", g_sign_tool_options, NULL);
        if (ch == -1)
        {
            break;
        }

        switch (ch) 
        {
        case 'a':
            snprintf(g_sign_algo_name, sizeof(g_sign_algo_name), "%s", optarg);
            break;

        case 'c':
            snprintf(g_cert_file_name, sizeof(g_cert_file_name), "%s", optarg);
            break;

        case 'k':
            snprintf(g_key_file_name, sizeof(g_key_file_name), "%s", optarg);
            break;

        case 'd':
            snprintf(g_data_file_name, sizeof(g_data_file_name), "%s", optarg);
            break;

        case 's':
            snprintf(g_signed_file_name, sizeof(g_signed_file_name), "%s", optarg);
            break;

        case 'p':
            snprintf(g_priv_key_passwd, sizeof(g_priv_key_passwd), "%s", optarg);
            break;

        case 'h':
        default:
            ret = -1;
            break;
        }
    }

    if (ret != 0)
    {
        sign_tool_help_intro();
    }

    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250306
*  函数功能  : 私钥密码回调.
*  输入参数  : size - 密码字符串最大长度.
*             rwflag - 暂未使用.
*             data - 暂未使用.
*  输出参数  : buf - 密码字符串.
*  返回值    : 密码字符串长度.
*  其他     : 无.
*************************************************************************/
int password_callback(char *buf, int size, int rwflag, void *data)
{
    if (0 == strcmp("", g_priv_key_passwd))
    {
        return 0;
    }

    snprintf(buf, size, "%s", g_priv_key_passwd);
    return strlen(g_priv_key_passwd);
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 生成数字签名文件(RSA普通签名算法).
*  输入参数  : key_file - 私钥文件.
*             data_file - 数据文件.
*             cert_file - 证书文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : 普通签名算法只包含签名值和签名算法，不包含证书及证书链等信息.
*************************************************************************/
int generate_rsa_signature(const char* key_file, const char* data_file, const char *cert_file, const char* signed_file)
{
    int ret = -1;
    FILE *fp = NULL;
    RSA *rsa = NULL;
    EVP_MD_CTX *ctx = NULL;
    uint8_t *data = NULL;
    long read_size = 0;
    long data_size = 0;
    uint8_t *hash = NULL;
    uint32_t hash_len = 0;
    uint8_t *sign = NULL;
    uint32_t sign_len = 0;

    if (NULL == key_file || NULL == data_file || NULL == signed_file)
    {
        APP_LOG_ERROR("Parameter is NULL[ ]");
        return -1;
    }

    /* 加载私钥 */
    fp = fopen(key_file, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[file: %s]", key_file);
        goto CLEAN;
    }

    rsa = PEM_read_RSAPrivateKey(fp, NULL, password_callback, NULL);
    if (NULL == rsa)
    {
        APP_LOG_ERROR("Failed to get rsa[file: %s]", key_file);
        goto CLEAN;
    }

    fclose(fp);
    fp = NULL;

    /* 读取原始数据 */
    fp = fopen(data_file, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[file: %s]", data_file);
        goto CLEAN;
    }

    fseek(fp, 0, SEEK_END);
    data_size = ftell(fp);
    rewind(fp);

    /* data segment + hash + sign */
    data = (uint8_t *)calloc(1, 256 + EVP_MAX_MD_SIZE + RSA_size(rsa));
    if (NULL == data)
    {
        APP_LOG_ERROR("calloc failed");
        goto CLEAN;
    }

    ctx = EVP_MD_CTX_create();
    if (NULL == ctx)
    {
        APP_LOG_ERROR("EVP_MD_CTX_create failed");
        goto CLEAN;
    }

    if (EVP_DigestInit(ctx, EVP_sha256()) != 1)
    {
        APP_LOG_ERROR("EVP_DigestInit with EVP_sha256 failed");
        goto CLEAN;
    }

    while (read_size + 256 < data_size)
    {
        fread(data, 256, 1, fp);
        if (EVP_DigestUpdate(ctx, data, 256) != 1)
        {
            APP_LOG_ERROR("EVP_DigestUpdate failed");
            goto CLEAN;
        }
        read_size += 256;
    }

    fread(data, data_size - read_size, 1, fp);
    if (EVP_DigestUpdate(ctx, data, data_size - read_size) != 1)
    {
        APP_LOG_ERROR("EVP_DigestUpdate failed");
        goto CLEAN;
    }

    fclose(fp);
    fp = NULL;

    /* 计算哈希 */
    hash = data + 256;
    if (EVP_DigestFinal(ctx, hash, &hash_len) != 1)
    {
        APP_LOG_ERROR("EVP_DigestFinal failed");
        goto CLEAN;
    }

    /* 签名哈希 */
    sign = data + 256 + EVP_MAX_MD_SIZE;
    RSA_sign(NID_sha256, hash, hash_len, sign, &sign_len, rsa);

    /* 保存签名 */
    fp = fopen(signed_file, "wb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[file: %s]", signed_file);
        goto CLEAN;
    }

    fwrite(sign, 1, sign_len, fp);
    ret = 0;

CLEAN: 
    FREE_VARIATE_WITH_FUNC(fp, fclose);
    FREE_VARIATE_WITH_FUNC(rsa, RSA_free);
    FREE_VARIATE_WITH_FUNC(ctx, EVP_MD_CTX_destroy);
    FREE_VARIATE_WITH_FUNC(data, free);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 验证数字签名文件(RSA普通签名算法).
*  输入参数  : cert_file - 证书文件(公钥).
*             data_file - 数据文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : 普通签名算法只包含签名值和签名算法，不包含证书及证书链等信息.
*************************************************************************/
int verify_rsa_signature(const char *cert_file, const char *data_file, const char *signed_file)
{
    FILE *fp = NULL;
    X509 *cert = NULL;
    int ret = -1;
    long sign_size = 0;
    uint8_t *sign = NULL;
    long read_size = 0;
    long data_size = 0;
    uint8_t *data = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_MD_CTX *ctx = NULL;

    if (NULL == cert_file || NULL == signed_file || NULL == data_file)
    {
        APP_LOG_ERROR("Parameter is NULL[cert_file: %p][signed_file: %p][data_file: %p]", cert_file, signed_file, data_file);
        return  -1;
    }

    fp = fopen(cert_file, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[file: %s]", cert_file);
        goto CLEAN;
    }

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (NULL == cert)
    {
        APP_LOG_ERROR("PEM_read_X509 failed[file: %s]", cert_file);
        goto CLEAN;
    }

    fclose(fp);
    fp = NULL;

    /* 读取签名数据 */
    fp = fopen(signed_file, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[file: %s]", signed_file);
        goto CLEAN;
    }

    fseek(fp, 0, SEEK_END);
    sign_size = ftell(fp);
    rewind(fp);

    sign = (uint8_t *)calloc(1, sign_size);
    if (NULL == sign)
    {
        APP_LOG_ERROR("calloc failed");
        goto CLEAN;
    }
    fread(sign, 1, sign_size, fp);
    fclose(fp);
    fp = NULL;

    /* 读取原始数据 */
    fp = fopen(data_file, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[file: %s]", data_file);
        goto CLEAN;
    }

    fseek(fp, 0, SEEK_END);
    data_size = ftell(fp);
    rewind(fp);

    data = (uint8_t *)calloc(1, 256);

    /* 验证签名 */
    pubkey = X509_get_pubkey(cert);
    if (NULL == pubkey)
    {
        APP_LOG_ERROR("X509_get_pubkey failed");
        goto CLEAN;
    }

    ctx = EVP_MD_CTX_create();
    if (NULL == ctx)
    {
        APP_LOG_ERROR("EVP_MD_CTX_create failed");
        goto CLEAN;
    }

    if (EVP_VerifyInit(ctx, EVP_sha256()) != 1)
    {
        APP_LOG_ERROR("EVP_VerifyInit failed");
        goto CLEAN;
    }

    while (read_size + 256 < data_size)
    {
        fread(data, 1, 256, fp);
        if (EVP_VerifyUpdate(ctx, data, 256) != 1)
        {
            APP_LOG_ERROR("EVP_VerifyUpdate failed");
            goto CLEAN;
        }
        read_size += 256;
    }

    fread(data, 1, data_size - read_size, fp);
    if (EVP_VerifyUpdate(ctx, data, data_size - read_size) != 1)
    {
        APP_LOG_ERROR("EVP_VerifyUpdate failed");
        goto CLEAN;
    }

    if (EVP_VerifyFinal(ctx, sign, sign_size, pubkey) != 1)
    {
        APP_LOG_ERROR("Signification verified error");
    }
    else
    {
        APP_LOG_INFO("Signification verified success");
        ret = 0;
    }

CLEAN: 
    FREE_VARIATE_WITH_FUNC(fp, fclose);
    FREE_VARIATE_WITH_FUNC(ctx, EVP_MD_CTX_destroy);
    FREE_VARIATE_WITH_FUNC(pubkey, EVP_PKEY_free);
    FREE_VARIATE_WITH_FUNC(data, free);
    FREE_VARIATE_WITH_FUNC(sign, free);
    FREE_VARIATE_WITH_FUNC(cert, X509_free);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 生成数字签名文件(CMS).
*  输入参数  : key_file - 私钥文件.
*             data_file - 数据文件.
*             cert_file - 证书文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : CMS 额外封装了证书、证书链、时间戳等信息.
*************************************************************************/
int generate_cms_signature(const char *key_file, const char *data_file, const char *cert_file, const char *signed_file)
{
    int ret = -1;
    BIO* data_bio = NULL;
    FILE *cert = NULL;
    FILE *key = NULL;
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    CMS_ContentInfo *cms = NULL;
    BIO* signature_bio = NULL;

    if (NULL == data_file || NULL == cert_file || NULL == key_file || NULL == signed_file)
    {
        APP_LOG_ERROR("Parameter is NULL[data_file: %p][cert_file: %p][key_file: %p][signed_file: %p]", 
            data_file, cert_file, key_file, signed_file);
        return -1;
    }

    data_bio = BIO_new_file(data_file, "rb");
    if (NULL == data_bio)
    {
        APP_LOG_ERROR("Failed to open data file[%s]", data_file);
        goto CLEAN;
    }

    cert = fopen(cert_file, "rb");
    if (NULL == cert)
    {
        APP_LOG_ERROR("Failed to open certificate file[%s]", cert_file);
        goto CLEAN;
    }

    key = fopen(key_file, "rb");
    if (NULL == key)
    {
        APP_LOG_ERROR("Failed to open key file[%s]", key_file);
        goto CLEAN;
    }

    x509 = PEM_read_X509(cert, NULL, NULL, NULL);
    if (NULL == x509)
    {
        APP_LOG_ERROR("PEM_read_X509 failed");
        goto CLEAN;
    }

    pkey = PEM_read_PrivateKey(key, NULL, password_callback, NULL);
    if (NULL == pkey)
    {
        APP_LOG_ERROR("PEM_read_PrivateKey failed");
        goto CLEAN;
    }

    cms = CMS_sign(x509, pkey, NULL, data_bio, CMS_DETACHED | CMS_BINARY);
    if (NULL == cms)
    {
        APP_LOG_ERROR("CMS_sign failed");
        goto CLEAN;
    }

    /* 将签名写入文件 */
    signature_bio = BIO_new_file(signed_file, "wb");
    if (NULL == signature_bio)
    {
        APP_LOG_ERROR("Failed to open signature file[%s]", signed_file);
        goto CLEAN;
    }

    if (0 == i2d_CMS_bio(signature_bio, cms))
    {
        APP_LOG_ERROR("i2d_CMS_bio failed");
        goto CLEAN;
    }
    ret = 0;

CLEAN: 
    FREE_VARIATE_WITH_FUNC(signature_bio, BIO_free);
    FREE_VARIATE_WITH_FUNC(data_bio, BIO_free);
    FREE_VARIATE_WITH_FUNC(cms, CMS_ContentInfo_free);
    FREE_VARIATE_WITH_FUNC(x509, X509_free);
    FREE_VARIATE_WITH_FUNC(pkey, EVP_PKEY_free);
    FREE_VARIATE_WITH_FUNC(cert, fclose);
    FREE_VARIATE_WITH_FUNC(key, fclose);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 验证数字签名文件(CMS).
*  输入参数  : cert_file - 证书文件.
*             data_file - 数据文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : CMS 额外封装了证书、证书链、时间戳等信息.
*************************************************************************/
int verify_cms_signature(const char *cert_file, const char *data_file, const char *signed_file)
{
    int ret = -1;
    BIO *data_bio = NULL;
    BIO *p7_bio = NULL;
    FILE *cert = NULL;
    CMS_ContentInfo *cms = NULL;
    X509 *x509 = NULL;
    STACK_OF(X509) *certs = NULL;
    X509_STORE *store = NULL;

    if (NULL == data_file || NULL == signed_file || NULL == cert_file)
    {
        APP_LOG_ERROR("Parameter is NULL[data_file: %p][signed_file: %p][cert_file: %p]", 
            data_file, signed_file, cert_file);
        return -1;
    }

    data_bio = BIO_new_file(data_file, "rb");
    if (NULL == data_bio)
    {
        APP_LOG_ERROR("Failed to open data file[%s]", data_file);
        goto CLEAN;
    }

    p7_bio = BIO_new_file(signed_file, "rb");
    if (NULL == p7_bio)
    {
        APP_LOG_ERROR("Failed to open p7 file[%s]", signed_file);
        goto CLEAN;
    }

    cert = fopen(cert_file, "rb");
    if (NULL == cert)
    {
        APP_LOG_ERROR("Failed to open certificate file[%s]", cert_file);
        goto CLEAN;
    }

    cms = d2i_CMS_bio(p7_bio, NULL);
    if (NULL == cms)
    {
        APP_LOG_ERROR("d2i_CMS_bio failed");
        goto CLEAN;
    }

    x509 = PEM_read_X509(cert, NULL, NULL, NULL);
    if (NULL == x509)
    {
        APP_LOG_ERROR("PEM_read_X509 failed");
        goto CLEAN;
    }

    /* 创建证书栈 */
    certs = sk_X509_new_null();
    if (NULL == certs)
    {
        APP_LOG_ERROR("Failed to create certificate stack");
        goto CLEAN;
    }

    if (0 == sk_X509_push(certs, x509))
    {
        APP_LOG_ERROR("Failed to add certificate to stack");
        goto CLEAN;
    }

    /* 将自签名证书添加到信任库 */
    store = X509_STORE_new();
    if (0 == X509_STORE_add_cert(store, x509))
    {
        APP_LOG_ERROR("Failed to add certificate to store");
        goto CLEAN;
    }

    // if (CMS_verify(cms, certs, NULL, data_bio, NULL, CMS_DETACHED | CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) <= 0)
    if (CMS_verify(cms, certs, store, data_bio, NULL, CMS_DETACHED | CMS_BINARY) <= 0)
    {
        APP_LOG_ERROR("Signature verified failed!");
        goto CLEAN;
    }

    ret = 0;
    APP_LOG_INFO("Signature verified successfully!");

CLEAN: 
    FREE_VARIATE_WITH_FUNC(cms, CMS_ContentInfo_free);
    FREE_VARIATE_WITH_FUNC(x509, X509_free);
    FREE_VARIATE_WITH_FUNC(cert, fclose);
    FREE_VARIATE_WITH_FUNC(store, X509_STORE_free);
    FREE_VARIATE_WITH_FUNC(data_bio, BIO_free);
    FREE_VARIATE_WITH_FUNC(p7_bio, BIO_free);
    FREE_VARIATE_WITH_FUNC(certs, sk_X509_free);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 生成数字签名文件(PKCS #7).
*  输入参数  : key_file - 私钥文件.
*             data_file - 数据文件.
*             cert_file - 证书文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : PKCS #7 额外封装了证书、证书链、时间戳等信息.
*************************************************************************/
int generate_pkcs7_signature(const char *key_file, const char *data_file, const char *cert_file, const char *signed_file)
{
    int ret = -1;
    BIO *bio = NULL;
    FILE *fp = NULL;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    struct stack_st_X509 *certs = NULL;
    PKCS7 *p7 = NULL;

    if (NULL == key_file || NULL == data_file || NULL == cert_file || NULL == signed_file)
    {
        APP_LOG_ERROR("Parameter is NULL[key_file: %p][data_file: %p][cert_file: %p][signed_file: %p]", 
            key_file, data_file, cert_file, signed_file);
        return -1;
    }

    /* 读取数据文件 */
    bio = BIO_new_file(data_file, "rb");
    if (NULL == bio)
    {
        APP_LOG_ERROR("BIO_new_file failed[%s]", data_file);
        goto CLEAN;
    }

    /* 读取证书 */
    fp = fopen(cert_file, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]", cert_file);
        goto CLEAN;
    }

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (NULL == cert)
    {
        APP_LOG_ERROR("PEM_read_X509 failed");
        goto CLEAN;
    }

    fclose(fp);
    fp = NULL;

    /* 读取私钥 */
    fp = fopen(key_file, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]", key_file);
        goto CLEAN;
    }

    key = PEM_read_PrivateKey(fp, NULL, password_callback, NULL);
    if (NULL == key)
    {
        APP_LOG_ERROR("PEM_read_PrivateKey failed");
        goto CLEAN;
    }

    certs = sk_X509_new_null();
    if (NULL == certs)
    {
        APP_LOG_ERROR("sk_X509_new_null failed");
        goto CLEAN;
    }

    if (0 == sk_X509_push(certs, cert))
    {
        APP_LOG_ERROR("sk_X509_push failed");
        goto CLEAN;
    }

    /* 创建签名结构 */
    p7 = PKCS7_sign(cert, key, certs, bio, PKCS7_DETACHED | PKCS7_BINARY);
    if (NULL == p7)
    {
        ERR_print_errors_fp(stderr);
        APP_LOG_ERROR("PKCS7_sign failed");
        goto CLEAN;
    }
    ERR_print_errors_fp(stderr);

    BIO_free(bio);
    bio = NULL;

    /* 设置哈希算法上下文到 PKCS7 对象 */
    if (0 == PKCS7_set_detached(p7, 1))
    {
        APP_LOG_ERROR("PKCS7_sign failed");
        goto CLEAN;
    }

    /* 保存签名到文件 */
    bio = BIO_new_file(signed_file, "wb");
    if (NULL == bio)
    {
        APP_LOG_ERROR("BIO_new_file failed[%s]", signed_file);
        goto CLEAN;
    }

    if (0 == PEM_write_bio_PKCS7(bio, p7))
    {
        APP_LOG_ERROR("PEM_write_bio_PKCS7 failed");
        goto CLEAN;
    }

    ret = 0;

CLEAN: 
    FREE_VARIATE_WITH_FUNC(bio, BIO_free);
    FREE_VARIATE_WITH_FUNC(p7, PKCS7_free);
    FREE_VARIATE_WITH_FUNC(certs, sk_X509_free);
    FREE_VARIATE_WITH_FUNC(key, EVP_PKEY_free);
    FREE_VARIATE_WITH_FUNC(fp, fclose);
    FREE_VARIATE_WITH_FUNC(cert, X509_free);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 验证数字签名文件(PKCS #7).
*  输入参数  : cert_file - 证书文件.
*             data_file - 数据文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : PKCS #7 额外封装了证书、证书链、时间戳等信息.
*************************************************************************/
int verify_pkcs7_signature(const char *cert_file, const char *data_file, const char *signed_file)
{
    int ret = -1;
    FILE *fp = NULL;
    BIO *bio = NULL;
    PKCS7 *p7_verify = NULL;
    X509 *cert = NULL;
    struct stack_st_X509 *certs = NULL;
    X509_STORE *store = NULL;

    if (NULL == cert_file || NULL == data_file || NULL == signed_file)
    {
        APP_LOG_ERROR("Parameter is NULL[cert_file: %p][data_file: %p][signed_file: %p]", 
            cert_file, data_file, signed_file);
        return -1;
    }

    bio = BIO_new_file(signed_file, "rb");
    if (NULL == bio)
    {
        APP_LOG_ERROR("BIO_new_file failed[%s]", signed_file);
        goto CLEAN;
    }

    p7_verify = PEM_read_bio_PKCS7(bio, NULL, NULL, NULL);
    if (NULL == p7_verify)
    {
        APP_LOG_ERROR("PEM_read_bio_PKCS7 failed");
        goto CLEAN;
    }

    BIO_free(bio);
    bio = NULL;

    /* 创建证书栈 */
    certs = sk_X509_new_null();
    if (NULL == certs)
    {
        APP_LOG_ERROR("sk_X509_new_null failed");
        goto CLEAN;
    }

    /* 读取证书 */
    fp = fopen(cert_file, "rb");
    if (NULL == fp)
    {
        APP_LOG_ERROR("fopen failed[%s]", cert_file);
        goto CLEAN;
    }

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (NULL == cert)
    {
        APP_LOG_ERROR("PEM_read_X509 failed");
        goto CLEAN;
    }

    if (0 == sk_X509_push(certs, cert))
    {
        APP_LOG_ERROR("sk_X509_push failed");
        goto CLEAN;
    }

    bio = BIO_new_file(data_file, "rb");
    if (NULL == bio)
    {
        APP_LOG_ERROR("BIO_new_file failed[%s]", data_file);
        goto CLEAN;
    }

    /* 将自签名证书添加到信任库 */
    store = X509_STORE_new();
    if (NULL == store)
    {
        APP_LOG_ERROR("X509_STORE_new failed");
        goto CLEAN;
    }

    if (0 == X509_STORE_add_cert(store, cert))
    {
        APP_LOG_ERROR("X509_STORE_add_cert failed");
        goto CLEAN;
    }

    if (0 == PKCS7_verify(p7_verify, certs, store, bio, NULL, PKCS7_DETACHED | PKCS7_BINARY))
    {
        APP_LOG_ERROR("PKCS7_verify failed");
        goto CLEAN;
    }

    APP_LOG_INFO("Verify success");
    ret = 0;

CLEAN: 
    FREE_VARIATE_WITH_FUNC(store, X509_STORE_free);
    FREE_VARIATE_WITH_FUNC(bio, BIO_free);
    FREE_VARIATE_WITH_FUNC(cert, X509_free);
    FREE_VARIATE_WITH_FUNC(fp, fclose);
    FREE_VARIATE_WITH_FUNC(certs, sk_X509_free);
    FREE_VARIATE_WITH_FUNC(p7_verify, PKCS7_free);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250305
*  函数功能  : 检查签名工具必要参数.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 0 - 已具备  -1 - 未具备.
*************************************************************************/
int check_sign_tool_required_parameter(void)
{
    if (0 == strcmp("", g_data_file_name) || 
        0 == strcmp("", g_signed_file_name))
    {
        return -1;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250305
*  函数功能  : 判定是否签名生成请求.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : true - 是  false - 否.
*************************************************************************/
bool is_sign_generate_request(void)
{
    if (0 == strcmp("", g_key_file_name))
    {
        return false;
    }

    return true;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250305
*  函数功能  : 判定是否签名验证请求.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : true - 是  false - 否.
*************************************************************************/
bool is_sign_verify_request(void)
{
    if (0 == strcmp("", g_key_file_name))
    {
        return true;
    }

    return false;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250305
*  函数功能  : 数字签名处理入口(仅在作为独立的程序时调用).
*  输入参数  : argc - 命令行参数个数.
*             argv - 命令行参数内容.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void sign_tool_main(int argc, char **argv)
{
    /* 命令行参数解析 */
    if (sign_parse_command_line(argc, argv) != 0)
    {
        return ;
    }

    /* 检查必要参数 */
    if (check_sign_tool_required_parameter() != 0)
    {
        APP_LOG_ERROR("Sign tool needs required parameters: data file and signed file");
        return ;
    }

    /* 生成签名 */
    if (is_sign_generate_request())
    {
        for (int i = 0; i < sizeof(g_sign_func_set) / sizeof(SIGN_FUNC_SET_T); i++)
        {
            if (0 == strcmp(g_sign_algo_name, g_sign_func_set[i].algo_name) && 
                g_sign_func_set[i].generate != NULL)
            {
                if (g_sign_func_set[i].generate(g_key_file_name, 
                                                g_data_file_name, 
                                                g_cert_file_name, 
                                                g_signed_file_name) != 0)
                {
                    APP_LOG_ERROR("Signature generate failed");
                }
                else 
                {
                    APP_LOG_INFO("Signature generate success");
                }
                break;
            }
        }
    }

    /* 验证签名 */
    if (is_sign_verify_request())
    {
        for (int i = 0; i < sizeof(g_sign_func_set) / sizeof(SIGN_FUNC_SET_T); i++)
        {
            if (0 == strcmp(g_sign_algo_name, g_sign_func_set[i].algo_name) && 
                g_sign_func_set[i].verify != NULL)
            {
                if (g_sign_func_set[i].verify(g_cert_file_name, 
                                              g_data_file_name, 
                                              g_signed_file_name) != 0)
                {
                    APP_LOG_ERROR("Signature verify failed");
                }
                else 
                {
                    APP_LOG_INFO("Signature verify success");
                }
                break;
            }
        }
    }

    return ;
}
