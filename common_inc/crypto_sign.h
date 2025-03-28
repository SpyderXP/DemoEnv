/******************************************************************************
  *  文件名     : crypto_sign.h
  *  负责人     : xupeng
  *  创建日期   : 20250305
  *  版本号     : v1.1 
  *  文件描述   : 数字签名接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __CRYPTO_SIGN_H__
#define __CRYPTO_SIGN_H__

#ifdef __cplusplus
extern "C" {
#endif

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 生成数字签名文件(RSA普通签名算法).
*  输入参数  : key_file - 私钥文件.
*             passwd - 私钥密码.
*             data_file - 数据文件.
*             cert_file - 证书文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : 普通签名算法只包含签名值和签名算法，不包含证书及证书链等信息.
*************************************************************************/
int generate_rsa_signature(const char *key_file, const char *passwd, const char *data_file, 
  const char *cert_file, const char *signed_file);

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
int verify_rsa_signature(const char *cert_file, const char *data_file, const char *signed_file);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 生成数字签名文件(CMS).
*  输入参数  : key_file - 私钥文件.
*             passwd - 私钥密码.
*             data_file - 数据文件.
*             cert_file - 证书文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : CMS 额外封装了证书、证书链、时间戳等信息.
*************************************************************************/
int generate_cms_signature(const char *key_file, const char *passwd, const char *data_file, 
  const char *cert_file, const char *signed_file);

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
int verify_cms_signature(const char *cert_file, const char *data_file, const char *signed_file);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250304
*  函数功能  : 生成数字签名文件(PKCS #7).
*  输入参数  : key_file - 私钥文件.
*             passwd - 私钥密码.
*             data_file - 数据文件.
*             cert_file - 证书文件.
*             signed_file - 签名文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  其他     : PKCS #7 额外封装了证书、证书链、时间戳等信息.
*************************************************************************/
int generate_pkcs7_signature(const char *key_file, const char *passwd, const char *data_file, 
  const char *cert_file, const char *signed_file);

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
int verify_pkcs7_signature(const char *cert_file, const char *data_file, const char *signed_file);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250305
*  函数功能  : 数字签名处理入口(仅在作为独立的程序时调用).
*  输入参数  : argc - 命令行参数个数.
*             argv - 命令行参数内容.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void sign_tool_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif
