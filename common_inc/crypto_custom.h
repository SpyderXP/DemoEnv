/******************************************************************************
  *  文件名     : crypto_custom.h
  *  负责人     : xupeng
  *  创建日期   : 20250118
  *  版本号     : v1.1 
  *  文件描述   : 通用文件加密解密模块.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __CRYPTO_CUSTOM_H__
#define __CRYPTO_CUSTOM_H__

#ifdef __cplusplus
extern "C" {
#endif

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
                        const char *encrypt_path);

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
                        const char *decrypt_path);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 文件加密/解密入口(仅在作为独立的加密/解密程序时调用).
*  输入参数  : argc - 命令行参数个数.
*             argv - 命令行参数内容.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void crypto_main(int argc, char **argv);

#ifdef __GTEST_DEMO__

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 检查必填参数(文件名/密钥路径/算法名).
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int crypto_check_required_param(void);

#endif

#ifdef __cplusplus
}
#endif

#endif
