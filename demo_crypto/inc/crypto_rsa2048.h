/******************************************************************************
  *  文件名     : crypto_rsa2048.h
  *  负责人     : xupeng
  *  创建日期   : 20250225
  *  版本号     : v1.1 
  *  文件描述   : RSA2048加解密接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __CRYPTO_RSA2048_H__
#define __CRYPTO_RSA2048_H__

#ifdef __cplusplus
extern "C" {
#endif

/************************************************************************* 
*  负责人    : xupeng
*  创建日期	 : 20250225
*  函数功能  : RSA密钥生成.
*  输入参数  : key_path - 指定加密的密钥路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int rsa2048_crypto_key_generator(const char *key_path);

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
int rsa2048_encrypt_specified_mmap_addr(const uint8_t *addr, 
                                       int datalen, 
                                       const char *key_path, 
                                       const char *encrypt_file);

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
int rsa2048_decrypt_specified_mmap_addr(const uint8_t *addr, 
                                       int datalen, 
                                       const char *key_path, 
                                       const char *decrypt_file);

#ifdef __cplusplus
}
#endif

#endif
