/******************************************************************************
  *  文件名     : crypto_aes256.h
  *  负责人     : xupeng
  *  创建日期   : 20250123
  *  版本号     : v1.1 
  *  文件描述   : AES256加解密接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __CRYPTO_AES256_H__
#define __CRYPTO_AES256_H__

#ifdef __cplusplus
extern "C" {
#endif

#define AES_KEY_LEN 32  /* AES对称加密密钥长度（256位AES加密） */
#define AES_IV_LEN  16  /* AES对称加密向量长度 */

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
                                       const char *filename);

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
                                       const char *filename);

#ifdef __cplusplus
}
#endif

#endif
