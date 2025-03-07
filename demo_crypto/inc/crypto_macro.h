/******************************************************************************
  *  文件名     : crypto_macro.h
  *  负责人     : xupeng
  *  创建日期   : 20250123
  *  版本号     : v1.1 
  *  文件描述   : 加密/解密模块通用宏.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __CRYPTO_MACRO_H__
#define __CRYPTO_MACRO_H__

#ifdef __cplusplus
extern "C" {
#endif

#define BUFFER_SIZE             (16 * 1024)             /* 每次处理 16KB 数据 */
#define FILENAME_LEN            256                     /* 文件名最大长度 */
#define PATHNAME_LEN            256                     /* 文件路径最大长度 */
#define FULL_FILENAME_LEN       512                     /* 文件路径 + 文件名 最大长度 */
#define CRYPTO_ALGO_NAMELEN     32                      /* 加密/解密算法名称最大长度 */
#define CRYPTO_PASSWD_SIZE      32                      /* 通用密码最大长度 */

#ifdef __cplusplus
}
#endif

#endif
