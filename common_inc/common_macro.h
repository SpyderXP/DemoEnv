/******************************************************************************
  *  文件名     : common_macro.h
  *  负责人     : xupeng
  *  创建日期   : 20250117
  *  版本号     : v1.1 
  *  文件描述   : 通用宏定义.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __COMMON_MACRO__H__
#define __COMMON_MACRO__H__

#include <stdio.h>
#include <sys/time.h>

#ifdef __cpluscplus
extern "C" {
#endif

#define TIME_ELAPSED(code)                                                      \
do                                                                              \
{                                                                               \
    struct timeval begin = {0};                                                 \
    struct timeval end = {0};                                                   \
    long sec = 0;                                                               \
    long usec = 0;                                                              \
    gettimeofday(&begin, NULL);                                                 \
    {code;}                                                                     \
    gettimeofday(&end, NULL);                                                   \
    sec = end.tv_sec - begin.tv_sec;                                            \
    usec = end.tv_usec - begin.tv_usec;                                         \
    fprintf(stdout, "[%s(%d)]Elapsed Time: SecTime = %lds, UsecTime = %ldus\n", \
         __FILE__, __LINE__, sec, usec);                                        \
} while (0);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 快速字符串拼接.
*  输入参数  : src - 源字符串.
*             size - 拼接长度.
*             dst - 目的字符串.
*  输出参数  : 无.
*  返回值    : 目的字符串.
*************************************************************************/
inline char *fast_strncat(char *dst, char *src, int size)
{
    while (*dst)
    {
        dst++;
    }

    while (size--)
    {
        *dst++ = *src++;
    }
    return --dst;
}

#define OSTRNCAT(dst, src, size) fast_strncat(dst, src, size)

#define CHECK_NULL_1PARAM_WITHOUT_RET(param1)                               \
if (NULL == param1)                                                         \
{                                                                           \
    return ;                                                                \
}                                                                           \

#define CHECK_NULL_1PARAM_WITH_RET(param1, ret)                             \
if (NULL == param1)                                                         \
{                                                                           \
    return ret;                                                             \
}                                                                           \

#define CHECK_NULL_2PARAM_WITHOUT_RET(param1, param2)                       \
if (NULL == param1 || NULL == param2)                                       \
{                                                                           \
    return ;                                                                \
}                                                                           \

#define CHECK_NULL_2PARAM_WITH_RET(param1, param2, ret)                     \
if (NULL == param1 || NULL == param2)                                       \
{                                                                           \
    return ret;                                                             \
}                                                                           \

#define CHECK_NULL_3PARAM_WITHOUT_RET(param1, param2, param3)               \
if (NULL == param1 || NULL == param2 || NULL == param3)                     \
{                                                                           \
    return ;                                                                \
}                                                                           \

#define CHECK_NULL_3PARAM_WITH_RET(param1, param2, param3, ret)             \
if (NULL == param1 || NULL == param2 || NULL == param3)                     \
{                                                                           \
    return ret;                                                             \
}                                                                           \

#define CHECK_NULL_4PARAM_WITHOUT_RET(param1, param2, param3, param4)       \
if (NULL == param1 || NULL == param2 || NULL == param3 || NULL == param4)   \
{                                                                           \
    return ;                                                                \
}                                                                           \

#define CHECK_CONDITION_WITHOUT_RET(cond)                                   \
if (cond)                                                                   \
{                                                                           \
    return ;                                                                \
}                                                                           \

#define CHECK_CONDITION_WITH_RET(cond, ret)                                 \
if (cond)                                                                   \
{                                                                           \
    return ret;                                                             \
}                                                                           \

#ifdef __cpluscplus
}
#endif

#endif
