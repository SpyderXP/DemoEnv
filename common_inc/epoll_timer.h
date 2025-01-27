/******************************************************************************
  *  文件名     : epoll_timer.h
  *  负责人     : xupeng
  *  创建日期   : 20250126
  *  版本号     : v1.1 
  *  文件描述   : 基于EPOLL实现的C语言定时器.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __EPOLL_TIMER_H__
#define __EPOLL_TIMER_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TRANS_DATA_S
{
    int timerfd;

    /* data section */
    int val;
} TRANS_DATA_T;

typedef int (*DATA_HANDLER)(TRANS_DATA_T *data);

typedef struct DATA_CONTEXT_S
{
    TRANS_DATA_T data;
    DATA_HANDLER handler;
} DATA_CONTEXT_T;

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 创建 EPOLL 文件描述符.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : EPOLL 文件描述符.
*************************************************************************/
int create_epollfd(void);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 创建毫秒级EPOLL定时器.
*  输入参数  : trans_data - 定时器回调参数.
*             epollfd - EPOLL 文件描述符.
*             interval - 定时器回调间隔(毫秒).
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int create_ms_epoll_timer(DATA_CONTEXT_T *trans_data, int epollfd, int interval);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 非阻塞EPOLL定时器维护循环.
*  输入参数  : para - EPOLL 文件描述符.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void *nonblock_epoll_timer_maintain_loop(void *para);

#ifdef __cplusplus
}
#endif

#endif
