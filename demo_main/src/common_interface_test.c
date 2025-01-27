/******************************************************************************
  *  文件名     : epoll_timer_usage.c
  *  负责人     : xupeng
  *  创建日期   : 20250118
  *  版本号     : v1.1 
  *  文件描述   : EPOLL 定时器调用示例.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include "logger.h"
#include "common_macro.h"
#include "epoll_timer.h"

/* 用户自定义定时器参数数据域 */
typedef struct EPOLL_TIMER_DATA_S
{
    int num;
    char arr[32];
} EPOLL_TIMER_DATA_T;

/* EPOLL FD */
int g_epollfd = -1;

/* EPOLL定时器实例 */
EPOLL_TIMER_T g_epoll_timer[EPOLL_EVENT_SIZE] = {0};

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : EPOLL处理回调.
*  输入参数  : ctx - 定时器回调参数.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int epoll_data_process(TIMER_CTX_T *ctx)
{
    struct timeval tv = {0};
    EPOLL_TIMER_DATA_T *ptr = NULL;

    if (NULL == ctx)
    {
        APP_LOG_ERROR("ctx is NULL");
        return -1;
    }

    ptr = (EPOLL_TIMER_DATA_T *)ctx->data;
    if (NULL == ptr)
    {
        APP_LOG_ERROR("Epoll timer data is NULL");
    }

    gettimeofday(&tv, NULL);
    APP_LOG_ERROR("timer: %d | num: %d | sec: %ld | usec: %ld\n", 
        ctx->timerfd, ptr->num, tv.tv_sec, tv.tv_usec);
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : EPOLL定时器处理逻辑.
*  输入参数  : ctx - 定时器回调参数.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int epoll_timer_run(void)
{
    pthread_t pt = 0;
    char *alloc_mem = NULL;
    EPOLL_TIMER_DATA_T *dataptr = NULL;

    alloc_mem = (char *)calloc(2, sizeof(EPOLL_TIMER_DATA_T));
    if (NULL == alloc_mem)
    {
        APP_LOG_ERROR("CALLOC FAILED");
        return -1;
    }

    // 数据赋值.
    g_epoll_timer[0].ctx.data = alloc_mem;
    dataptr = (EPOLL_TIMER_DATA_T *)g_epoll_timer[0].ctx.data;
    dataptr->num = 1;
    g_epoll_timer[0].handler = epoll_data_process;
    g_epoll_timer[1].ctx.data = alloc_mem + sizeof(EPOLL_TIMER_DATA_T);
    dataptr = (EPOLL_TIMER_DATA_T *)g_epoll_timer[1].ctx.data;
    dataptr->num = 2;
    g_epoll_timer[1].handler = epoll_data_process;

    g_epollfd = create_epollfd();
    if (pthread_create(&pt, NULL, nonblock_epoll_timer_loop_run, (void *)&g_epollfd) != 0)
    {
        APP_LOG_ERROR("Failed to create thread func");
        goto FAIL;
    }

    // 创建毫秒级定时器并加入到epoll管理.
    if (create_ms_epoll_timer(&g_epoll_timer[0], g_epollfd, 2500) != 0)
    {
        APP_LOG_ERROR("Failed to create epoll timer");
        goto FAIL;
    }

    if (create_ms_epoll_timer(&g_epoll_timer[1], g_epollfd, 3000) != 0)
    {
        APP_LOG_ERROR("Failed to create epoll timer");
        goto FAIL;
    }

    return 0;

FAIL:
    if (g_epoll_timer[0].ctx.timerfd > 0)
    {
        destroy_ms_epoll_timer(&g_epoll_timer[0], g_epollfd);
    }

    if (g_epoll_timer[1].ctx.timerfd > 0)
    {
        destroy_ms_epoll_timer(&g_epoll_timer[1], g_epollfd);
    }

    nonblock_epoll_timer_loop_stop();
    pthread_join(pt, NULL);
    if (alloc_mem != NULL)
    {
        free(alloc_mem);
        alloc_mem = NULL;
    }

    return -1;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : 通用测试入口.
*  输入参数  : argc - 命令行参数个数.
*             argv - 命令行参数内容.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int main(int argc, char **argv)
{
    if (init_logger(NULL, NULL) != 0) 
    {
        fprintf(stdout, "Init logger failed\n");
        return -1;
    }

    if (epoll_timer_run() != 0)
    {
        APP_LOG_ERROR("epoll timer went error");
    }

    // wait for thread.
    while (1)
    {
        sleep(1);
    }

    destroy_logger();
    return 0;
}
