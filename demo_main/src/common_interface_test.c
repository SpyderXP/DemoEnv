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

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250117
*  函数功能  : EPOLL处理回调.
*  输入参数  : data - 回调参数.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int epoll_data_process(TRANS_DATA_T *data)
{
    struct timeval tv = {0};

    if (NULL == data)
    {
        return -1;
    }

    gettimeofday(&tv, NULL);
    APP_LOG_ERROR("timer: %d | val: %d | sec: %ld | usec: %ld\n", 
        data->timerfd, data->val, tv.tv_sec, tv.tv_usec);
    return 0;
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

    pthread_t pt = 0;
    int epollfd = -1;
    DATA_CONTEXT_T trans_data[8] = {0};

    epollfd = create_epollfd();
    pthread_create(&pt, NULL, nonblock_epoll_timer_maintain_loop, &epollfd);

    // 数据赋值.
    trans_data[0].data.val = 1;
    trans_data[0].handler = epoll_data_process;
    trans_data[1].data.val = 2;
    trans_data[1].handler = epoll_data_process;

    // 创建毫秒级定时器并加入到epoll管理.
    if (create_ms_epoll_timer(&trans_data[0], epollfd, 2500) != 0)
    {
        APP_LOG_ERROR("Failed to create epoll timer");
        return -1;
    }

    if (create_ms_epoll_timer(&trans_data[1], epollfd, 3000) != 0)
    {
        APP_LOG_ERROR("Failed to create epoll timer");
        return -1;
    }

    // wait for thread.
    while (1)
    {
        sleep(1);
    }

    destroy_logger();
    return 0;
}
