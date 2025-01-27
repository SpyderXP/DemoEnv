/******************************************************************************
  *  文件名     : epoll_timer.c
  *  负责人     : xupeng
  *  创建日期   : 20250126
  *  版本号     : v1.1 
  *  文件描述   : 基于EPOLL实现的C语言定时器.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <math.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include "logger.h"
#include "epoll_timer.h"

#define EPOLL_EVENT_SIZE 8

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 创建 EPOLL 文件描述符.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : EPOLL 文件描述符.
*************************************************************************/
int create_epollfd(void)
{
    int epollfd = -1;

    // EPOLL_CLOEXEC 在进程切换映像后自动关闭此FD.
    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (-1 == epollfd)
    {
        APP_LOG_ERROR("Failed to create epoll fd");
        return -1;
    }

    return epollfd;
}

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
int create_ms_epoll_timer(DATA_CONTEXT_T *trans_data, int epollfd, int interval)
{
    int timerfd = -1;
    struct itimerspec ts = {0};
    struct epoll_event ep_event = {0};

    if (NULL == trans_data)
    {
        APP_LOG_ERROR("trans_data is NULL");
        return -1;
    }

    timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (-1 == timerfd)
    {
        APP_LOG_ERROR("Failed to create timerfd");
        return -1;
    }

    ts.it_value.tv_sec = interval / 1000;
    ts.it_value.tv_nsec = (interval % 1000) * 1000000;
    ts.it_interval.tv_sec = interval / 1000;
    ts.it_interval.tv_nsec = (interval % 1000) * 1000000;
    if (timerfd_settime(timerfd, 0, &ts, NULL) != 0)
    {
        APP_LOG_ERROR("Failed to timerfd settime");
        return -1;
    }

    // EPOLLET 边缘触发，只在发生的时候触发一次.
    ep_event.events = EPOLLIN | EPOLLET;
    trans_data->data.timerfd = timerfd;
    ep_event.data.ptr = (void *)trans_data;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &ep_event) != 0)
    {
        APP_LOG_ERROR("Failed to epoll_ctl()");
        return -1;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 非阻塞EPOLL定时器维护循环.
*  输入参数  : para - EPOLL 文件描述符.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void *nonblock_epoll_timer_maintain_loop(void *para)
{
    int epollfd = -1;
    int count = 0;
    DATA_CONTEXT_T *output_data = NULL;
    uint64_t exp = 0;
    struct epoll_event ep_wait_events[EPOLL_EVENT_SIZE] = {0};

    epollfd = *(int *)para;
    if (epollfd < 0)
    {
        APP_LOG_ERROR("epollfd[%d] is invalid", epollfd);
        return NULL;
    }

    while (1)
    {
        // ep_wait_events 数组可以是任意长度，内核不会丢弃消息，但是在高压测试下，长度越长，效率越高（与epoll_wait调用次数成反比）.
        // timeout 0 代表立即返回，需要在线程中添加睡眠时间保证不会持续占用CPU.
        // timeout -1 代表阻塞等待，此种情况无法处理后续代码.
        count = epoll_wait(epollfd, ep_wait_events, EPOLL_EVENT_SIZE, 0);
        if (count > 0)
        {
            APP_LOG_DEBUG("Recv epoll event count: %d", count);
            for (int i = 0; i < count; i++)
            {
                output_data = (DATA_CONTEXT_T *)ep_wait_events[i].data.ptr;
                if (NULL == output_data)
                {
                    continue;
                }

                while (read(output_data->data.timerfd, &exp, sizeof(uint64_t)) != -1)
                {
                    // nothing to do.
                }

                if (NULL == output_data->handler)
                {
                    continue;
                }

                output_data->handler(&output_data->data);
            }
        }

        usleep(10000);
    }

    close(epollfd);
    epollfd = -1;
    return NULL;
}
