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
#include <stdbool.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include "epoll_timer.h"

bool g_epoll_timer_loop_flag = true;

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
        return -1;
    }

    return epollfd;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 创建毫秒级EPOLL定时器.
*  输入参数  : timer - 定时器回调参数.
*             epollfd - EPOLL 文件描述符.
*             interval - 定时器回调间隔(毫秒).
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int create_ms_epoll_timer(EPOLL_TIMER_T *timer, int epollfd, int interval)
{
    int timerfd = -1;
    struct itimerspec ts = {0};
    struct epoll_event ep_event = {0};

    if (NULL == timer)
    {
        return -1;
    }

    timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (-1 == timerfd)
    {
        return -1;
    }

    ts.it_value.tv_sec = interval / 1000;
    ts.it_value.tv_nsec = (interval % 1000) * 1000000;
    ts.it_interval.tv_sec = interval / 1000;
    ts.it_interval.tv_nsec = (interval % 1000) * 1000000;
    if (timerfd_settime(timerfd, 0, &ts, NULL) != 0)
    {
        return -1;
    }

    // EPOLLET 边缘触发，只在发生的时候触发一次.
    ep_event.events = EPOLLIN | EPOLLET;
    timer->ctx.timerfd = timerfd;
    ep_event.data.ptr = (void *)timer;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &ep_event) != 0)
    {
        return -1;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 销毁毫秒级EPOLL定时器.
*  输入参数  : timer - 定时器回调参数.
*             epollfd - EPOLL 文件描述符.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void destroy_ms_epoll_timer(EPOLL_TIMER_T *timer, int epollfd)
{
    struct itimerspec ts = {0};

    if (NULL == timer || timer->ctx.timerfd <= 0)
    {
        return ;
    }

    // stop.
    if (timerfd_settime(timer->ctx.timerfd, 0, &ts, NULL) != 0)
    {
        return ;
    }

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, timer->ctx.timerfd, NULL) != 0)
    {
        return ;
    }

    close(timer->ctx.timerfd);
    timer->ctx.timerfd = -1;
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 非阻塞EPOLL定时器维护循环(默认开启循环).
*  输入参数  : para - EPOLL 文件描述符.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void *nonblock_epoll_timer_loop_run(void *para)
{
    int epollfd = -1;
    int count = 0;
    EPOLL_TIMER_T *timer = NULL;
    uint64_t exp = 0;       // linux 内核规定定时器触发后向fd写入64位数据.
    struct epoll_event ep_wait_events[EPOLL_EVENT_SIZE] = {0};

    epollfd = *(int *)para;
    if (epollfd < 0)
    {
        return NULL;
    }

    while (g_epoll_timer_loop_flag)
    {
        // ep_wait_events 数组可以是任意长度，内核不会丢弃消息，但是在高压测试下，长度越长，效率越高（与epoll_wait调用次数成反比）.
        // timeout 0 代表立即返回，需要在线程中添加睡眠时间保证不会持续占用CPU.
        // timeout -1 代表阻塞等待，此种情况无法处理后续代码.
        count = epoll_wait(epollfd, ep_wait_events, EPOLL_EVENT_SIZE, 0);
        if (count > 0)
        {
            for (int i = 0; i < count; i++)
            {
                timer = (EPOLL_TIMER_T *)ep_wait_events[i].data.ptr;
                if (NULL == timer)
                {
                    continue;
                }

                while (read(timer->ctx.timerfd, &exp, sizeof(exp)) != -1)
                {
                    // 固定读取64位数据，将内核写入的数据读走.
                }

                if (NULL == timer->handler)
                {
                    continue;
                }

                timer->handler(&timer->ctx);
            }
        }

        usleep(10000);
    }

    close(epollfd);
    epollfd = -1;
    return NULL;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250127
*  函数功能  : 终止非阻塞EPOLL定时器维护循环.
*  输入参数  : para - EPOLL 文件描述符.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void nonblock_epoll_timer_loop_stop(void)
{
    g_epoll_timer_loop_flag = false;
    return ;
}
