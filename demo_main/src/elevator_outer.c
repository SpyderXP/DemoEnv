/******************************************************************************
  *  文件名     : elevator.c
  *  负责人     : xupeng
  *  创建日期   : 20260107
  *  版本号     : v1.1 
  *  文件描述   : 模拟商用电梯逻辑.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <threads.h>
#include <math.h>
#include <stdbool.h>
#include <termios.h>
#include <signal.h>
#include <sys/select.h>
#include "common_socket.h"

int16_t g_self_level = 1;

/* 当前电梯所在楼层（内外面板使用） */
int16_t g_elevator_level = 1;

/* 电梯当前运行方向（内外面板使用） */
char g_elevator_direction[8] = "-";

char g_hint_str[512] = {0};

struct termios orig_termios;

int g_client_fd = 0;

void set_conio_terminal_mode()
{
    struct termios new_termios;

    tcgetattr(0, &orig_termios); // 保存原始设置
    memset(&new_termios, 0, sizeof(new_termios));
    memcpy(&new_termios, &orig_termios, sizeof(new_termios));

    // 关键：关闭规范模式和回显
    new_termios.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(0, TCSANOW, &new_termios);
    return ;
}

void reset_terminal_mode()
{
    tcsetattr(0, TCSANOW, &orig_termios); // 程序退出前恢复终端设置
}

int keyboard_hit()
{
    struct timeval tv = { 0L, 0L };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}

int getch()
{
    int ret;
    unsigned char c;
    if ((ret = read(STDIN_FILENO, &c, sizeof(c))) < 0)
    {
        return ret;
    }
    else
    {
        return c;
    }
}

void *tcp_msg_process_func(void *para)
{
    char tcp_msg[512] = {0};

    g_client_fd = tcp_client_init(8081, "127.0.0.1");
    if (g_client_fd < 0)
    {
        fprintf(stdout, "tcp client init failed\n");
        return NULL;
    }

    while (1)
    {
        if (tcp_client_recv_msg(g_client_fd, tcp_msg, sizeof(tcp_msg)) > 0)
        {
            printf("tcp msg: %s\n", tcp_msg);
        }

        usleep(50000);
    }
}

void handle_sigint(int sig)
{
    switch (sig)
    {
    case SIGINT: 
        exit(EXIT_SUCCESS);
        break;

    case SIGPIPE: 
        fprintf(stdout, "Recv SIGPIPE signal.\n");
        break;

    default:
        break;
    }

    return ;
}

int signal_process(void)
{
    struct sigaction act;
    struct sigaction oact;

    memset(&act, 0, sizeof(act));
    memset(&oact, 0, sizeof(oact));

    act.sa_handler = handle_sigint;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGINT);
    sigaddset(&act.sa_mask, SIGPIPE);
    act.sa_flags = 0;

    if (sigaction(SIGINT, &act, &oact) != 0)
    {
        fprintf(stdout, "sigaction failed\n");
        return -1;
    }

    if (sigaction(SIGPIPE, &act, &oact) != 0)
    {
        fprintf(stdout, "sigaction failed\n");
        return -1;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20260107
*  函数功能  : 主程序入口.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : -1 失败.
*************************************************************************/
int main(int argc, char **argv)
{
    pthread_t tcp_pt = 0;
    int button = 0;
    char tcp_msg[512] = {0};

    if (argc > 1)
    {
        g_self_level = atoi(argv[1]);
    }

    set_conio_terminal_mode();      // 设置终端模式
    atexit(reset_terminal_mode);    // 确保程序退出时终端模式被重置
    signal_process();

    if (pthread_create(&tcp_pt, NULL, tcp_msg_process_func, NULL) != 0)
    {
        return -1;
    }

    snprintf(g_hint_str, sizeof(g_hint_str), "电梯待机中...");

    while (1)
    {
        fprintf(stdout, "\rLevel: %2d | Direction: %s | %s   ", 
                        g_elevator_level, 
                        g_elevator_direction, 
                        g_hint_str);
        fflush(stdout);

        if (keyboard_hit() != 0)
        {
            button = getch();
            if (27 == button)   // 检测到ESC，可能是方向键前缀
            {
                button = getch();
                if (91 == button)   // 确认是'['，是方向键序列
                {
                    button = getch();
                    switch (button)
                    {
                    case 'A':   // 方向上.
                        snprintf(tcp_msg, sizeof(tcp_msg), "UP");

                        if (g_client_fd > 0)
                        {
                            if (tcp_client_send_msg(g_client_fd, tcp_msg, strlen(tcp_msg)) < 0)
                            {
                                printf("tcp client send msg failed\n");
                            }
                        }
                        break;
                    case 'B':   // 方向下.
                        snprintf(tcp_msg, sizeof(tcp_msg), "DOWN");

                        if (g_client_fd > 0)
                        {
                            if (tcp_client_send_msg(g_client_fd, tcp_msg, strlen(tcp_msg)) < 0)
                            {
                                printf("tcp client send msg failed\n");
                            }
                        }
                        break;
                    case 'C':   // 方向右.
                        break;
                    case 'D':   // 方向左.
                        break;
                    default:
                        break;
                    }
                }
            }
        }

        usleep(50000);
    }

    reset_terminal_mode();
    return -1;
}
