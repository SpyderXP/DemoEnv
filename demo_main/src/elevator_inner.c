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

/* 目的所在楼层 */
int16_t g_target_level = 1;

/* 当前电梯所在楼层（内外面板使用） */
int16_t g_elevator_level = 1;

/* 电梯当前运行方向（内外面板使用） */
char g_elevator_direction[8] = "-";

/* 当前电梯距离地面高度（地面指1楼地面） */
int g_elevator_height = 0.0;

/* 电梯移动标记 */
bool g_move_flag = false;

char g_hint_str[512] = {0};

struct termios orig_termios;

typedef struct BUILDING_PARA_S
{
    int16_t level;
    int height;
    bool flag;  /* false-未按下 true-已按下 */
} BUILDING_PARA_T;

/* 做成配置文件 */
BUILDING_PARA_T building_height[] = 
{
    {-2, -100}, 
    {-1, -50}, 
    {1, 0}, 
    {2, 40}, 
    {3, 80}, 
    {4, 120}, 
    {5, 160}, 
    {6, 200}
};

int g_client_fd_num = 0;
int *g_client_fd_set = NULL;
int g_server_fd = 0;

int remove_obj_from_fdset(int *fd_set, int fd_num, int target)
{
    for (int i = 0; i < fd_num; i++)
    {
        if (target == fd_set[i])
        {
            fd_set[i] = fd_set[fd_num - 1];
            fd_num--;
            break;
        }
    }

    close(target);
    return fd_num;
}

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
    int ret = 0;
    char tcp_msg[512] = {0};

    while (1)
    {
        for (int i = 0; i < g_client_fd_num; i++)
        {
            ret = tcp_server_msg_recv(g_client_fd_set[i], tcp_msg, sizeof(tcp_msg));
            if (ret <= 0)
            {
                g_client_fd_num = remove_obj_from_fdset(g_client_fd_set, g_client_fd_num, g_client_fd_set[i]);
            }

            printf("recv tcp: %s\n", tcp_msg);
        }

        usleep(50000);
    }

    return NULL;
}

void *tcp_listen_func(void *para)
{
    int client_fd = 0;

    g_server_fd = tcp_server_init(8081, 128);
    if (g_server_fd < 0)
    {
        fprintf(stdout, "tcp server init failed\n");
        return NULL;
    }

    g_client_fd_set = calloc(1, 128 * sizeof(int));
    if (NULL == g_client_fd_set)
    {
        return NULL;
    }

    while (1)
    {
        client_fd = tcp_server_accept(g_server_fd);
        if (client_fd > 0)
        {
            g_client_fd_set[g_client_fd_num++] = client_fd;
        }

        usleep(50000);
    }

    return NULL;
}

void *button_monitor_func(void *para)
{
    /* 检测命令行输入，更新up/down button */
    int button = 0;
    int level = 0;

    while (1)
    {
        if (keyboard_hit() != 0)
        {
            button = getch();
            if (button > '0' && button <= '9')
            {
                level = button - '0';
                button = getch();
                if (button >= '0' && button <= '9')
                {
                    level = level * 10 + (button - '0');
                    button = getch();
                    if (button >= '0' && button <= '9')
                    {
                        g_target_level = level * 10 + (button - '0');
                    }
                    else 
                    {
                        g_target_level = level;
                    }
                }
                else 
                {
                    g_target_level = level;
                }

                g_move_flag = true;
            }
            else if ('-' == button)
            {
                button = getch();
                if (button >= '0' && button <= '9')
                {
                    g_target_level = -1 * (button - '0');
                    g_move_flag = true;
                }
            }
        }

        usleep(50000);
    }

    return NULL;
}

int get_level_by_height(int height)
{
    for (int i = 0; i < sizeof(building_height) / sizeof(BUILDING_PARA_T); i++)
    {
        if (building_height[i].height == height)
        {
            return building_height[i].level;
        }
    }

    return 0;
}

int send_elevator_move_cmd(int16_t target)
{
    int ret = 0;

    if (0 == strcmp(g_elevator_direction, "↑"))
    {
        snprintf(g_hint_str, sizeof(g_hint_str), "电梯上升中...");
        g_elevator_height++;

        if ((ret = get_level_by_height(g_elevator_height)) != 0)
        {
            g_elevator_level = ret;
        }

        if (g_elevator_level == target)
        {
            snprintf(g_elevator_direction, sizeof(g_elevator_direction), "-");
            snprintf(g_hint_str, sizeof(g_hint_str), "已到达目的楼层");
        }
    }
    else if (0 == strcmp(g_elevator_direction, "↓"))
    {
        snprintf(g_hint_str, sizeof(g_hint_str), "电梯下降中...");
        g_elevator_height--;

        if ((ret = get_level_by_height(g_elevator_height)) != 0)
        {
            g_elevator_level = ret;
        }

        if (g_elevator_level == target)
        {
            snprintf(g_elevator_direction, sizeof(g_elevator_direction), "-");
            snprintf(g_hint_str, sizeof(g_hint_str), "已到达目的楼层");
        }
    }

    return 0;
}

void handle_sigint(int sig)
{
    exit(EXIT_SUCCESS);
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
    pthread_t button_monitor_pt = 0;
    pthread_t tcp_listen_pt = 0;
    pthread_t tcp_msg_process_pt = 0;

    if (argc > 1)
    {
        g_target_level = atoi(argv[1]);
    }

    set_conio_terminal_mode();      // 设置终端模式
    atexit(reset_terminal_mode);    // 确保程序退出时终端模式被重置
    signal_process();

    if (pthread_create(&button_monitor_pt, NULL, button_monitor_func, NULL) != 0)
    {
        return -1;
    }

    if (pthread_create(&tcp_listen_pt, NULL, tcp_listen_func, NULL) != 0)
    {
        return -1;
    }

    if (pthread_create(&tcp_msg_process_pt, NULL, tcp_msg_process_func, NULL) != 0)
    {
        return -1;
    }

    snprintf(g_hint_str, sizeof(g_hint_str), "电梯待机中...");

    while (1)
    {
        fprintf(stdout, "\rLevel: %2d | Direction: %s | Height: %lfm | %s   ", 
                        g_elevator_level, 
                        g_elevator_direction, 
                        (double)g_elevator_height / 10.0, 
                        g_hint_str);
        fflush(stdout);

        if (g_target_level > g_elevator_level)
        {
            if (g_move_flag)
            {
                snprintf(g_elevator_direction, sizeof(g_elevator_direction), "↑");
                send_elevator_move_cmd(g_target_level);
            }
            else 
            {
                snprintf(g_elevator_direction, sizeof(g_elevator_direction), "-");
            }
        }
        else if (g_target_level < g_elevator_level)
        {
            if (g_move_flag)
            {
                snprintf(g_elevator_direction, sizeof(g_elevator_direction), "↓");
                send_elevator_move_cmd(g_target_level);
            }
            else 
            {
                snprintf(g_elevator_direction, sizeof(g_elevator_direction), "-");
            }
        }
        else 
        {
            snprintf(g_elevator_direction, sizeof(g_elevator_direction), "-");

            if (true == g_move_flag)
            {
                g_move_flag = false;
            }

        }


        // g_elevator_level = calc_current_elevator_level_by_height(g_elevator_direction, g_elevator_height);



        usleep(50000);
    }

    reset_terminal_mode();
    return -1;
}
