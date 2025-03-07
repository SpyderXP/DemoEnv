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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "logger.h"
#include "common_macro.h"

/* 预定义的关键字列表 */
const char *g_compl_keywords[] = 
{
    "exit", "help", "print", "admin", "save", "load", "quit", "user", "test"
};

/* 关键字数量 */
int g_compl_list_cnt = sizeof(g_compl_keywords) / sizeof(char *);

/* 补全关键字索引号 */
int g_compl_list_index = 0;

/* 补全关键字长度 */
int g_compl_strlen = 0;

/* 命令行提示字符串 */
char g_command_hint[64] = {0};

int g_command_argc = 0;

char **g_command_argv = NULL;

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250228
*  函数功能  : Ctrl C SIGINT 信号处理函数.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void handle_sigint(int sig)
{
    printf("\n%s", g_command_hint);
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250228
*  函数功能  : 信号绑定函数.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int signal_process(void)
{
    struct sigaction sa = {0};

    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        APP_LOG_ERROR("sigaction failed");
        return -1;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250228
*  函数功能  : 辅助函数：生成可能的匹配项.
*  输入参数  : text - 输入的字符串.
*             state - 调用状态.
*  输出参数  : 无.
*  返回值    : 匹配的字符串.
*************************************************************************/
char *possible_matches(const char *text, int state)
{
    const char *name = NULL;

    /* 在第一次调用时初始化 */
    if (0 == state)
    {
        g_compl_list_index = 0;
        g_compl_strlen = strlen(text);
    }

    /* 遍历预定义的关键字列表 */
    while ((name = g_compl_keywords[g_compl_list_index++]))
    {
        if (0 == strncmp(name, text, g_compl_strlen))
        {
            if (0 == g_compl_strlen)  /* 避免选择默认关键字 */
            {
                break;
            }

            /* 返回匹配项的副本，由readline库free */
            return strdup(name);
        }

        if (g_compl_list_index >= g_compl_list_cnt)
        {
            break;
        }
    }

    return NULL;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250228
*  函数功能  : 补全函数.
*  输入参数  : text - 输入的字符串.
*             start - 文本字符串起始索引.
*             end - 文本字符串结束索引.
*  输出参数  : 无.
*  返回值    : 匹配回调.
*************************************************************************/
char **command_completer(const char *text, int start, int end)
{
    /* 禁止后续自动添加空格 */
    // rl_attempted_completion_over = 1; 
    rl_completion_append_character = '\0';
    return rl_completion_matches(text, possible_matches);
}

// 解析输入行，分割成以空格分隔的参数
int split_line(char* line)
{
    char *token = NULL;

    if (line == NULL || strlen(line) == 0)
    {
        return -1;
    }

    g_command_argc = 0;

    token = strtok(line, " ");
    while (token != NULL)
    {
        if (g_command_argc >= 63)
        {
            break;
        }

        g_command_argv[g_command_argc] = strdup(token);
        g_command_argc++;
        token = strtok(NULL, " ");
    }

    g_command_argv[g_command_argc] = NULL;
    return 0;
}

int command_parameter_process(int argc, char **argv)
{
    int level = 0;
    char username[32] = {0};

    if (0 == argc)
    {
        return 0;
    }

    if (0 == strcmp(argv[0], "admin"))
    {
        level = 2;
    }

    if (0 == strcmp(argv[0], "user") && argc > 1)
    {
        snprintf(username, sizeof(username), "%s", argv[1]);
        level = 1;
    }

    if (0 == strcmp(argv[0], "exit") && level > 0)
    {
        level--;
    }

    if (0 == strcmp(argv[0], "quit"))
    {
        exit(0);
    }

    switch (level)
    {
    case 2:
        snprintf(username, sizeof(username), "Admin");
        break;

    case 1:
    case 0:
    default:
        break;
    }

    snprintf(g_command_hint, sizeof(g_command_hint), "%s> ", username);
    return 0;
}

void command_process_loop(void)
{
    char *line = NULL;

    g_command_argv = calloc(1, 64 * sizeof(char*));
    if (!g_command_argv)
    {
        APP_LOG_ERROR("calloc failed");
        return ;
    }

    /* 历史命令使能 */
    using_history();

    /* 设置自动补全回调 */
    rl_attempted_completion_function = command_completer;

    for (int i = 0; i < g_compl_list_cnt; i++)
    {
        printf("[%d] %p\n", i, g_compl_keywords[i]);
    }

    snprintf(g_command_hint, sizeof(g_command_hint), "> ");
    while ((line = readline(g_command_hint)) != NULL)
    {
        if (strlen(line) > 0)
        {
            add_history(line);  /* 添加到历史记录 */
        }

        split_line(line);

        command_parameter_process(g_command_argc, g_command_argv);

        free(line);
        line = NULL;
    }
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
    // char *log_conf_file = "./etc/tool_center_logconf.json";

    if (init_logger(NULL, NULL) != 0) 
    {
        fprintf(stdout, "Init logger failed\n");
        return -1;
    }

    signal_process();

    command_process_loop();

    // wait for thread.
    while (1)
    {
        sleep(1);
    }

    destroy_logger();
    return 0;
}
