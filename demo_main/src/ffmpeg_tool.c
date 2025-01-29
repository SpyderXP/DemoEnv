/******************************************************************************
  *  文件名     : ffmpeg_tool.c
  *  负责人     : xupeng
  *  创建日期   : 20250118
  *  版本号     : v1.1 
  *  文件描述   : FFMPEG工具.
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
#include "logger.h"
#include "common_macro.h"

void test_func(void)
{
    char cpu_md5[33] = {0};
    char cpld_md5[33] = {0};
    char wstring[64] = {0};
    int fd = -1;
    int offset = 0;
    mode_t old_mask = 0;

    snprintf(cpu_md5, sizeof(cpu_md5), "11111111111111111111111111111111");
    snprintf(cpld_md5, sizeof(cpld_md5), "22222222222222222222222222222222");

    old_mask = umask(0000);     /* 修改默认 umask，并保存旧的umask值 */
    fd = open("./all.md5", O_RDWR | O_CREAT, (mode_t)0666);
    umask(old_mask);            /* 还原umask值 */
    if (fd < 0)
    {
        APP_LOG_ERROR("fd open failed");
        return ;
    }

    /* 写CPU MD5 */
    snprintf(wstring, sizeof(wstring), "CPU\t%s\n", cpu_md5);
    write(fd, wstring, sizeof(wstring));
    offset += sizeof(wstring);

    /* 写CPLD MD5 */
    lseek(fd, offset, SEEK_SET);
    snprintf(wstring, sizeof(wstring), "CPLD\t%s\n", cpld_md5);
    write(fd, wstring, sizeof(wstring));
    offset += sizeof(wstring);

    close(fd);
    fd = -1;
    return ;
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
    // if (init_logger("./etc/ffmpeg_tool_logconf.json", "ffmpeg_tool") != 0)
    if (init_logger(NULL, NULL) != 0) 
    {
        fprintf(stdout, "Init logger failed\n");
        return -1;
    }

    test_func();

    // wait for thread.
    // while (1)
    // {
    //     sleep(1);
    // }

    destroy_logger();
    return 0;
}
