/******************************************************************************
  *  文件名     : logger.c
  *  负责人     : xupeng
  *  创建日期   : 20201203
  *  版本号     : v1.1 
  *  文件描述   : 通用日志模块.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <execinfo.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <dirent.h>
#include "logger.h"
#include "common_macro.h"

#define gettid()                        syscall(SYS_gettid)
#define NONE_COLOR_LOG                  "\033[0m"
#define RED_COLOR_LOG                   "\033[1;31m"
#define YELLOW_COLOR_LOG                "\033[1;33m"
#define LIGHT_CYAN_COLOR_LOG            "\033[1;36m"
#define LIGHT_GREEN_COLOR_LOG           "\033[1;32m"

#define MAX_QUEUE_SIZE                  32
#define MAX_QUEUE_NUM                   8
#define BACKTRACE_SIZE                  32
#define FILEPATH_SIZE                   128
#define FILENAME_SIZE                   32
#define LOGNAME_SIZE                    64
#define FULLNAME_SIZE                   256
#define DIR_STR_SIZE                    (128 + 256)
#define MOD_NAME_SIZE                   16
#define FUNC_NAME_SIZE                  64
#define LOGLEVEL_NUM                    8
#define LOGLEVEL_SIZE                   16
#define TIMESTAMP_SIZE                  32
#define PREFIX_BUFSIZE                  512
#define SUFFIX_BUFSIZE                  2048
#define CMD_SIZE                        1024
#define LOGFILE_SIZE                    5
#define MBYTES_SIZE                     (1024 * 1024)

enum QUEUE_STATE_E
{
    EMPTY_QUEUE = 0,
    FREE_QUEUE,
    FULL_QUEUE
};

typedef struct LOG_CONF_ITEM_S
{
    char level[LOGLEVEL_SIZE];
    char log_file_path[FILEPATH_SIZE];
    char log_name[LOGNAME_SIZE];
    char errlog_name[LOGNAME_SIZE];
    uint8_t log_switch;
    uint8_t debug_switch;
    uint16_t log_maxlen;
    uint32_t single_file_size_mb;
    uint32_t directory_size_mb;
} LOG_CONF_ITEM_T;

typedef struct LOG_DATA_S
{
    uint8_t mode;
    uint8_t level;
    char *buf;                      /* 日志内容 */
    char logname[FILENAME_SIZE];    /* 输出的日志文件名 */
} LOG_DATA_T;

typedef struct QUEUE_NODE_S
{
    LOG_DATA_T *data;
    int head;                       /* 队头索引 */
    int tail;                       /* 队尾索引 */
    int status;                     /* 队列是否已满 */
} QUEUE_NODE_T;

typedef struct LOG_PREFIX_S
{
    uint8_t level;
    uint8_t out_mode;
    uint16_t line;
    pid_t pid;
    pid_t tid;
    char time_buf[TIMESTAMP_SIZE];
    char file[FILEPATH_SIZE];
    char module[MOD_NAME_SIZE];
    char function[FUNC_NAME_SIZE];
} LOG_PREFIX_T;

typedef struct LINK_QUEUE_S
{
    QUEUE_NODE_T *queue;
    struct LINK_QUEUE_S *next;
} LINK_QUEUE_T;

typedef struct 
{
    bool main_loop;
    pthread_rwlock_t lock;
} MAIN_LOOP_FLAG_T;

/* LOG LEVEL String */
static char s_loglevel_str[LOGLEVEL_NUM][LOGLEVEL_SIZE] = 
{
    "EMERG",
    "ALERT",
    "CRIT",
    "ERROR",
    "WARN",
    "NOTICE",
    "INFO",
    "DEBUG",
};

static LOG_CONF_ITEM_T s_log_conf_item;             /* LOG CONFIGURATION ITEM */
static int s_def_level = 0;                         /* LOG LEVEL NUM */
static char s_log_path[FULLNAME_SIZE] = {0};        /* LOG ABSOLUTE PATH */
static char s_sublog_path[FULLNAME_SIZE] = {0};     /* SUBLOG ABSOLUTE PATH */
static char s_errlog_path[FULLNAME_SIZE] = {0};     /* ERROR LOG ABSOLUTE PATH */
static pthread_spinlock_t s_link_queue_lock;        /* LOG LINK QUEUE LOCK */
static pthread_spinlock_t s_input_lock;             /* INPUT LOG LOCK */

static pid_t s_process_id = 0;                      /* Caller process ID */
static pthread_t s_async_pt = 0;                    /* ASYNC PROCESS THREAD */
static pthread_t s_statis_pt = 0;                   /* STATISTICS PROCESS THREAD */
static LOG_DATA_T s_async_tmp_node;                 /* ASYNC QUEUE TMP NODE */
static LINK_QUEUE_T *s_link_queue = NULL;           /* ASYNC LOG LINK QUEUE */
static LINK_QUEUE_T *s_producer_ptr = NULL;         /* PRODUCER QUEUE POINTER */
static LINK_QUEUE_T *s_consumer_ptr = NULL;         /* CONSUMER QUEUE POINTER */
static int s_queue_cnt = 0;                         /* QUEUE NUMBER COUNT */

static char *s_err_log_buf = NULL;                  /* GLOBAL ERROR LOG BUFFER */
static uint32_t s_err_log_buflen = 0;               /* GLOBAL ERROR LOG BUFFER DATA LENGTH */
static char *s_file_log_buf = NULL;                 /* GLOBAL FILE LOG BUFFER */
static uint32_t s_file_log_buflen = 0;              /* GLOBAL FILE LOG BUFFER DATA LENGTH */
static char *s_qnode_databuf[MAX_QUEUE_NUM] = {0};  /* ASYNC QUEUE NODE DATA BUFFER */
static char *s_color_buf = NULL;                    /* COLORFUL LOG */
static char *s_byte_log_buff = NULL;                /* BYTE LOG BUFFER */
static char *s_suffix_log_buff = NULL;              /* LOG SUFFIX BUFFER */
static char *s_whole_log_buff = NULL;               /* LOG PREFIX + SUFFIX BUFFER */

// static char *s_log_io_buf1 = NULL;                  /* LOG IO BUFFER BLOCK 1 */
// static char *s_log_io_buf2 = NULL;                  /* LOG IO BUFFER BLOCK 2 */
// static char *s_read_bufptr = NULL;                  /* READ BUFFER POINTER */
// static char *s_write_bufptr = NULL;                 /* WRITE BUFFER POINTER */

static char s_system_cmdstr[CMD_SIZE] = {0};        /* 系统命令行字符串 */
static MAIN_LOOP_FLAG_T s_loop_flag;                /* 控制主流程循环 */

int wrt_all_log(const char *log_buff, uint8_t out_mode, uint8_t level, const char *logname);
QUEUE_NODE_T *init_log_queue(unsigned max_queue_size);
int destroy_log_queue(QUEUE_NODE_T **queue);
int file_log_flush(char *log_path);
int err_log_flush(char *log_path);

/************************************************************************* 
*  负责人    :  xupeng
*  创建日期  : 20210322
*  函数功能  : 获取档案变更flag.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 主逻辑循环标志.
*************************************************************************/
bool get_loop_flag(void)
{
    bool ret = false;

    pthread_rwlock_rdlock(&s_loop_flag.lock);
    ret = s_loop_flag.main_loop;
    pthread_rwlock_unlock(&s_loop_flag.lock);
    return ret;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210322
*  函数功能  : 设定档案变更flag.
*  输入参数  : flag - 设定的布尔值.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void set_loop_flag(bool flag)
{
    pthread_rwlock_wrlock(&s_loop_flag.lock);
    s_loop_flag.main_loop = flag;
    pthread_rwlock_unlock(&s_loop_flag.lock);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210528
*  函数功能  : 主循环标志初始化.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int init_loop_flag(void)
{
    CHECK_CONDITION_WITH_RET(pthread_rwlock_init(&s_loop_flag.lock, NULL) != 0, -1);
    set_loop_flag(true);
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210528
*  函数功能  : 主循环标志销毁.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void destroy_loop_flag(void)
{
    set_loop_flag(false);
    pthread_rwlock_destroy(&s_loop_flag.lock);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 清理日志库中用到的一些数据缓冲.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void clean_logger_buffer(void)
{
    FREE_VARIATE_WITH_FUNC(s_file_log_buf, free);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 日志链队初始化.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 日志链队.
*************************************************************************/
LINK_QUEUE_T *init_logger_link_queue(void)
{
    LINK_QUEUE_T *head = NULL;

    head = (LINK_QUEUE_T *)calloc(1, sizeof(LINK_QUEUE_T));
    if (NULL == head)
    {
        return NULL;
    }

    head->queue = init_log_queue(MAX_QUEUE_SIZE);
    if (NULL == head->queue)
    {
        free(head);
        head = NULL;
        return NULL;
    }

    head->next = head;
    s_producer_ptr = head;
    s_consumer_ptr = head;
    s_queue_cnt = 1;

    /* 初始化互斥锁 */
    if (pthread_spin_init(&s_link_queue_lock, PTHREAD_PROCESS_PRIVATE) != 0)
    {
        if (head->queue != NULL)
        {
            destroy_log_queue(&head->queue);
        }
        free(head);
        head = NULL;
        return NULL;
    }

    return head;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 销毁日志链队.
*  输入参数  : 日志链队任意节点.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void destroy_logger_link_queue(LINK_QUEUE_T *head)
{
    LINK_QUEUE_T *tmp_node = NULL;
    LINK_QUEUE_T *head_node = NULL;

    CHECK_NULL_1PARAM_WITHOUT_RET(head);

    head_node = head;

    while (head_node->next != NULL && head_node != head_node->next)
    {
        tmp_node = head_node->next;
        head_node->next = head_node->next->next;
        if (tmp_node->queue != NULL)
        {
            destroy_log_queue(&tmp_node->queue);
        }
        tmp_node->next = NULL;
        free(tmp_node);
        tmp_node = NULL;
    }

    if (head_node->queue != NULL)
    {
        destroy_log_queue(&head_node->queue);
    }
    head_node->next = NULL;
    free(head_node);
    head_node = NULL;

    s_queue_cnt = 0;

    /* 销毁互斥锁 */
    pthread_spin_destroy(&s_link_queue_lock);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 创建新的日志链队节点.
*  输入参数  : 待创建新节点的前置节点.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int create_new_log_link_node(LINK_QUEUE_T *node)
{
    LINK_QUEUE_T *new_node = NULL;
    LINK_QUEUE_T *tmp_node = NULL;

    CHECK_NULL_1PARAM_WITH_RET(node, -1);

    new_node = (LINK_QUEUE_T *)calloc(1, sizeof(LINK_QUEUE_T));
    if (NULL == new_node)
    {
        return -1;
    }

    new_node->queue = init_log_queue(MAX_QUEUE_SIZE);
    if (NULL == new_node->queue)
    {
        free(new_node);
        new_node = NULL;
        return -1;
    }

    tmp_node = node->next;
    node->next = new_node;
    new_node->next = tmp_node;
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 初始化异步日志队列.
*  输入参数  : queue - 异步日志队列.
*             max_queue_size - 最大队列长度.
*  输出参数  : 无.
*  返回值    : -1 - 失败.
*************************************************************************/
QUEUE_NODE_T *init_log_queue(unsigned max_queue_size)
{
    QUEUE_NODE_T *queue = NULL;

    queue = (QUEUE_NODE_T *)calloc(1, sizeof(QUEUE_NODE_T));
    if (NULL == queue)
    {
        return NULL;
    }

    queue->data = (LOG_DATA_T *)calloc(max_queue_size, sizeof(LOG_DATA_T));
    if (NULL == queue->data)
    {
        free(queue);
        queue = NULL;
        return NULL;
    }

    s_qnode_databuf[s_queue_cnt] = 
        (char *)calloc(max_queue_size * s_log_conf_item.log_maxlen, sizeof(char));
    if (NULL == s_qnode_databuf[s_queue_cnt])
    {
        free(queue->data);
        queue->data = NULL;
        free(queue);
        queue = NULL;
        return NULL;
    }

    for (int i = 0; i < max_queue_size; i++)
    {
        queue->data[i].buf = s_qnode_databuf[s_queue_cnt] + i *s_log_conf_item.log_maxlen;
    }

    queue->tail = 0;
    queue->head = 0;
    queue->status = EMPTY_QUEUE;
    return queue;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 销毁异步日志队列.
*  输入参数  : queue - 异步日志队列.
*  输出参数  : 无.
*  返回值    : -1 - 失败.
*************************************************************************/
int destroy_log_queue(QUEUE_NODE_T **queue)
{
    CHECK_NULL_2PARAM_WITH_RET(queue, *queue, -1);

    for (int i = 0; i < MAX_QUEUE_NUM; i++)
    {
        if (s_qnode_databuf[i] != NULL)
        {
            free(s_qnode_databuf[i]);
            s_qnode_databuf[i] = NULL;
        }
    }

    if ((*queue)->data != NULL)
    {
        free((*queue)->data);
        (*queue)->data = NULL;
    }

    (*queue)->head = 0;
    (*queue)->tail = 0;
    (*queue)->status = EMPTY_QUEUE;

    free(*queue);
    *queue = NULL;
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 队列判满.
*  输入参数  : queue - 异步日志队列.
*             max_queue_size - 最大队列长度.
*  输出参数  : 无.
*  返回值    : 0 - 满  1 - 未满.
*************************************************************************/
int log_queue_is_full(QUEUE_NODE_T *queue, unsigned max_queue_size)
{
    CHECK_NULL_1PARAM_WITH_RET(queue, -1);

    if ((queue->tail + 1) % max_queue_size == queue->head)
    {
        return 0;
    }
    else 
    {
        return 1;
    }
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 队列判空.
*  输入参数  : queue - 异步日志队列.
*  输出参数  : 无.
*  返回值    : 0 - 空  1 - 非空.
*************************************************************************/
int log_queue_is_empty(QUEUE_NODE_T *queue)
{
    // CHECK_NULL_1PARAM_WITH_RET(queue, -1);

    if (queue->head == queue->tail)
    {
        return 0;
    }
    else 
    {
        return 1;
    }
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 入队.
*  输入参数  : queue - 异步日志队列.
*             max_queue_size - 最大队列长度.
*             data - 待入队节点信息.
*  输出参数  : 无.
*  返回值    : -1 - 失败.
*************************************************************************/
int log_enqueue(QUEUE_NODE_T *queue, unsigned max_queue_size, const LOG_DATA_T *data)
{
    // CHECK_NULL_2PARAM_WITH_RET(queue, data, -1);

    if (queue->status == FULL_QUEUE)
    {
        fprintf(stderr, "RING QUEUE is FULL, enqueue failed\n");
        return -1;
    }

    // CHECK_NULL_1PARAM_WITH_RET(data->buf, -1);
    CHECK_NULL_2PARAM_WITH_RET(queue->data, queue->data[queue->tail].buf, -1);

    snprintf(queue->data[queue->tail].buf, s_log_conf_item.log_maxlen, "%s", data->buf);
    memcpy(queue->data[queue->tail].logname, data->logname, FILENAME_SIZE);
    queue->data[queue->tail].logname[FILENAME_SIZE - 1] = '\0';
    queue->data[queue->tail].mode = data->mode;
    queue->data[queue->tail].level = data->level;

    queue->tail = (queue->tail + 1) % max_queue_size;
    queue->status = FREE_QUEUE;

    if (log_queue_is_full(queue, max_queue_size) == 0)
    {
        queue->status = FULL_QUEUE;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 出队.
*  输入参数  : queue - 异步日志队列.
*             max_queue_size - 最大队列长度.
*  输出参数  : node - 出队节点信息.
*  返回值    : -1 - 失败.
*************************************************************************/
int log_dequeue(QUEUE_NODE_T *queue, unsigned max_queue_size, LOG_DATA_T *data)
{
    // CHECK_NULL_2PARAM_WITH_RET(queue, data, -1);

    if (queue->status == EMPTY_QUEUE)
    {
        fprintf(stderr, "RING QUEUE is empty, dequeue failed\n");
        return -1;
    }

    // CHECK_NULL_1PARAM_WITH_RET(data->buf, -1);
    CHECK_NULL_1PARAM_WITH_RET(queue->data, -1);

    snprintf(data->buf, s_log_conf_item.log_maxlen, "%s", queue->data[queue->head].buf);
    memcpy(data->logname, queue->data[queue->head].logname, FILENAME_SIZE);
    data->logname[FILENAME_SIZE - 1] = '\0';
    data->mode = queue->data[queue->head].mode;
    data->level = queue->data[queue->head].level;

    queue->head = (queue->head + 1) % max_queue_size;
    queue->status = FREE_QUEUE;

    if (log_queue_is_empty(queue) == 0)
    {
        queue->status = EMPTY_QUEUE;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 日志模块自定义system接口(避免线程不安全).
*  输入参数  : cmd - 命令行内容.
*  输出参数  : 无.
*  返回值    : -1 - 失败.
*************************************************************************/
int logger_system(const char *cmd)
{
    FILE *fp = NULL;
    int res = 0;

    CHECK_NULL_1PARAM_WITH_RET(cmd, -1);

    fp = popen(cmd, "r");
    if (NULL == fp)
    {
        return -1;
    }

    res = pclose(fp);
    return res;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210622
*  函数功能  : 日志模块自定义usleep接口.
*  输入参数  : usleep_us - 指定的睡眠微秒数.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void logger_usleep(int usleep_us)
{
    struct timespec slptm = {0};
    int slp_us = 0;
    int slp_sec = 0;

    CHECK_CONDITION_WITHOUT_RET(usleep_us <= 0);

    slp_sec = usleep_us / 1000000;
    slp_us = usleep_us % 1000000;

    slptm.tv_sec = slp_sec;
    slptm.tv_nsec = slp_us * 1000;

    nanosleep(&slptm, NULL);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210425
*  函数功能  : 设定日志等级.
*  输入参数  : log_level - 指定的日志等级(枚举).
*                           LOG_EMERG	0.
*                           LOG_ALERT	1.
*                           LOG_CRIT	2.
*                           LOG_ERR		3.
*                           LOG_WARNING	4.
*                           LOG_NOTICE	5.
*                           LOG_INFO	6.
*                           LOG_DEBUG	7.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void set_log_level(int log_level)
{
    if (log_level < LOG_EMERG || log_level > LOG_DEBUG)
    {
        s_def_level = LOG_DEBUG;    /* 默认按照DEBUG级别打印所有日志 */
        return;
    }

    s_def_level = log_level;
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210425
*  函数功能  : 设定日志等级.
*  输入参数  : log_level - 指定的日志等级.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void set_log_level_str(char *log_level)
{
    int i = 0;

    if (NULL == log_level)
    {
        s_def_level = LOG_DEBUG;    /* 默认按照DEBUG级别打印所有日志 */
        return;
    }

    for (i = 0; i < (int)(sizeof(s_loglevel_str) / sizeof(s_loglevel_str[0])); i++)
    {
        if (0 == strcmp(log_level, s_loglevel_str[i]))
        {
            s_def_level = i;

            break;
        }
    }

    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 刷新日志.
*  输入参数  : logger - 日志文件指针.
*             len - 日志长度.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  调用关系  : 日志缓冲区满.
*************************************************************************/
int log_flush(FILE *logger, uint32_t len)
{
    CHECK_NULL_1PARAM_WITH_RET(logger, -1);
    CHECK_CONDITION_WITH_RET(EOF == fflush(logger), -1);
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201209
*  函数功能  : 主动立即刷新所有日志.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 配置文件控制.
*************************************************************************/
void manual_flush_log_buffer(void)
{
    if (file_log_flush(s_log_path) != 0)
    {
        // fprintf(stderr, "FILE LOG Flush Failed\n");
    }

    if (err_log_flush(s_errlog_path) != 0)
    {
        // fprintf(stderr, "ERROR LOG Flush Failed\n");
    }
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201209
*  函数功能  : 立即刷新所有日志（程序崩溃或主动停止后调用）.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 和程序关闭信号相关联.
*************************************************************************/
void flush_log_buffer(int signo)
{
    (void)signo;

    manual_flush_log_buffer();

    exit(EXIT_SUCCESS);
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 获取当前生成的日志文件时间信息.
*  输入参数  : 无.
*  输出参数  : time_buf - 时间信息.
*  返回值    : 无.
*************************************************************************/
void get_log_file_time(char *time_buf)
{
    struct tm       timenow     = {0};
    struct timeval  tv          = {0};
    time_t          time_now    = {0};

    CHECK_NULL_1PARAM_WITHOUT_RET(time_buf);

    time(&time_now);
    localtime_r(&time_now, &timenow);
    gettimeofday(&tv, NULL);

    snprintf(time_buf, TIMESTAMP_SIZE, "%04d%02d%02d-%02d:%02d:%02d", 
                    timenow.tm_year + 1900, timenow.tm_mon + 1, timenow.tm_mday,
                    timenow.tm_hour, timenow.tm_min, timenow.tm_sec);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 日志打包.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 日志文件大小超过限定值.
*  其它      : 将日志目录下所有log后缀的文件进行打包.
*************************************************************************/
int log_pack(void)
{
    char filename[DIR_STR_SIZE] = {0};
    uint16_t cmd_offset = 0;
    DIR *dp = NULL;
    struct dirent *stp = NULL;

    cmd_offset = snprintf(s_system_cmdstr, sizeof(s_system_cmdstr), "cd %s && tar -cvf %s.tar.gz", 
            s_log_conf_item.log_file_path, s_log_conf_item.log_name);
    cmd_offset += snprintf(s_system_cmdstr + cmd_offset, sizeof(s_system_cmdstr) - cmd_offset, " *.log");
    fprintf(stdout, "%s\n", s_system_cmdstr);

    if (-1 == logger_system(s_system_cmdstr))
    {
        fprintf(stdout, "logger_system() execute failed\n");
        return -1;
    }

    // 清除当前日志文件.
    CHECK_CONDITION_WITH_RET(NULL == (dp = opendir(s_log_conf_item.log_file_path)), -1);

    while ((stp = readdir(dp)) != NULL)
    {
        if (0 == strcmp(stp->d_name, ".") || 0 == strcmp(stp->d_name, ".."))
        {
            continue;
        }

        if (NULL == strstr(stp->d_name, ".log"))
        {
            continue;
        }

        snprintf(filename, sizeof(filename), "%s/%s", s_log_conf_item.log_file_path, stp->d_name);
        if (remove(filename) != 0)
        {
            fprintf(stdout, "remove file[%s] failed, with errno:  %d\n", filename, errno);
        }
    }

    closedir(dp);
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 日志归档.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 日志文件大小超过限定值.
*************************************************************************/
int log_backup(uint8_t log_backup_num, const char *logname)
{
    char    filename[FULLNAME_SIZE]     = {0};
    char    filename2[FULLNAME_SIZE]    = {0};

    if (NULL == logname)
    {
        return -1;
    }

    if (log_backup_num > 0)
    {
        for (int i = (int)log_backup_num - 1; i >= 0; i--)
        {
            snprintf(filename, sizeof(filename), "%s/%s.%d.log", s_log_conf_item.log_file_path, logname, i);
            snprintf(filename2, sizeof(filename2), "%s/%s.%d.log", s_log_conf_item.log_file_path, logname, i + 1);
            (void)rename(filename, filename2);
        }
    }

    snprintf(filename, sizeof(filename), "%s/%s.log", s_log_conf_item.log_file_path, logname);
    snprintf(filename2, sizeof(filename2), "%s/%s.0.log", s_log_conf_item.log_file_path, logname);
    (void)rename(filename, filename2);

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 检测日志大小，确定是否需要归档.
*  输入参数  : logname - 日志文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int detect_log_size(const char *logname)
{
    DIR *dp = NULL;
    struct dirent *stp = NULL;
    struct stat stat_buf = {0};
    uint8_t log_backup_num = 0;
    uint32_t directory_size = 0;
    uint32_t filesize = 0;
    char file_full_path[DIR_STR_SIZE] = {0};

    CHECK_NULL_1PARAM_WITH_RET(logname, -1);
    CHECK_CONDITION_WITH_RET(NULL == (dp = opendir(s_log_conf_item.log_file_path)), -1);

    while ((stp = readdir(dp)) != NULL)
    {
        if (0 == strcmp(stp->d_name, ".") || 0 == strcmp(stp->d_name, ".."))
        {
            continue;
        }

        if (strstr(stp->d_name, "tar.gz") != NULL)
        {
            continue;
        }

        // 累计目录下每一个日志文件的大小.
        snprintf(file_full_path, sizeof(file_full_path), "%s/%s", s_log_conf_item.log_file_path, stp->d_name);
        stat(file_full_path, &stat_buf);
        directory_size += stat_buf.st_size;

        // 1、确定当前日志大小  2、确定当前日志归档数.
        snprintf(file_full_path, sizeof(file_full_path), "%s.", logname);
        if (strstr(stp->d_name, file_full_path) != NULL)
        {
            snprintf(file_full_path, sizeof(file_full_path), "%s.log", logname);
            if (0 == strcmp(stp->d_name, file_full_path))
            {
                filesize = stat_buf.st_size;
            }
            else 
            {
                log_backup_num++;
            }
        }
    }

    closedir(dp);

    if (directory_size >= s_log_conf_item.directory_size_mb * MBYTES_SIZE)
    {
        log_pack();     // 目录下所有日志打包.
    }
    else if (filesize > s_log_conf_item.single_file_size_mb * MBYTES_SIZE)
    {
        log_backup(log_backup_num, logname);   // 当前日志归档.
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 屏幕输出backtrace日志.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 无法向ERROR日志输出backtrace日志时.
*************************************************************************/
void backtrace_to_screen(void)
{
    void    *buffer[BACKTRACE_SIZE]     = {0};
    char    **strings                   = NULL;
    size_t  size                        = 0;
    size_t  i                           = 0;

    size = backtrace(buffer, BACKTRACE_SIZE);

    fprintf(stdout, "Receive SIGSEGV, Obtained %zd stack frames.\n", size);

    strings = backtrace_symbols(buffer, size);

    if (NULL == strings)
    {
        fprintf(stdout, "backtrace_symbols() return NULL\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < size; i++)
    {
        fprintf(stdout, "------ %s\n", strings[i]);
    }

    FREE_VARIATE_WITH_FUNC(strings, free);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 输出backtrace调用栈日志到所有日志文件以及屏幕.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 成功打开ERROR日志后.
*************************************************************************/
void backtrace_to_buf(void)
{
    void    *buffer[BACKTRACE_SIZE]         = {0};
    char    **strings                       = NULL;
    char    text[CMD_SIZE]                  = {0};
    size_t  size                            = 0;
    size_t  i                               = 0;

    size = backtrace(buffer, BACKTRACE_SIZE);

    snprintf(text, sizeof(text), "Receive SIGSEGV, Obtained %zd stack frames.", size);
    wrt_all_log(text, FILE_AND_SCREEN, LOG_ERR, NULL);

    strings = backtrace_symbols(buffer, size);

    if (NULL == strings)
    {
        fprintf(stdout, "backtrace_symbols() return NULL\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < size; i++)
    {
        snprintf(text, sizeof(text), "------ %s", strings[i]);
        wrt_all_log(text, FILE_AND_SCREEN, LOG_ERR, NULL);
    }

    FREE_VARIATE_WITH_FUNC(strings, free);

    /* Flush buffer out before EXIT() */
    flush_log_buffer(0);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 捕捉收到SIGSEGV信号后的调用栈信息.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 进程收到SIGSEGV信号后.
*************************************************************************/
void print_backtrace(int signo)
{
    FILE *log_file_ptr                      = NULL;
    FILE *err_log_file_ptr                  = NULL;

    (void)signo;

    log_file_ptr = fopen(s_log_path, "a");
    err_log_file_ptr = fopen(s_errlog_path, "a");

    if (NULL == log_file_ptr && NULL == err_log_file_ptr)
    {
        /* Open file failed, Print to Screen. */
        fprintf(stderr, "logger.c[%d](logger):  %s errno:  %d\n", __LINE__, s_log_path, errno);

        backtrace_to_screen();

        exit(EXIT_SUCCESS);
    }

    backtrace_to_buf();

    FREE_VARIATE_WITH_FUNC(log_file_ptr, fclose);
    FREE_VARIATE_WITH_FUNC(err_log_file_ptr, fclose);
    exit(EXIT_SUCCESS);
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210426
*  函数功能  : 获取日志文件长度.
*  输入参数  : fp - 配置文件指针.
*  输出参数  : 无.
*  返回值    : 文件长度.
*************************************************************************/
long get_config_file_length(FILE *fp)
{
    long len = 0;

    CHECK_NULL_1PARAM_WITH_RET(fp, -1);

    fseek(fp, 0, SEEK_END);

    /* errno重置为0， 防止由于之前的错误误判ftell失败 */
    errno = 0;
    len = ftell(fp);
    if (errno != 0 && len == -1)
    {
        fprintf(stdout, "ftell() failed\n");
    }

    fseek(fp, 0, SEEK_SET);
    return len;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210426
*  函数功能  : 向日志配置项进行解析赋值.
*  输入参数  : object - 解析的JSON对象.
*  输出参数  : log_conf_item - 日志配置项.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int assign_conf_item(cJSON *object, LOG_CONF_ITEM_T *log_conf_item)
{
    cJSON *item = NULL;

    CHECK_NULL_2PARAM_WITH_RET(object, log_conf_item, -1);

    item = cJSON_GetObjectItemCaseSensitive(object, "level");
    if (item != NULL)
    {
        snprintf(log_conf_item->level, sizeof(log_conf_item->level), "%s", item->valuestring);
        set_log_level_str(log_conf_item->level);
    }

    item = cJSON_GetObjectItemCaseSensitive(object, "log_maxlen");
    if (item != NULL)
    {
        log_conf_item->log_maxlen = atoi(item->valuestring);
    }

    item = cJSON_GetObjectItemCaseSensitive(object, "switch");
    if (item != NULL)
    {
        log_conf_item->log_switch = atoi(item->valuestring);
    }

    item = cJSON_GetObjectItemCaseSensitive(object, "path");
    if (item != NULL)
    {
        snprintf(log_conf_item->log_file_path, sizeof(log_conf_item->log_file_path), "%s", item->valuestring);
    }

    item = cJSON_GetObjectItemCaseSensitive(object, "errlog_name");
    if (item != NULL)
    {
        snprintf(log_conf_item->errlog_name, sizeof(log_conf_item->errlog_name), "%s", item->valuestring);
    }

    item = cJSON_GetObjectItemCaseSensitive(object, "debug_switch");
    if (item != NULL)
    {
        log_conf_item->debug_switch = atoi(item->valuestring);
    }

    item = cJSON_GetObjectItemCaseSensitive(object, "name");
    if (item != NULL)
    {
        snprintf(log_conf_item->log_name, sizeof(log_conf_item->log_name), "%s", item->valuestring);
    }

    item = cJSON_GetObjectItemCaseSensitive(object, "single_file_size_mb");
    if (item != NULL)
    {
        log_conf_item->single_file_size_mb = atoi(item->valuestring);
    }

    item = cJSON_GetObjectItemCaseSensitive(object, "directory_size_mb");
    if (item != NULL)
    {
        log_conf_item->directory_size_mb = atoi(item->valuestring);
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210426
*  函数功能  : 解析JSON内容.
*  输入参数  : content - JSON内容字符串.
*  输出参数  : log_conf_item - 日志配置项.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int parse_conf_json_content(char *content, unsigned int content_len, LOG_CONF_ITEM_T *log_conf_item)
{
    cJSON *root = NULL;

    CHECK_NULL_2PARAM_WITH_RET(content, log_conf_item, -1);

    root = cJSON_ParseWithLength(content, content_len);
    if (cJSON_IsObject(root) == 0)
    {
        fprintf(stdout, "CJSON root data parse failed\n");
        return -1;
    }

    if (assign_conf_item(root, log_conf_item) != 0)
    {
        fprintf(stdout, "Assign CONF item failed\n");
    }

    FREE_VARIATE_WITH_FUNC(root, cJSON_Delete);
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 从日志配置文件读取配置信息.
*  输入参数  : config_file - 配置文件绝对路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  调用关系  : 初始化调用.
*************************************************************************/
int get_log_config(char *config_file)
{
    FILE    *fp                     = NULL;
    long    file_len                = 0;
    char    *file_content           = NULL;

    CHECK_NULL_1PARAM_WITH_RET(config_file, -1);

    fp = fopen(config_file, "r");
    if (NULL == fp)
    {
        fprintf(stdout, "logfile open failed:  %s\n", config_file);
        return -1;
    }

    file_len = get_config_file_length(fp);
    if (file_len <= 0)
    {
        fprintf(stdout, "logfile content error:  %s\n", config_file);
        fclose(fp);
        fp = NULL;
        return -1;
    }

    file_content = (char *)calloc(file_len + 1, sizeof(char));
    if (NULL == file_content)
    {
        fprintf(stdout, "calloc failed\n");
        fclose(fp);
        fp = NULL;
        return -1;
    }

    if (fread(file_content, sizeof(char), file_len, fp) != file_len)
    {
        fprintf(stdout, "fread log conf file failed\n");
        free(file_content);
        file_content = NULL;
        fclose(fp);
        fp = NULL;
        return -1;
    }

    fclose(fp);
    fp = NULL;

    if (parse_conf_json_content(file_content, file_len, &s_log_conf_item) != 0)
    {
        fprintf(stdout, "Parse LOG conf JSON file failed\n");
        free(file_content);
        file_content = NULL;
        return -1;
    }

    free(file_content);
    file_content = NULL;

    // fprintf(stdout, "level:  %s\n", s_loglevel_str[s_def_level]);
    // fprintf(stdout, "log_maxlen:  %u Bytes\n", s_log_conf_item.log_maxlen);
    // fprintf(stdout, "switch:  %u\n", s_log_conf_item.log_switch);
    // fprintf(stdout, "log path:  %s\n", s_log_conf_item.log_file_path);
    // fprintf(stdout, "log name:  %s\n", s_log_conf_item.log_name);
    // fprintf(stdout, "error log name:  %s\n", s_log_conf_item.errlog_name);
    // fprintf(stdout, "debug switch:  %u\n", s_log_conf_item.debug_switch);
    // fprintf(stdout, "single file size:  %u MB\n", s_log_conf_item.single_file_size_mb);
    // fprintf(stdout, "directory size:  %u MB\n", s_log_conf_item.directory_size_mb);

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 获取当前时间信息.
*  输入参数  : 无.
*  输出参数  : time_buf - 时间信息.
*  返回值    : 无.
*************************************************************************/
void get_log_time_buf(char *time_buf)
{
    struct tm       timenow     = {0};
    struct timeval  tv          = {0};
    time_t          time_now    = {0};

    CHECK_NULL_1PARAM_WITHOUT_RET(time_buf);

    time(&time_now);
    localtime_r(&time_now, &timenow);
    gettimeofday(&tv, NULL);

    snprintf(time_buf, TIMESTAMP_SIZE, "%04d%02d%02d %02d:%02d:%02d.%06ld", 
                    timenow.tm_year + 1900, timenow.tm_mon + 1, timenow.tm_mday,
                    timenow.tm_hour, timenow.tm_min, timenow.tm_sec,
                    tv.tv_usec);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 日志输出到文件.
*  输入参数  : log_file_ptr - 日志文件指针.
*             log_buff - 日志内容.
*  输出参数  : 0 - 成功  -1 - 失败  1 - 日志缓冲区已满.
*  返回值    : 无.
*  调用关系  : 日志调用指定宏ONLY_FILE.
*************************************************************************/
int print_log_only_file(FILE *log_file_ptr, const char *log_buff, uint8_t level)
{
    int res = -1;
    uint32_t len = 0;

    CHECK_NULL_2PARAM_WITH_RET(log_file_ptr, log_buff, -1);

    if (strlen(log_buff) + 7 >= LOG_BUF_SIZE - s_file_log_buflen)
    {
        res = fprintf(log_file_ptr, "%s", s_file_log_buf);
        if (res < 0)
        {
            return -1;
        }
        len = s_file_log_buflen;

        memset(s_file_log_buf, 0, LOG_BUF_SIZE);
        s_file_log_buflen = 0;

        snprintf(s_file_log_buf, LOG_BUF_SIZE, "%-6s %s\n", s_loglevel_str[level], log_buff);
        s_file_log_buflen = strlen(s_file_log_buf);

        /* FLUSH LOG */
        log_flush(log_file_ptr, len);
        return 1;
    }

    snprintf(s_file_log_buf + s_file_log_buflen, LOG_BUF_SIZE - s_file_log_buflen, "%-6s %s\n", 
        s_loglevel_str[level], log_buff);

    s_file_log_buflen = strlen(s_file_log_buf);

    if (s_file_log_buflen >= LOG_BUF_SIZE)
    {
        res = fprintf(log_file_ptr, "%s", s_file_log_buf);
        if (res < 0)
        {
            return -1;
        }
        len = s_file_log_buflen;

        snprintf(s_file_log_buf, LOG_BUF_SIZE, "%s\n", log_buff);

        s_file_log_buflen = strlen(s_file_log_buf);

        /* FLUSH LOG */
        log_flush(log_file_ptr, len);
        return 1;
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20220128
*  函数功能  : 打印彩色日志到屏幕.
*  输入参数  : log_buff - ERROR日志内容.
*             level - 日志等级.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void print_screen_color_log(const char *log_buff, uint8_t level)
{
    int offset = 0;

    CHECK_NULL_1PARAM_WITHOUT_RET(log_buff);

    // 暂时仅对警告与错误日志进行上色处理.
    switch (level)
    {
    case LOG_WARNING:  
        snprintf(s_color_buf, s_log_conf_item.log_maxlen, YELLOW_COLOR_LOG"%-6s %s"NONE_COLOR_LOG, 
            s_loglevel_str[level], log_buff);
        fprintf(stdout, "%s\n", s_color_buf);
        break;

    case LOG_ERR:  
    case LOG_CRIT: 
    case LOG_ALERT: 
    case LOG_EMERG: 
        snprintf(s_color_buf, s_log_conf_item.log_maxlen, RED_COLOR_LOG"%-6s %s"NONE_COLOR_LOG, 
            s_loglevel_str[level], log_buff);
        fprintf(stdout, "%s\n", s_color_buf);
        break;

    case LOG_INFO:  
        offset = snprintf(s_color_buf, s_log_conf_item.log_maxlen, LIGHT_GREEN_COLOR_LOG);
        if (s_log_conf_item.log_maxlen < offset)
        {
            break;
        }
        offset += snprintf(s_color_buf + offset, s_log_conf_item.log_maxlen - offset, "%-6s ", s_loglevel_str[level]);
        if (s_log_conf_item.log_maxlen < offset)
        {
            break;
        }
        snprintf(s_color_buf + offset, s_log_conf_item.log_maxlen - offset, NONE_COLOR_LOG"%s", log_buff);
        fprintf(stdout, "%s\n", s_color_buf);
        break;

    case LOG_DEBUG:  
        offset = snprintf(s_color_buf, s_log_conf_item.log_maxlen, LIGHT_CYAN_COLOR_LOG);
        if (s_log_conf_item.log_maxlen < offset)
        {
            break;
        }
        offset += snprintf(s_color_buf + offset, s_log_conf_item.log_maxlen - offset, "%-6s ", s_loglevel_str[level]);
        if (s_log_conf_item.log_maxlen < offset)
        {
            break;
        }
        snprintf(s_color_buf + offset, s_log_conf_item.log_maxlen - offset, NONE_COLOR_LOG"%s", log_buff);
        fprintf(stdout, "%s\n", s_color_buf);
        break;

    default: 
        fprintf(stdout, "%-6s %s\n", s_loglevel_str[level], log_buff);
        break;
    }

    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20220128
*  函数功能  : 输出程序总日志到缓冲区.
*  输入参数  : log_buff - 日志内容.
*             out_mode - 输出模式.
*             level - 日志等级.
*  输出参数  : 0 - 成功  -1 - 失败.
*  返回值    : 无.
*************************************************************************/
int write_chief_log_to_buffer(const char *log_buff, uint8_t out_mode, uint8_t level)
{
    FILE *log_file_ptr = NULL;
    int ret = 0;

    CHECK_NULL_1PARAM_WITH_RET(log_buff, -1);

    /* LOG File Detect and Open */
    if (out_mode > ONLY_SCREEN)
    {
        /* judge the size of log file, if above max size, backup and rewrite log file */
        detect_log_size(s_log_conf_item.log_name);
        log_file_ptr = fopen(s_log_path, "a");
    }

    if (out_mode == ONLY_SCREEN)
    {
        print_screen_color_log(log_buff, level);
    }
    else if (out_mode == ONLY_FILE)
    {
        ret = print_log_only_file(log_file_ptr, log_buff, level);
    }
    else if (out_mode == FILE_AND_SCREEN)
    {
        print_screen_color_log(log_buff, level);
        ret = print_log_only_file(log_file_ptr, log_buff, level);
    }

    if (log_file_ptr != NULL)
    {
        fclose(log_file_ptr);
        log_file_ptr = NULL;
    }

    /* 单独打印错误日志 */
    if (level <= LOG_ERR && out_mode > ONLY_SCREEN)
    {
        snprintf(s_err_log_buf + s_err_log_buflen, LOG_BUF_SIZE - s_err_log_buflen, "%-6s %s\n", 
            s_loglevel_str[level], log_buff);
        s_err_log_buflen = strlen(s_err_log_buf);
        detect_log_size(s_log_conf_item.errlog_name);

        /* 普通日志缓冲区刷新时，同时需要刷新错误日志缓冲区 */
        if (ret > 0)
        {
            log_file_ptr = fopen(s_errlog_path, "a");
            if (log_file_ptr != NULL)
            {
                fprintf(log_file_ptr, "%s", s_err_log_buf);
                log_flush(log_file_ptr, s_err_log_buflen);
                memset(s_err_log_buf, 0, LOG_BUF_SIZE);
                s_err_log_buflen = 0;

                fclose(log_file_ptr);
                log_file_ptr = NULL;
            }
        }
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20220128
*  函数功能  : 将独立的子日志立即输出到内核.
*  输入参数  : log_file_ptr - 子日志文件指针.
*             log_buff - 日志内容.
*             level - 日志等级.
*  输出参数  : 0 - 成功  -1 - 失败.
*  返回值    : 无.
*************************************************************************/
int print_sublog_file(FILE *log_file_ptr, const char *log_buff, uint8_t level)
{
    int res = -1;
    char sublog_buf[SUFFIX_BUFSIZE] = {0};

    snprintf(sublog_buf, SUFFIX_BUFSIZE, "%-6s %s\n", s_loglevel_str[level], log_buff);

    res = fprintf(log_file_ptr, "%s", sublog_buf);
    if (res < 0)
    {
        return -1;
    }

    /* FLUSH LOG */
    log_flush(log_file_ptr, strlen(sublog_buf));
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20220128
*  函数功能  : 将独立的子日志输出到文件.
*  输入参数  : log_buff - 日志内容.
*             out_mode - 输出模式.
*             level - 日志等级.
*             logname - 日志文件名.
*  输出参数  : 0 - 成功  -1 - 失败.
*  返回值    : 无.
*************************************************************************/
int write_sublog_to_file(const char *log_buff, uint8_t out_mode, uint8_t level, const char *logname)
{
    FILE *log_file_ptr = NULL;
    int ret = 0;

    CHECK_NULL_2PARAM_WITH_RET(log_buff, logname, -1);

    if (out_mode > ONLY_SCREEN)
    {
        snprintf(s_sublog_path, sizeof(s_sublog_path), "%s/%s.log", s_log_conf_item.log_file_path, logname);
        detect_log_size(logname);
        log_file_ptr = fopen(s_sublog_path, "a");
    }

    if (out_mode == ONLY_SCREEN)
    {
        print_screen_color_log(log_buff, level);
    }
    else if (out_mode == ONLY_FILE)
    {
        ret = print_sublog_file(log_file_ptr, log_buff, level);
    }
    else if (out_mode == FILE_AND_SCREEN)
    {
        print_screen_color_log(log_buff, level);
        ret = print_sublog_file(log_file_ptr, log_buff, level);
    }

    if (log_file_ptr != NULL)
    {
        fclose(log_file_ptr);
        log_file_ptr = NULL;
    }

    /* 单独打印错误日志 */
    if (level <= LOG_ERR && out_mode > ONLY_SCREEN)
    {
        snprintf(s_err_log_buf + s_err_log_buflen, LOG_BUF_SIZE - s_err_log_buflen, "%-6s %s\n", 
            s_loglevel_str[level], log_buff);
        s_err_log_buflen = strlen(s_err_log_buf);
        detect_log_size(s_log_conf_item.errlog_name);

        /* 普通日志缓冲区刷新时，同时需要刷新错误日志缓冲区 */
        if (ret > 0)
        {
            log_file_ptr = fopen(s_errlog_path, "a");
            if (log_file_ptr != NULL)
            {
                fprintf(log_file_ptr, "%s", s_err_log_buf);
                log_flush(log_file_ptr, s_err_log_buflen);
                memset(s_err_log_buf, 0, LOG_BUF_SIZE);
                s_err_log_buflen = 0;

                fclose(log_file_ptr);
                log_file_ptr = NULL;
            }
        }
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 打印所有等级日志.
*  输入参数  : log_buff - 日志内容.
*             out_mode - 日志输出模式.
*             level - 日志等级.
*             logname - 输出的日志文件名.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int wrt_all_log(const char *log_buff, uint8_t out_mode, uint8_t level, const char *logname)
{
    CHECK_NULL_1PARAM_WITH_RET(log_buff, -1);

    if (NULL == logname || 0 == strcmp(logname, ""))
    {
        return write_chief_log_to_buffer(log_buff, out_mode, level);
    }
    else 
    {
        return write_sublog_to_file(log_buff, out_mode, level, logname);
    }
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210426
*  函数功能  : 信号绑定.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 初始化调用.
*************************************************************************/
void signal_bind(void)
{
    struct sigaction seg_act;
    struct sigaction seg_oact;
    struct sigaction act;
    struct sigaction oact;

    memset(&seg_act, 0, sizeof(seg_act));
    memset(&seg_oact, 0, sizeof(seg_oact));
    memset(&act, 0, sizeof(act));
    memset(&oact, 0, sizeof(oact));

    seg_act.sa_handler = print_backtrace;
    sigemptyset(&seg_act.sa_mask);
    sigaddset(&seg_act.sa_mask, SIGSEGV);
    seg_act.sa_flags = 0;

    errno = 0;
    if (sigaction(SIGSEGV, &seg_act, &seg_oact) != 0)
    {
        fprintf(stdout, "Can't attach SIGSEGV to print_backtrace(), errno:  %d\n", errno);
    }

    act.sa_handler = flush_log_buffer;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGINT);
    sigaddset(&act.sa_mask, SIGTERM);
    sigaddset(&act.sa_mask, SIGQUIT);
    sigaddset(&act.sa_mask, SIGTSTP);
    act.sa_flags = 0;

    errno = 0;
    if (sigaction(SIGINT, &act, &oact) != 0)
    {
        fprintf(stdout, "Can't attach SIGINT to flush_log_buffer(), errno:  %d\n", errno);
    }

    errno = 0;
    if (sigaction(SIGTERM, &act, &oact) != 0)
    {
        fprintf(stdout, "Can't attach SIGTERM to flush_log_buffer(), errno:  %d\n", errno);
    }

    errno = 0;
    if (sigaction(SIGQUIT, &act, &oact) != 0)
    {
        fprintf(stdout, "Can't attach SIGQUIT to flush_log_buffer(), errno:  %d\n", errno);
    }

    errno = 0;
    if (sigaction(SIGTSTP, &act, &oact) != 0)
    {
        fprintf(stdout, "Can't attach SIGTSTP to flush_log_buffer(), errno:  %d\n", errno);
    }

    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210628
*  函数功能  : 异步日志处理线程.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 初始化调用.
*************************************************************************/
void *async_log_process_thread(void *arg)
{
    s_async_tmp_node.buf = (char *)calloc(s_log_conf_item.log_maxlen, sizeof(char));
    if (NULL == s_async_tmp_node.buf)
    {
        fprintf(stderr, "Calloc failed\n");
        return NULL;
    }

    while (get_loop_flag())
    {
        pthread_spin_lock(&s_link_queue_lock);

        if (s_consumer_ptr->queue->status == EMPTY_QUEUE)
        {
            s_consumer_ptr = s_consumer_ptr->next;
            pthread_spin_unlock(&s_link_queue_lock);
            logger_usleep(20000);
            continue;
        }

        if (log_dequeue(s_consumer_ptr->queue, MAX_QUEUE_SIZE, &s_async_tmp_node) != 0)
        {
            fprintf(stdout, "LOG DEQUEUE failed\n");
        }

        pthread_spin_unlock(&s_link_queue_lock);

        wrt_all_log(s_async_tmp_node.buf, s_async_tmp_node.mode, s_async_tmp_node.level, s_async_tmp_node.logname);

        if (s_log_conf_item.debug_switch != 0)
        {
            manual_flush_log_buffer();
        }
    }

    FREE_VARIATE_WITH_FUNC(s_async_tmp_node.buf, free);
    return NULL;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20220518
*  函数功能  : 日志统计处理线程.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 初始化调用.
*************************************************************************/
void *log_statis_process_thread(void *arg)
{
    char *log_conf_path = (char *)arg;

    while (get_loop_flag())
    {
        (void)get_log_config(log_conf_path);
        sleep(1);
    }

    return NULL;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 日志模块初始化.
*  输入参数  : log_conf_path - 日志配置文件绝对路径(具体到文件名称).
                    如果填NULL，则启用默认配置.
              app_name - 调用日志模块的APP名称.
                    默认配置下填NULL，则屏幕输出日志，不保存到文件.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  调用关系  : 初始化调用.
*  其它      : 调用此函数返回失败后，也请调用销毁函数，防止内存泄漏.
*************************************************************************/
int init_logger(char *log_conf_path, char *app_name)
{
    int ret = 0;
    int alloc_size = 0;
    char mkdir[CMD_SIZE] = {0};

    if (NULL == log_conf_path)
    {
        fprintf(stdout, "INIT LOGGER parameter is NULL[log_conf_path:  %p]\n", log_conf_path);
    }

    memset(&s_log_conf_item, 0, sizeof(s_log_conf_item));
    s_process_id = getpid();
    s_def_level                         = LOG_DEBUG;
    s_log_conf_item.log_switch          = LOG_SWITCH;
    s_log_conf_item.debug_switch        = 1;
    s_log_conf_item.log_maxlen          = SUFFIX_BUFSIZE;
    s_log_conf_item.single_file_size_mb = LOGFILE_SIZE;
    s_log_conf_item.directory_size_mb   = 4 * LOGFILE_SIZE;
    snprintf(s_log_conf_item.log_file_path, FILEPATH_SIZE, "/data/log");

    if (app_name != NULL)
    {
        snprintf(s_log_conf_item.log_name, LOGNAME_SIZE, "%s", app_name);
        snprintf(s_log_conf_item.errlog_name, LOGNAME_SIZE, "%s_err", app_name);
    }

    ret = get_log_config(log_conf_path);
    if (ret != 0)
    {
        fprintf(stdout, "Get log configuration failed\n");
        fprintf(stdout, "Apply the default configuration\n");
        fprintf(stdout, "level:  %s\n", s_loglevel_str[s_def_level]);
        fprintf(stdout, "log_maxlen:  %d Bytes\n", s_log_conf_item.log_maxlen);
        fprintf(stdout, "switch:  %d\n", s_log_conf_item.log_switch);
        fprintf(stdout, "log path:  %s\n", s_log_conf_item.log_file_path);
        fprintf(stdout, "log name:  %s\n", s_log_conf_item.log_name);
        fprintf(stdout, "error log name:  %s\n", s_log_conf_item.errlog_name);
        fprintf(stdout, "debug switch:  %d\n", s_log_conf_item.debug_switch);
        fprintf(stdout, "single file size:  %d MB\n", s_log_conf_item.single_file_size_mb);
        fprintf(stdout, "directory size:  %d MB\n", s_log_conf_item.directory_size_mb);
    }

    if (0 == ret || app_name != NULL)
    {
        snprintf(s_log_path, sizeof(s_log_path), "%s/%s.log", 
            s_log_conf_item.log_file_path, s_log_conf_item.log_name);
        snprintf(s_errlog_path, sizeof(s_errlog_path), "%s/%s.log", 
            s_log_conf_item.log_file_path, s_log_conf_item.errlog_name);

        snprintf(mkdir, sizeof(mkdir), "mkdir -p %s", s_log_conf_item.log_file_path);

        if (-1 == logger_system(mkdir))
        {
            fprintf(stdout, "logger_system() execute failed\n");
            return -1;
        }
    }

    /* 相关信号绑定处理 */
    signal_bind();

    alloc_size = LOG_BUF_SIZE + 1 + LOG_BUF_SIZE + 1 + s_log_conf_item.log_maxlen + 1 + 
        s_log_conf_item.log_maxlen + 1 + s_log_conf_item.log_maxlen + 1 + s_log_conf_item.log_maxlen + 1;
    s_file_log_buf = (char *)calloc(alloc_size, sizeof(char));
    if (NULL == s_file_log_buf)
    {
        goto FAIL;
    }

    s_err_log_buf = s_file_log_buf + LOG_BUF_SIZE + 1;
    s_color_buf = s_err_log_buf + LOG_BUF_SIZE + 1;
    s_byte_log_buff = s_color_buf + s_log_conf_item.log_maxlen + 1;
    s_suffix_log_buff = s_byte_log_buff + s_log_conf_item.log_maxlen + 1;
    s_whole_log_buff = s_suffix_log_buff + s_log_conf_item.log_maxlen + 1;

    if(pthread_spin_init(&s_input_lock, PTHREAD_PROCESS_PRIVATE) != 0)
    {
        fprintf(stdout, "pthread_mutex_init() failed\n");
        goto FAIL;
    }

    s_link_queue = init_logger_link_queue();
    if (NULL == s_link_queue)
    {
        fprintf(stdout, "Failed to init looger link queue\n");
        goto FAIL;
    }

    if (init_loop_flag() != 0)
    {
        fprintf(stdout, "Failed to init loop flag\n");
        goto FAIL;
    }

    if (pthread_create(&s_async_pt, NULL, async_log_process_thread, NULL) != 0)
    {
        fprintf(stdout, "Create Async log thread Failed\n");
        goto FAIL;
    }

    if (pthread_create(&s_statis_pt, NULL, log_statis_process_thread, (void *)log_conf_path) != 0)
    {
        fprintf(stdout, "Create Statistics log thread Failed\n");
        goto FAIL;
    }

    return 0;

FAIL: 
    pthread_spin_destroy(&s_input_lock);
    pthread_join(s_async_pt, NULL);
    destroy_logger_link_queue(s_link_queue);
    destroy_loop_flag();
    clean_logger_buffer();
    return -1;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 日志消息入队前以及入队的相关处理操作.
*  输入参数  : data - 日志数据.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void log_enqueue_process(LOG_DATA_T *data)
{
    // CHECK_NULL_1PARAM_WITHOUT_RET(data);

    pthread_spin_lock(&s_link_queue_lock);

    /* 根据producer pointer寻找可用的空闲日志队列 */
    if (s_producer_ptr->queue->status == FULL_QUEUE)
    {
        s_producer_ptr = s_producer_ptr->next;

        /* 由于是单向循环链表，所以两次判定队列满，则可以确定所有队列已满 */
        if (s_producer_ptr->queue->status == FULL_QUEUE)
        {
            if (s_queue_cnt == MAX_QUEUE_NUM)
            {
                pthread_spin_unlock(&s_link_queue_lock);
                fprintf(stderr, "ALL QUEUEs are busy now[MAX QUEUE NUM:  %d]\n", MAX_QUEUE_NUM);
                return ;
            }

            /* 创建新节点 */
            if (create_new_log_link_node(s_producer_ptr) != 0)
            {
                /* MEM PROBLEM */
                pthread_spin_unlock(&s_link_queue_lock);
                fprintf(stderr, "create_new_log_link_node failed\n");
                return ;
            }

            /* 新增了一条队列计数 */
            s_queue_cnt++;
            s_producer_ptr = s_producer_ptr->next;
            fprintf(stdout, "create a new log queue:  %d\n", s_queue_cnt);
        }
    }

    /* 数据入队 */
    log_enqueue(s_producer_ptr->queue, MAX_QUEUE_SIZE, data);
    pthread_spin_unlock(&s_link_queue_lock);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 模块日志打印函数.
*  输入参数  : file - 当前文件名.
*             function - 当前函数名.
*             module - 模块名(可以为空).
*             line - 当前行数.
*             out_mode - 指定日志输出模式.
*             level - 指定日志等级.
*             fmt - 日志内容格式.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 打印日志时调用.
*************************************************************************/
void write_log(const char *file, const char *function, const char *module, uint16_t line, uint8_t out_mode, 
                        uint8_t level, const char *fmt, ...)
{
    char            time_buf[TIMESTAMP_SIZE]    = {0};
    va_list         ap;
    pid_t           tid                         = 0;
    LOG_DATA_T      data;

    CHECK_CONDITION_WITHOUT_RET(s_log_conf_item.log_switch != LOG_SWITCH);
    CHECK_CONDITION_WITHOUT_RET(level > s_def_level);
    CHECK_NULL_3PARAM_WITHOUT_RET(file, function, fmt);

    /* Get Now Time */
    get_log_time_buf(time_buf);
    tid = gettid();

    va_start(ap, fmt);
    pthread_spin_lock(&s_input_lock);
    vsnprintf(s_suffix_log_buff, s_log_conf_item.log_maxlen, fmt, ap);

    /* Construct LOG Information */
    if (module != NULL)
    {
        snprintf(s_whole_log_buff, s_log_conf_item.log_maxlen, "%s %d/%d [%s] %s:%d(%s) - %s", 
            time_buf, s_process_id, tid, module, file, line, function, s_suffix_log_buff);
    }
    else 
    {
        snprintf(s_whole_log_buff, s_log_conf_item.log_maxlen, "%s %d/%d %s:%d(%s) - %s", 
            time_buf, s_process_id, tid, file, line, function, s_suffix_log_buff);
    }

    data.buf = s_whole_log_buff;
    data.level = level;
    data.mode = out_mode;
    data.logname[0] = '\0';

    log_enqueue_process(&data);

    pthread_spin_unlock(&s_input_lock);
    va_end(ap);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 日志打印函数(输出到指定日志文件).
*  输入参数  : logname - 指定的日志文件名(不包含路径和文件后缀，禁止包含字符'.').
*             file - 此条日志所在文件名.
*             function - 此条日志所在函数名.
*             line - 此条日志所在行数.
*             out_mode - 指定日志输出模式.
*             level - 指定日志等级.
*             fmt - 日志内容格式.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 打印日志时调用.
*************************************************************************/
void write_file_log(const char *logname, const char *file, const char *function, uint16_t line, uint8_t out_mode, 
                            uint8_t level, const char *fmt, ...)
{
    char            time_buf[TIMESTAMP_SIZE]    = {0};
    va_list         ap;
    pid_t           tid                         = 0;
    LOG_DATA_T      data;

    CHECK_CONDITION_WITHOUT_RET(NULL == logname);
    CHECK_CONDITION_WITHOUT_RET(s_log_conf_item.log_switch != LOG_SWITCH);
    CHECK_CONDITION_WITHOUT_RET(level > s_def_level);
    CHECK_NULL_3PARAM_WITHOUT_RET(file, function, fmt);
    CHECK_NULL_3PARAM_WITHOUT_RET(s_suffix_log_buff, s_whole_log_buff, s_color_buf);

    /* Get Now Time */
    get_log_time_buf(time_buf);
    tid = gettid();

    va_start(ap, fmt);
    pthread_spin_lock(&s_input_lock);
    vsnprintf(s_suffix_log_buff, s_log_conf_item.log_maxlen, fmt, ap);

    /* Construct LOG Information */
    snprintf(s_whole_log_buff, s_log_conf_item.log_maxlen, "%s %d/%d %s:%d(%s) - %s", 
        time_buf, s_process_id, tid, file, line, function, s_suffix_log_buff);

    snprintf(data.logname, sizeof(data.logname), "%s", logname);
    data.buf = s_whole_log_buff;
    data.level = level;
    data.mode = out_mode;

    log_enqueue_process(&data);

    pthread_spin_unlock(&s_input_lock);
    va_end(ap);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 字节流日志打印函数.
*  输入参数  : file - 当前文件名.
*             function - 当前函数名.
*             module - 模块名(可以为空).
*             line - 当前行数.
*             out_mode - 指定日志输出模式.
*             level - 指定日志等级.
*             byte - 字节流.
*             byte_len - 字节流长度.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 打印日志时调用.
*************************************************************************/
void write_byte_log(const char *file, const char *function, const char *module, uint16_t line, uint8_t out_mode, 
                        uint8_t level, const uint8_t *byte, uint32_t byte_len)
{
    char            time_buf[TIMESTAMP_SIZE]    = {0};
    pid_t           tid                         = 0;
    LOG_DATA_T      data;

    CHECK_CONDITION_WITHOUT_RET(s_log_conf_item.log_switch != LOG_SWITCH);
    CHECK_CONDITION_WITHOUT_RET(level > s_def_level);
    CHECK_NULL_4PARAM_WITHOUT_RET(file, function, byte, s_byte_log_buff);

    /* Get Now Time */
    get_log_time_buf(time_buf);
    tid = gettid();

    pthread_spin_lock(&s_input_lock);

    if (byte_len * 2 >= s_log_conf_item.log_maxlen)
    {
        byte_len = s_log_conf_item.log_maxlen / 2;
    }
    else 
    {
        s_byte_log_buff[byte_len * 2] = '\0';
    }

    for (int i = 0; i < byte_len; i++)
    {
        snprintf(s_byte_log_buff + 2 * i, 3, "%02x", byte[i]);
    }

    /* Construct LOG Information */
    if (module != NULL)
    {
        snprintf(s_whole_log_buff, s_log_conf_item.log_maxlen, "%s %d/%d [%s] %s:%d(%s) - %s", 
            time_buf, s_process_id, tid, module, file, line, function, s_byte_log_buff);
    }
    else 
    {
        snprintf(s_whole_log_buff, s_log_conf_item.log_maxlen, "%s %d/%d %s:%d(%s) - %s", 
            time_buf, s_process_id, tid, file, line, function, s_byte_log_buff);
    }

    data.buf = s_whole_log_buff;
    data.level = level;
    data.mode = out_mode;
    data.logname[0] = '\0';

    log_enqueue_process(&data);

    pthread_spin_unlock(&s_input_lock);
    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201204
*  函数功能  : 刷新文件日志缓冲区.
*  输入参数  : log_path - 日志文件绝对路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  调用关系  : 应用层强制输出当前日志.
*************************************************************************/
int file_log_flush(char *log_path)
{
    FILE *logger = NULL;

    CHECK_NULL_1PARAM_WITH_RET(log_path, -1);
    CHECK_CONDITION_WITH_RET(0 == s_file_log_buflen, 0);

    logger = fopen(log_path, "a");
    if (NULL == logger)
    {
        // fprintf(stderr, "Failed to Get LOG File Pointer\n");
        return -1;
    }

    fprintf(logger, "%s", s_file_log_buf);
    if (-1 == log_flush(logger, s_file_log_buflen))
    {
        // fprintf(stderr, "FILE LOG FLUSH Failed\n");
        fclose(logger);
        logger = NULL;
        return -1;
    }

    memset(s_file_log_buf, 0, LOG_BUF_SIZE);
    s_file_log_buflen = 0;
    fclose(logger);
    logger = NULL;

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201204
*  函数功能  : 刷新ERROR日志缓冲区.
*  输入参数  : log_path - ERROR日志文件绝对路径.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*  调用关系  : 应用层强制输出当前日志.
*************************************************************************/
int err_log_flush(char *log_path)
{
    FILE *logger = NULL;

    CHECK_NULL_1PARAM_WITH_RET(log_path, -1);
    CHECK_CONDITION_WITH_RET(0 == s_err_log_buflen, 0);

    logger = fopen(log_path, "a");
    if (NULL == logger)
    {
        // fprintf(stderr, "Failed to Get LOG File Pointer\n");
        return -1;
    }

    fprintf(logger, "%s", s_err_log_buf);
    if (-1 == log_flush(logger, s_err_log_buflen))
    {
        // fprintf(stderr, "SCREEN AND FILE LOG FLUSH Failed\n");
        fclose(logger);
        logger = NULL;
        return -1;
    }

    memset(s_err_log_buf, 0, LOG_BUF_SIZE);
    s_err_log_buflen = 0;
    fclose(logger);
    logger = NULL;

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210412
*  函数功能  : 销毁日志模块.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void destroy_logger(void)
{
    sleep(1);
    manual_flush_log_buffer();      // 销毁前清空缓冲区日志.

    set_loop_flag(false);
    pthread_join(s_async_pt, NULL);
    pthread_join(s_statis_pt, NULL);
    destroy_logger_link_queue(s_link_queue);
    destroy_loop_flag();
    clean_logger_buffer();
    pthread_spin_destroy(&s_input_lock);
    return ;
}
