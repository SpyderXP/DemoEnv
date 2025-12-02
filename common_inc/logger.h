/******************************************************************************
  *  文件名     : logger.h
  *  负责人     : xupeng
  *  创建日期   : 20201203
  *  版本号     : v1.1 
  *  文件描述   : 通用日志模块.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __LOGGER_H__
#define __LOGGER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <syslog.h>
#include <stdint.h>

/*
    日志配置样例
    日志筛选等级(level)(区分大小写) EMERG ALERT CRIT ERROR WARN NOTICE INFO DEBUG
    单条日志支持的最大长度(log_maxlen) 单位为Byte，默认为2048.
    日志使能开关(switch) 0-disable 1-enable
    日志输出路径(path)
    日志文件名称(name)  禁止在name字符串内包含字符'.'
    ERROR级别日志文件名称(errlog_name)  禁止在errlog_name字符串内包含字符'.'
    日志刷新功能(debug_switch) 0-待缓冲区满，刷新到日志文件 1-立即刷新到日志文件.
    单个文件大小限制(single_file_size_mb) 单位为MB
    日志目录大小限制(directory_size_mb) 单位为MB，指定日志目录下所有日志文件超过该大小，则进行打包.
    日志输出模式(output_mode) 0-只输出到屏幕 1-只输出到文件 2-同时输出到屏幕和文件.

    {
        "level": "DEBUG",
        "switch": "1",
        "path": "/data/app/DEMO/logFile",
        "name": "demo",
        "errlog_name": "demo_err",
        "debug_switch": "1",
        "single_file_size_mb": "1",
        "directory_size_mb": "6", 
        "output_mode": "2"
    }
*/

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#ifdef __FILENAME__

/* 通用日志接口 */
#define APP_LOG(level, format, ...) \
            write_log(__FILENAME__, __FUNCTION__, NULL, __LINE__, level, format, ##__VA_ARGS__)

/* 字节流日志接口 */
#define APP_BYTE_LOG(level, byte, byte_len) \
            write_byte_log(__FILENAME__, __FUNCTION__, NULL, __LINE__, level, byte, byte_len)

/* 通用模块化日志接口 */
#define APP_MODULE_LOG(module, level, format, ...) \
            write_log(__FILENAME__, __FUNCTION__, module, __LINE__, level, format, ##__VA_ARGS__)

/* 模块化字节流日志接口 */
#define APP_MODULE_BYTE_LOG(module, level, byte, byte_len) \
            write_byte_log(__FILENAME__, __FUNCTION__, module, __LINE__, level, byte, byte_len)

/* 文件日志接口 */
#define APP_FLOG(file, level, format, ...) \
            write_file_log(file, __FILENAME__, __FUNCTION__, __LINE__, level, format, ##__VA_ARGS__)
#else

/* 通用日志接口 */
#define APP_LOG(level, format, ...) \
            write_log(__FILE__, __FUNCTION__, NULL, __LINE__, level, format, ##__VA_ARGS__)

/* 字节流日志接口 */
#define APP_BYTE_LOG(level, byte, byte_len) \
            write_byte_log(__FILE__, __FUNCTION__, NULL, __LINE__, level, byte, byte_len)

/* 通用模块化日志接口 */
#define APP_MODULE_LOG(module, level, format, ...) \
            write_log(__FILE__, __FUNCTION__, module, __LINE__, level, format, ##__VA_ARGS__)

/* 模块化字节流日志接口 */
#define APP_MODULE_BYTE_LOG(module, level, byte, byte_len) \
            write_byte_log(__FILE__, __FUNCTION__, module, __LINE__, level, byte, byte_len)

/* 文件日志接口 */
#define APP_FLOG(file, level, format, ...) \
            write_file_log(file, __FILE__, __FUNCTION__, __LINE__, level, format, ##__VA_ARGS__)
#endif

/* 不同级别的日志输出宏定义 */
#define APP_LOG_DEBUG(format, ...)      APP_LOG(LOG_DEBUG, format, ##__VA_ARGS__)               /* DEBUG */
#define APP_LOG_INFO(format, ...)       APP_LOG(LOG_INFO, format, ##__VA_ARGS__)                /* INFO */
#define APP_LOG_NOTICE(format, ...)     APP_LOG(LOG_NOTICE, format, ##__VA_ARGS__)              /* NOTICE */
#define APP_LOG_WARNING(format, ...)    APP_LOG(LOG_WARNING, format, ##__VA_ARGS__)             /* WARNING */
#define APP_LOG_ERROR(format, ...)      APP_LOG(LOG_ERR, format, ##__VA_ARGS__)                 /* ERROR */
#define APP_LOG_CRIT(format, ...)       APP_LOG(LOG_CRIT, format, ##__VA_ARGS__)                /* CRIT */
#define APP_LOG_ALERT(format, ...)      APP_LOG(LOG_ALERT, format, ##__VA_ARGS__)               /* ALERT */
#define APP_LOG_EMERG(format, ...)      APP_LOG(LOG_EMERG, format, ##__VA_ARGS__)               /* EMERG */

/* 模块化不同级别的日志输出宏定义 */
#define APP_MODULE_LOG_DEBUG(module, format, ...)           \
            APP_MODULE_LOG(module, LOG_DEBUG, format, ##__VA_ARGS__)                            /* DEBUG */
#define APP_MODULE_LOG_INFO(module, format, ...)            \
            APP_MODULE_LOG(module, LOG_INFO, format, ##__VA_ARGS__)                             /* INFO */
#define APP_MODULE_LOG_NOTICE(module, format, ...)          \
            APP_MODULE_LOG(module, LOG_NOTICE, format, ##__VA_ARGS__)                           /* NOTICE */
#define APP_MODULE_LOG_WARNING(module, format, ...)         \
            APP_MODULE_LOG(module, LOG_WARNING, format, ##__VA_ARGS__)                          /* WARNING */
#define APP_MODULE_LOG_ERROR(module, format, ...)           \
            APP_MODULE_LOG(module, LOG_ERR, format, ##__VA_ARGS__)                              /* ERROR */
#define APP_MODULE_LOG_CRIT(module, format, ...)            \
            APP_MODULE_LOG(module, LOG_CRIT, format, ##__VA_ARGS__)                             /* CRIT */
#define APP_MODULE_LOG_ALERT(module, format, ...)           \
            APP_MODULE_LOG(module, LOG_ALERT, format, ##__VA_ARGS__)                            /* ALERT */
#define APP_MODULE_LOG_EMERG(module, format, ...)           \
            APP_MODULE_LOG(module, LOG_EMERG, format, ##__VA_ARGS__)                            /* EMERG */

/* 字节流日志打印 */
#define APP_MODULE_BYTE_LOG_DEBUG(module, byte, byte_len) \
            APP_MODULE_BYTE_LOG(module, LOG_DEBUG, byte, byte_len)                              /* DEBUG */
#define APP_MODULE_BYTE_LOG_INFO(module, byte, byte_len) \
            APP_MODULE_BYTE_LOG(module, LOG_INFO, byte, byte_len)                               /* INFO */
#define APP_MODULE_BYTE_LOG_NOTICE(module, byte, byte_len) \
            APP_MODULE_BYTE_LOG(module, LOG_NOTICE, byte, byte_len)                             /* NOTICE */
#define APP_MODULE_BYTE_LOG_WARNING(module, byte, byte_len) \
            APP_MODULE_BYTE_LOG(module, LOG_WARNING, byte, byte_len)                            /* WARNING */
#define APP_MODULE_BYTE_LOG_ERROR(module, byte, byte_len) \
            APP_MODULE_BYTE_LOG(module, LOG_ERROR, byte, byte_len)                              /* ERROR */
#define APP_MODULE_BYTE_LOG_CRIT(module, byte, byte_len) \
            APP_MODULE_BYTE_LOG(module, LOG_CRIT, byte, byte_len)                               /* CRIT */
#define APP_MODULE_BYTE_LOG_ALERT(module, byte, byte_len) \
            APP_MODULE_BYTE_LOG(module, LOG_ALERT, byte, byte_len)                              /* ALERT */
#define APP_MODULE_BYTE_LOG_EMERG(module, byte, byte_len) \
            APP_MODULE_BYTE_LOG(module, LOG_EMERG, byte, byte_len)                              /* EMERG */

/* 日志输出到指定文件 */
#define APP_FLOG_DEBUG(file, format, ...)   APP_FLOG(file, LOG_DEBUG, format, ##__VA_ARGS__)    /* DEBUG */
#define APP_FLOG_INFO(file, format, ...)    APP_FLOG(file, LOG_INFO, format, ##__VA_ARGS__)     /* INFO */
#define APP_FLOG_NOTICE(file, format, ...)  APP_FLOG(file, LOG_NOTICE, format, ##__VA_ARGS__)   /* NOTICE */
#define APP_FLOG_WARNING(file, format, ...) APP_FLOG(file, LOG_WARNING, format, ##__VA_ARGS__)  /* WARNING */
#define APP_FLOG_ERROR(file, format, ...)   APP_FLOG(file, LOG_ERR, format, ##__VA_ARGS__)      /* ERROR */
#define APP_FLOG_CRIT(file, format, ...)    APP_FLOG(file, LOG_CRIT, format, ##__VA_ARGS__)     /* CRIT */
#define APP_FLOG_ALERT(file, format, ...)   APP_FLOG(file, LOG_ALERT, format, ##__VA_ARGS__)    /* ALERT */
#define APP_FLOG_EMERG(file, format, ...)   APP_FLOG(file, LOG_EMERG, format, ##__VA_ARGS__)    /* EMERG */

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
int init_logger(char *log_conf_path, char *app_name);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20210412
*  函数功能  : 销毁日志模块.
*  输入参数  : 无.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void destroy_logger(void);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 模块日志打印函数.
*  输入参数  : file - 当前文件名.
*             function - 当前函数名.
*             module - 模块名(可以为空).
*             line - 当前行数.
*             level - 指定日志等级.
*             fmt - 日志内容格式.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 打印日志时调用.
*************************************************************************/
void write_log(const char *file, const char *function, const char *module, uint16_t line, uint8_t level, 
        const char *fmt, ...);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 日志打印函数(输出到指定日志文件).
*  输入参数  : logname - 指定的日志文件名(不包含路径和文件后缀，禁止包含字符'.').
*             file - 此条日志所在文件名.
*             function - 此条日志所在函数名.
*             line - 此条日志所在行数.
*             level - 指定日志等级.
*             fmt - 日志内容格式.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 打印日志时调用.
*************************************************************************/
void write_file_log(const char *logname, const char *file, const char *function, uint16_t line, uint8_t level, 
        const char *fmt, ...);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20201203
*  函数功能  : 字节流日志打印函数.
*  输入参数  : file - 当前文件名.
*             function - 当前函数名.
*             module - 模块名(可以为空).
*             line - 当前行数.
*             level - 指定日志等级.
*             byte - 字节流.
*             byte_len - 字节流长度.
*  输出参数  : 无.
*  返回值    : 无.
*  调用关系  : 打印日志时调用.
*************************************************************************/
void write_byte_log(const char *file, const char *function, const char *module, uint16_t line, uint8_t level, 
        const uint8_t *byte, uint32_t byte_len);

#ifdef __cplusplus
}
#endif

#endif
