/******************************************************************************
  *  文件名     : lockfree_queue.h
  *  负责人     : xupeng
  *  创建日期   : 20250708
  *  版本号     : v1.1 
  *  文件描述   : 无锁队列接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __LOCKFREE_QUEUE_H__
#define __LOCKFREE_QUEUE_H__

#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LOCKFREE_RINGBUFFER_NODE_S
{
    void *data;
    atomic_uint head;
    atomic_uint tail;
} LOCKFREE_RINGBUFFER_NODE_T;

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250708
*  函数功能  : 初始化无锁环形队列.
*  输入参数  : single_buflen - 环形队列单个缓冲区长度.
*             bufnum - 环形队列缓冲区数量.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int lockfree_ringbuffer_init(uint32_t single_buflen, uint32_t bufnum);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250708
*  函数功能  : 无锁环形队列节点入队.
*  输入参数  : node - 无锁环形队列.
*             data - 入队数据.
*             datalen - 入队数据长度.
*  输出参数  : 无.
*  返回值    : 0 - 成功.
*             -1 - 无效参数.
*             -2 - 队列已满.
*************************************************************************/
int lockfree_ringbuffer_push(LOCKFREE_RINGBUFFER_NODE_T *node, const void *data, unsigned int datalen);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250708
*  函数功能  : 无锁环形队列节点出队.
*  输入参数  : node - 无锁环形队列.
*  输出参数  : data - 出队数据.
*             datalen - 出队数据长度.
*  返回值    : 无.
*************************************************************************/
int lockfree_ringbuffer_pop(LOCKFREE_RINGBUFFER_NODE_T *node, void *data, unsigned int *datalen);

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250708
*  函数功能  : 销毁无锁环形队列.
*  输入参数  : node - 环形队列节点.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int lockfree_ringbuffer_destroy(LOCKFREE_RINGBUFFER_NODE_T *node);

#ifdef __cplusplus
}
#endif

#endif
