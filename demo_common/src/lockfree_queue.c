/******************************************************************************
  *  文件名     : lockfree_queue.c
  *  负责人     : xupeng
  *  创建日期   : 20250708
  *  版本号     : v1.1 
  *  文件描述   : 无锁队列接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lockfree_queue.h"

/* 无锁环形队列 */
LOCKFREE_RINGBUFFER_NODE_T *g_ringbuffer_node = NULL;

/* 环形队列单个缓冲区长度 */
uint32_t g_ringbuffer_single_buflen = 0;

/* 环形队列缓冲区数量 */
uint32_t g_ringbuffer_bufnum = 0;

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250708
*  函数功能  : 初始化无锁环形队列.
*  输入参数  : single_buflen - 环形队列单个缓冲区长度.
*             bufnum - 环形队列缓冲区数量.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int lockfree_ringbuffer_init(uint32_t single_buflen, uint32_t bufnum)
{
    g_ringbuffer_node = (LOCKFREE_RINGBUFFER_NODE_T *)calloc(1, sizeof(LOCKFREE_RINGBUFFER_NODE_T));
    if (NULL == g_ringbuffer_node)
    {
        return -1; // Memory allocation failed
    }

    g_ringbuffer_node->data = (void *)calloc(single_buflen * bufnum, 1);
    if (NULL == g_ringbuffer_node->data)
    {
        free(g_ringbuffer_node);
        g_ringbuffer_node = NULL;
        return -1; // Memory allocation failed
    }

    atomic_init(&g_ringbuffer_node->head, 0);
    atomic_init(&g_ringbuffer_node->tail, 0);

    g_ringbuffer_single_buflen = single_buflen;
    g_ringbuffer_bufnum = bufnum;
    return 0; // Success
}

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
int lockfree_ringbuffer_push(LOCKFREE_RINGBUFFER_NODE_T *node, const void *data, unsigned int datalen)
{
    if (node == NULL || data == NULL || datalen == 0)
    {
        return -1; // Invalid parameters
    }

    unsigned int tail = atomic_load(&node->tail);
    unsigned int head = atomic_load(&node->head);

    // Check if the queue is full
    if ((tail + 1) % g_ringbuffer_bufnum == head)
    {
        return -2; // Queue is full
    }

    // Copy data to the buffer
    memcpy((char *)node->data + tail * g_ringbuffer_single_buflen, data, datalen);

    // Update the tail index
    atomic_store(&node->tail, (tail + 1) % g_ringbuffer_bufnum);

    return 0; // Success
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250708
*  函数功能  : 无锁环形队列节点出队.
*  输入参数  : node - 无锁环形队列.
*  输出参数  : data - 出队数据.
*             datalen - 出队数据长度.
*  返回值    : 无.
*************************************************************************/
int lockfree_ringbuffer_pop(LOCKFREE_RINGBUFFER_NODE_T *node, void *data, unsigned int *datalen)
{
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250708
*  函数功能  : 销毁无锁环形队列.
*  输入参数  : node - 环形队列节点.
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int lockfree_ringbuffer_destroy(LOCKFREE_RINGBUFFER_NODE_T *node)
{
    if (node == NULL)
    {
        return -1; // Node is NULL
    }

    if (node->data != NULL)
    {
        free(node->data);
        node->data = NULL;
    }

    free(node);
    node = NULL;

    return 0; // Success
}
