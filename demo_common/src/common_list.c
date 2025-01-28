/******************************************************************************
  *  文件名     : common_list.c
  *  负责人     : xupeng
  *  创建日期   : 20250128
  *  版本号     : v1.1 
  *  文件描述   : 通用链表接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "common_list.h"

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250128
*  函数功能  : 头插法入链.
*  输入参数  : node - 待插入节点.
*  输出参数  : list - 待插入链表.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int list_push_node(LIST_T *list, LIST_NODE_T *node)
{
    if (NULL == list || NULL == node)
    {
        return -1;
    }

    if (NULL == list->node)
    {
        list->node = node;
        list->node->next = NULL;
    }
    else 
    {
        node->next = list->node;
        list->node = node;
    }

    list->size++;
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250128
*  函数功能  : 取出指定条件的节点.
*  输入参数  : list - 待遍历链表.
*             data - 条件数据.
*             datalen - 数据长度.
*  输出参数  : node - 取出的节点.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int list_pop_node(LIST_T *list, void *data, uint32_t datalen, LIST_NODE_T **node)
{
    LIST_NODE_T *old = NULL;
    LIST_NODE_T *cur = NULL;

    if (NULL == list || NULL == node)
    {
        return -1;
    }

    if (0 == list->size)
    {
        return -1;
    }

    old = list->node;

    if (datalen == old->datalen && 
        0 == memcmp(old->data, data, datalen))
    {
        list->node = old->next;
        list->size--;
        *node = old;
        return 0;
    }

    cur = old->next;
    for (uint32_t i = 0; i < list->size && cur != NULL; i++)
    {
        if (datalen == cur->datalen && 
            0 == memcmp(cur->data, data, datalen))
        {
            old->next = cur->next;
            cur->next = NULL;
            list->size--;
            *node = cur;
            return 0;
        }

        old = old->next;
        cur = cur->next;
    }

    return -1;
}
