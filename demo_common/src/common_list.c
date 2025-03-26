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
#include <stdlib.h>
#include "common_list.h"

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250128
*  函数功能  : 头插入链.
*  输入参数  : node - 待插入节点.
*  输出参数  : list - 待插入链表.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int list_push_node_to_head(LIST_T *list, LIST_NODE_T *node)
{
    if (NULL == list || NULL == node)
    {
        return -1;
    }

    if (NULL == list->head)
    {
        list->head = node;
        list->tail = node;
        list->head->next = NULL;
        list->tail->next = NULL;
    }
    else 
    {
        node->next = list->head;
        list->head = node;
    }

    list->size++;
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250128
*  函数功能  : 尾插入链.
*  输入参数  : node - 待插入节点.
*  输出参数  : list - 待插入链表.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int list_push_node_to_tail(LIST_T *list, LIST_NODE_T *node)
{
    if (NULL == list || NULL == node)
    {
        return -1;
    }

    if (NULL == list->tail)
    {
        list->head = node;
        list->tail = node;
        list->head->next = NULL;
        list->tail->next = NULL;
    }
    else 
    {
        list->tail->next = node;
        list->tail = node;
    }

    list->size++;
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250128
*  函数功能  : 取出头部节点.
*  输入参数  : list - 待取链表.
*  输出参数  : node - 取出的节点.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int list_pop_node_from_head(LIST_T *list, LIST_NODE_T **node)
{
    if (NULL == list || NULL == node)
    {
        return -1;
    }

    if (0 == list->size || NULL == list->head)
    {
        return -1;
    }

    *node = list->head;
    list->head = list->head->next;
    list->size--;
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250128
*  函数功能  : 取出尾部节点.
*  输入参数  : list - 待取链表.
*  输出参数  : node - 取出的节点.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int list_pop_node_from_tail(LIST_T *list, LIST_NODE_T **node)
{
    LIST_NODE_T *new_tail = NULL;

    if (NULL == list || NULL == node)
    {
        return -1;
    }

    if (0 == list->size || NULL == list->tail)
    {
        return -1;
    }

    *node = list->tail;
    new_tail = list->head;
    for (uint16_t i = 0; i < list->size - 2; i++)
    {
        new_tail = new_tail->next;
    }

    list->tail = new_tail;
    list->tail->next = NULL;
    list->size--;
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
int list_pop_node_by_elem(LIST_T *list, void *data, uint32_t datalen, LIST_NODE_T **node)
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

    old = list->head;

    if (datalen == old->datalen && 0 == memcmp(old->data, data, datalen))
    {
        list->head = old->next;
        if (NULL == list->head)
        {
            list->tail = NULL;
        }
        list->size--;
        *node = old;
        return 0;
    }

    cur = old->next;
    for (uint32_t i = 0; i < list->size && cur != NULL; i++)
    {
        if (datalen == cur->datalen && 0 == memcmp(cur->data, data, datalen))
        {
            old->next = cur->next;
            cur->next = NULL;
            if (NULL == old->next)
            {
                list->tail = old;
            }
            list->size--;
            *node = cur;
            return 0;
        }

        old = old->next;
        cur = cur->next;
    }

    return -1;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250326
*  函数功能  : 创建二叉堆.
*  输入参数  : capacity - 二叉堆支持的最大节点数.
*  输出参数  : 无.
*  返回值    : 创建的二叉堆.
*************************************************************************/
BINARY_HEAP_T *create_binary_heap(int capacity)
{
    BINARY_HEAP_T *heap = (BINARY_HEAP_T*)calloc(1, sizeof(BINARY_HEAP_T));

    if (NULL == heap)
    {
        return NULL;
    }

    heap->nodes = (BINARY_HEAP_NODE_T **)calloc(1, capacity * sizeof(BINARY_HEAP_NODE_T *));
    if (NULL == heap->nodes)
    {
        free(heap);
        heap = NULL;
        return NULL;
    }

    heap->capacity = capacity;
    return heap;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250326
*  函数功能  : 扩展二叉堆的最大节点数.
*  输入参数  : heap - 待扩展的二叉堆.
*  输出参数  : 无.
*  返回值    : 扩展后的二叉堆.
*************************************************************************/
BINARY_HEAP_T *extend_binary_heap_capacity(BINARY_HEAP_T *heap)
{
    if (NULL == heap)
    {
        return NULL;
    }

#ifdef _GNU_SOURCE
    heap->nodes = reallocarray(heap->nodes, 2, heap->capacity * sizeof(BINARY_HEAP_NODE_T *));
#else
    heap->elements = realloc(heap->elements, 2 * heap->capacity * sizeof(BINARY_HEAP_NODE_T *));
#endif

    if (NULL == heap->nodes)
    {
        return NULL;
    }

    heap->capacity *= 2;
    return heap;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250326
*  函数功能  : 最小堆元素下沉.
*  输入参数  : heap - 最小堆.
*             index - 指定下沉节点的索引.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void min_heapify_down(BINARY_HEAP_T *heap, int index)
{
    int smallest = index;       /* 当前节点 */
    int left = 2 * index + 1;   /* 左子节点 */
    int right = 2 * index + 2;  /* 右子节点 */
    BINARY_HEAP_NODE_T *tmp = NULL;

    if (NULL == heap || index >= heap->size)
    {
        return ;
    }

    /* 找到当前节点、左子节点、右子节点中的最小值 */
    if (left < heap->size && heap->nodes[left]->priority < heap->nodes[smallest]->priority)
    {
        smallest = left;
    }

    if (right < heap->size && heap->nodes[right]->priority < heap->nodes[smallest]->priority)
    {
        smallest = right;
    }

    /* 若最小值不是当前节点，交换并递归调整 */
    if (smallest != index)
    {
        tmp = heap->nodes[index];
        heap->nodes[index] = heap->nodes[smallest];
        heap->nodes[smallest] = tmp;
        min_heapify_down(heap, smallest);
    }
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250326
*  函数功能  : 最小堆元素上浮.
*  输入参数  : heap - 最小堆.
*             index - 指定上浮节点的索引.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void min_heapify_up(BINARY_HEAP_T *heap, int index)
{
    int parent = (index - 1) / 2;
    BINARY_HEAP_NODE_T *tmp = NULL;

    if (NULL == heap)
    {
        return ;
    }

    if (index > heap->size || parent > heap->size)
    {
        return ;
    }

    while (index > 0 && heap->nodes[index]->priority < heap->nodes[parent]->priority)
    {
        /* 交换父子节点 */
        tmp = heap->nodes[parent];
        heap->nodes[parent] = heap->nodes[index];
        heap->nodes[index] = tmp;
        index = parent;
        parent = (index - 1) / 2;
    }
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250326
*  函数功能  : 最小堆元素插入.
*  输入参数  : heap - 最小堆.
*             node - 待插入节点(用户自己维护节点的内存).
*  输出参数  : 无.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int min_heap_insert(BINARY_HEAP_T *heap, BINARY_HEAP_NODE_T *node)
{
    if (NULL == heap || NULL == node)
    {
        return -1;
    }

    if (heap->size >= heap->capacity)
    {
        heap = extend_binary_heap_capacity(heap);
    }

    heap->nodes[heap->size] = node;
    min_heapify_up(heap, heap->size);
    heap->size++;
    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250326
*  函数功能  : 最小堆元素提取.
*  输入参数  : heap - 最小堆.
*  输出参数  : 无.
*  返回值    : 最小优先级节点.
*************************************************************************/
BINARY_HEAP_NODE_T *min_heap_extract(BINARY_HEAP_T *heap)
{
    BINARY_HEAP_NODE_T *min = NULL;

    if (NULL == heap)
    {
        return NULL;
    }

    if (heap->size == 0)
    {
        return NULL;
    }

    min = heap->nodes[0];
    heap->nodes[0] = heap->nodes[heap->size - 1];
    heap->nodes[heap->size - 1] = NULL;
    heap->size--;
    min_heapify_down(heap, 0);
    return min;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250326
*  函数功能  : 将一个无序二叉堆构建为最小堆.
*  输入参数  : heap - 最小堆.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void build_min_heap(BINARY_HEAP_T *heap)
{
    if (NULL == heap)
    {
        return ;
    }

    for (int i = (heap->size - 1) / 2; i >= 0; i--)
    {
        min_heapify_down(heap, i);
    }
}
