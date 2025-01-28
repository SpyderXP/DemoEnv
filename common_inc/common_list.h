/******************************************************************************
  *  文件名     : common_list.h
  *  负责人     : xupeng
  *  创建日期   : 20250128
  *  版本号     : v1.1 
  *  文件描述   : 通用链表接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#ifndef __COMMON_LIST_H__
#define __COMMON_LIST_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LIST_NODE_S
{
    void *data;                 /* 用户自定义数据区(用户申请释放) */
    uint32_t datalen;           /* 数据区长度 */
    struct LIST_NODE_S *next;
} LIST_NODE_T;

typedef struct LIST_S 
{
    uint8_t size;               /* 链表节点数量 */
    LIST_NODE_T *node;
} LIST_T;

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250128
*  函数功能  : 头插法入链.
*  输入参数  : node - 待插入节点.
*  输出参数  : list - 待插入链表.
*  返回值    : 0 - 成功  -1 - 失败.
*************************************************************************/
int list_push_node(LIST_T *list, LIST_NODE_T *node);

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
int list_pop_node(LIST_T *list, void *data, uint32_t datalen, LIST_NODE_T **node);

#ifdef __cplusplus
}
#endif

#endif
