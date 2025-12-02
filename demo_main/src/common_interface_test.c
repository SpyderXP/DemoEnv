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
#include <stdatomic.h>
#include <threads.h>
#include <math.h>
#include "logger.h"
#include "common_macro.h"
#include "epoll_timer.h"
#include "common_list.h"
#include "common_sort.h"

/* 用户自定义定时器参数数据域 */
typedef struct EPOLL_TIMER_DATA_S
{
    int num;
    char arr[32];
} EPOLL_TIMER_DATA_T;

/* EPOLL FD */
int g_epollfd = -1;

/* EPOLL定时器实例 */
EPOLL_TIMER_T g_epoll_timer[EPOLL_EVENT_SIZE] = {0};

int epoll_data_process(TIMER_CTX_T *ctx)
{
    struct timeval tv = {0};
    EPOLL_TIMER_DATA_T *ptr = NULL;

    if (NULL == ctx)
    {
        APP_LOG_ERROR("ctx is NULL");
        return -1;
    }

    ptr = (EPOLL_TIMER_DATA_T *)ctx->data;
    if (NULL == ptr)
    {
        APP_LOG_ERROR("Epoll timer data is NULL");
    }

    gettimeofday(&tv, NULL);
    APP_LOG_ERROR("timer: %d | num: %d | sec: %ld | usec: %ld", 
        ctx->timerfd, ptr->num, tv.tv_sec, tv.tv_usec);
    return 0;
}

int epoll_timer_run(void)
{
    pthread_t pt = 0;
    char *alloc_mem = NULL;
    EPOLL_TIMER_DATA_T *dataptr = NULL;

    alloc_mem = (char *)calloc(2, sizeof(EPOLL_TIMER_DATA_T));
    if (NULL == alloc_mem)
    {
        APP_LOG_ERROR("CALLOC FAILED");
        return -1;
    }

    // 数据赋值.
    g_epoll_timer[0].ctx.data = alloc_mem;
    dataptr = (EPOLL_TIMER_DATA_T *)g_epoll_timer[0].ctx.data;
    dataptr->num = 1;
    g_epoll_timer[0].handler = epoll_data_process;
    g_epoll_timer[1].ctx.data = alloc_mem + sizeof(EPOLL_TIMER_DATA_T);
    dataptr = (EPOLL_TIMER_DATA_T *)g_epoll_timer[1].ctx.data;
    dataptr->num = 2;
    g_epoll_timer[1].handler = epoll_data_process;

    g_epollfd = create_epollfd();
    if (pthread_create(&pt, NULL, nonblock_epoll_timer_loop_run, (void *)&g_epollfd) != 0)
    {
        APP_LOG_ERROR("Failed to create thread func");
        goto FAIL;
    }

    // 创建毫秒级定时器并加入到epoll管理.
    if (create_ms_epoll_timer(&g_epoll_timer[0], g_epollfd, 2500) != 0)
    {
        APP_LOG_ERROR("Failed to create epoll timer");
        goto FAIL;
    }

    if (create_ms_epoll_timer(&g_epoll_timer[1], g_epollfd, 3000) != 0)
    {
        APP_LOG_ERROR("Failed to create epoll timer");
        goto FAIL;
    }

    return 0;

    /* 资源回收 */
FAIL:
    if (g_epoll_timer[0].ctx.timerfd > 0)
    {
        destroy_ms_epoll_timer(&g_epoll_timer[0], g_epollfd);
    }

    if (g_epoll_timer[1].ctx.timerfd > 0)
    {
        destroy_ms_epoll_timer(&g_epoll_timer[1], g_epollfd);
    }

    nonblock_epoll_timer_loop_stop();
    pthread_join(pt, NULL);
    if (alloc_mem != NULL)
    {
        free(alloc_mem);
        alloc_mem = NULL;
    }

    return -1;
}

int common_list_interface_test(void)
{
    LIST_T list = {0};
    LIST_NODE_T *innode = NULL;
    LIST_NODE_T *outnode = NULL;
    char key[32] = {0};

    innode = calloc(1, sizeof(LIST_NODE_T));
    innode->data = calloc(1, 32);
    innode->datalen = 32;
    snprintf((char *)innode->data, 32, "first node");
    if (list_push_node_to_head(&list, innode) != 0)
    {
        APP_LOG_ERROR("Failed to push node");
        return -1;
    }

    innode = calloc(1, sizeof(LIST_NODE_T));
    innode->data = calloc(1, 32);
    innode->datalen = 32;
    snprintf((char *)innode->data, 32, "second node");
    if (list_push_node_to_head(&list, innode) != 0)
    {
        APP_LOG_ERROR("Failed to push node");
        return -1;
    }

    innode = calloc(1, sizeof(LIST_NODE_T));
    innode->data = calloc(1, 32);
    innode->datalen = 32;
    snprintf((char *)innode->data, 32, "third node");
    if (list_push_node_to_head(&list, innode) != 0)
    {
        APP_LOG_ERROR("Failed to push node");
        return -1;
    }

    snprintf(key, sizeof(key), "first node");
    list_pop_node_by_elem(&list, (void *)key, 32, &outnode);
    if (outnode != NULL)
    {
        APP_LOG_INFO("node1: %s[datalen: %d]", (char *)outnode->data, outnode->datalen);
        if (outnode->data != NULL)
        {
            free(outnode->data);
            outnode->data = NULL;
        }
        free(outnode);
        outnode = NULL;
    }

    snprintf(key, sizeof(key), "second node");
    list_pop_node_by_elem(&list, (void *)key, 32, &outnode);
    if (outnode != NULL)
    {
        APP_LOG_INFO("node2: %s[datalen: %d]", (char *)outnode->data, outnode->datalen);
        if (outnode->data != NULL)
        {
            free(outnode->data);
            outnode->data = NULL;
        }
        free(outnode);
        outnode = NULL;
    }

    snprintf(key, sizeof(key), "third node");
    list_pop_node_by_elem(&list, (void *)key, 32, &outnode);
    if (outnode != NULL)
    {
        APP_LOG_INFO("node3: %s[datalen: %d]", (char *)outnode->data, outnode->datalen);
        if (outnode->data != NULL)
        {
            free(outnode->data);
            outnode->data = NULL;
        }
        free(outnode);
        outnode = NULL;
    }

    return 0;
}

void partition_list()
{
    LIST_T list = {0};
    LIST_NODE_T node[6] = {0};
    int arr[6] = {1, 4, 3, 2, 5, 2};
    for (int i = 0; i < 6; i++)
    {
        node[i].data = calloc(1, 4);
        node[i].datalen = 4;
        *(int *)node[i].data = arr[i];
        if (list_push_node_to_tail(&list, &node[i]) != 0)
        {
            APP_LOG_ERROR("Failed to push node");
        }
    }

    {
        LIST_NODE_T *p = list.head;
        LIST_NODE_T dummy1 = {0};   /* 虚拟头节点 */
        LIST_NODE_T dummy2 = {0};   /* 虚拟头节点 */
        LIST_NODE_T *p1 = &dummy1;
        LIST_NODE_T *p2 = &dummy2;
        LIST_NODE_T *tmp = NULL;
    
        while (p != NULL)
        {
            if (*(int *)p->data < 3)
            {
                p1->next = p;
                p1 = p1->next;
            }
            else 
            {
                p2->next = p;
                p2 = p2->next;
            }
    
            /* 应将每一个节点的next断掉
               否则一旦原链表出现next没有置空的节点
               再转移到新链表上就可能导致链表成环 */
            // p = p->next;
            tmp = p->next;
            p->next = NULL;
            p = tmp;
        }
    
        p1->next = dummy2.next;
        p2 = dummy1.next;
        while (p2 != NULL)
        {
            APP_LOG_INFO("node: %d", *(int *)p2->data);
            p2 = p2->next;
        }
    }

    return ;
}

int list_reverse(LIST_T *list)
{
    LIST_NODE_T *next = NULL;
    LIST_NODE_T *cur = NULL;
    LIST_NODE_T *prev = NULL;

    if (NULL == list)
    {
        return -1;
    }

    if (NULL == list->head || 0 == list->size)
    {
        return -1;
    }

    cur = list->head;
    next = cur->next;

    if (NULL == next)
    {
        return 0;
    }
    else 
    {
        cur->next = NULL;
        while (next != NULL)
        {
            prev = cur;
            cur = next;
            next = cur->next;
            cur->next = prev;
        }
        list->head = cur;
    }

    return 0;
}

void list_reverse_test(void)
{
    LIST_T list = {0};
    LIST_NODE_T *innode = NULL;
    LIST_NODE_T *outnode = NULL;

    /* 加入节点 */
    innode = calloc(1, sizeof(LIST_NODE_T));
    innode->data = calloc(1, 4);
    innode->datalen = 4;
    *(int *)innode->data = 1;
    list_push_node_to_head(&list, innode);

    innode = calloc(1, sizeof(LIST_NODE_T));
    innode->data = calloc(1, 4);
    innode->datalen = 4;
    *(int *)innode->data = 2;
    list_push_node_to_head(&list, innode);

    innode = calloc(1, sizeof(LIST_NODE_T));
    innode->data = calloc(1, 4);
    innode->datalen = 4;
    *(int *)innode->data = 3;
    list_push_node_to_head(&list, innode);

    /* 链表反转 */
    if (list_reverse(&list) != 0)
    {
        APP_LOG_ERROR("list reverse failed");
    }

    /* 取出节点 */
    list_pop_node_from_head(&list, &outnode);
    APP_LOG_INFO("node1: %d", *(int *)outnode->data);
    free(outnode->data);
    free(outnode);
    outnode = NULL;

    list_pop_node_from_head(&list, &outnode);
    APP_LOG_INFO("node2: %d", *(int *)outnode->data);
    free(outnode->data);
    free(outnode);
    outnode = NULL;

    list_pop_node_from_head(&list, &outnode);
    APP_LOG_INFO("node3: %d", *(int *)outnode->data);
    free(outnode->data);
    free(outnode);
    outnode = NULL;

    return ;
}

int sort_algo_test()
{
    /* 冒泡排序 */
    {
        int arr[] = {33, 5, 23, 33, 697, 12, 88};

        TIME_ELAPSED(bubble_sort(arr, sizeof(arr) / sizeof(int)));
        for (int i = 0; i < sizeof(arr) / sizeof(int); i++)
        {
            printf("%d ", arr[i]);
        }
        printf("\n");
    }

    /* 插入排序 */
    {
        int arr[] = {33, 5, 23, 33, 697, 12, 88};

        TIME_ELAPSED(insert_sort(arr, sizeof(arr) / sizeof(int)));
        for (int i = 0; i < sizeof(arr) / sizeof(int); i++)
        {
            printf("%d ", arr[i]);
        }
        printf("\n");
    }

    /* 归并排序 */
    {
        int arr[] = {33, 5, 23, 33, 697, 12, 88};

        TIME_ELAPSED(merge_sort(arr, sizeof(arr) / sizeof(int)));
        for (int i = 0; i < sizeof(arr) / sizeof(int); i++)
        {
            printf("%d ", arr[i]);
        }
        printf("\n");
    }

    /* 堆排序 */
    {
        int arr[] = {33, 5, 23, 33, 697, 12, 88};

        TIME_ELAPSED(heap_sort(arr, sizeof(arr) / sizeof(int)));
        for (int i = 0; i < sizeof(arr) / sizeof(int); i++)
        {
            printf("%d ", arr[i]);
        }
        printf("\n");
    }

    /* 基数排序 */
    {

    }

    /* 桶排序 */
    {

    }

    return 0;
}

void binary_heap_test()
{
    BINARY_HEAP_T *heap = create_binary_heap(4);
    BINARY_HEAP_NODE_T arr[] = 
    {
        {12, 0, NULL}, 
        {11, 0, NULL}, 
        {13, 0, NULL}, 
        {5, 0, NULL}, 
        {6, 0, NULL}, 
        {7, 0, NULL}, 
    };

    // 插入元素
    for (int i = 0; i < sizeof(arr) / sizeof(arr[0]); i++)
    {
        min_heap_insert(heap, &arr[i]);
    }

    // 提取并打印堆顶元素
    BINARY_HEAP_NODE_T *outnode = NULL;
    printf("Min elements in order: ");
    while (heap->size > 0)
    {
        outnode = min_heap_extract(heap);
        printf("%d ", outnode->priority);
    }
    printf("\n");

    heap->size = 6;
    heap->nodes[0] = &arr[0];
    heap->nodes[1] = &arr[1];
    heap->nodes[2] = &arr[2];
    heap->nodes[3] = &arr[3];
    heap->nodes[4] = &arr[4];
    heap->nodes[5] = &arr[5];
    build_min_heap(heap);
    printf("Min elements in order: ");
    while (heap->size > 0)
    {
        outnode = min_heap_extract(heap);
        printf("%d ", outnode->priority);
    }
    printf("\n");

    BINARY_HEAP_NODE_T arr1[] = 
    {
        {1, 0, NULL}, 
        {4, 0, NULL}, 
        {5, 0, NULL}
    };

    BINARY_HEAP_NODE_T arr2[] = 
    {
        {1, 0, NULL}, 
        {3, 0, NULL}, 
        {4, 0, NULL}
    };

    BINARY_HEAP_NODE_T arr3[] = 
    {
        {2, 0, NULL}, 
        {6, 0, NULL}
    };

    for (int i = 0; i < sizeof(arr1) / sizeof(arr1[0]); i++)
    {
        min_heap_insert(heap, &arr1[i]);
    }

    for (int i = 0; i < sizeof(arr2) / sizeof(arr2[0]); i++)
    {
        min_heap_insert(heap, &arr2[i]);
    }

    for (int i = 0; i < sizeof(arr3) / sizeof(arr3[0]); i++)
    {
        min_heap_insert(heap, &arr3[i]);
    }

    printf("Min elements in order: ");
    while (heap->size > 0)
    {
        outnode = min_heap_extract(heap);
        printf("%d ", outnode->priority);
    }
    printf("\n");

    free(heap->nodes);
    free(heap);
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
    // char *log_conf_file = "./etc/test_code_logconf.json";

    if (init_logger(NULL, NULL) != 0) 
    {
        fprintf(stdout, "Init logger failed\n");
        return -1;
    }

    // if (epoll_timer_run() != 0)
    // {
    //     APP_LOG_ERROR("epoll timer went error");
    // }

    if (common_list_interface_test() != 0)
    {
        APP_LOG_ERROR("list interface test failed");
    }

    // partition_list();

    // binary_heap_test();

    // list_reverse_test();

    // sort_algo_test();

    // wait for thread.
    while (1)
    {
        sleep(1);
    }

    destroy_logger();
    return 0;
}
