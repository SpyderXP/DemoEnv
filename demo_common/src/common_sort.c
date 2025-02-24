/******************************************************************************
  *  文件名     : common_sort.c
  *  负责人     : xupeng
  *  创建日期   : 20250219
  *  版本号     : v1.1 
  *  文件描述   : 通用数据排序接口.
  *  其他       : 无.
  *  修改日志   : 无.
******************************************************************************/
#include "common_sort.h"

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250219
*  函数功能  : 整数交换.
*  输入参数  : a - 整数a.
*             b - 整数b.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250219
*  函数功能  : 冒泡排序 - O(n^2).
*  输入参数  : arr - 待排序数组.
*             arrnum - 数据个数.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
int bubble_sort(int *arr, int arrnum)
{
    int flag = 0;

    for (int i = 0; i < arrnum - 1; i++)
    {
        for (int j = 0; j < arrnum - i - 1; j++)
        {
            if (arr[j] > arr[j + 1])
            {
                swap(&arr[j], &arr[j + 1]);
                flag = 0;
            }
        }

        if (flag != 0)
        {
            break;
        }
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250219
*  函数功能  : 插入排序 - O(n^2).
*  输入参数  : arr - 待排序数组.
*             arrnum - 数据个数.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
int insert_sort(int *arr, int arrnum)
{
    for (int i = 1; i < arrnum; i++)
    {
        for (int j = i; j >= 1; j--)
        {
            if (arr[j] < arr[j - 1])
            {
                swap(&arr[j], &arr[j - 1]);
            }
            else 
            {
                break;
            }
        }
    }

    return 0;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250219
*  函数功能  : 合并两个子数组.
*  输入参数  : arr - 待排序数组.
*             arrnum - 数据个数.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
void merge(int *arr, int *left, int left_size, int *right, int right_size)
{
    int i = 0;
    int j = 0;
    int k = 0;

    /* 合并两个有序数组 */
    while (i < left_size && j < right_size) 
    {
        if (left[i] <= right[j])
        {
            arr[k++] = left[i++];
        }
        else 
        {
            arr[k++] = right[j++];
        }
    }

    /* 复制剩余的元素（如果有） */
    while (i < left_size)
    {
        arr[k++] = left[i++];
    }

    while (j < right_size)
    {
        arr[k++] = right[j++];
    }

    return ;
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250219
*  函数功能  : 归并排序 - O(nlogn).
*  输入参数  : arr - 待排序数组.
*             arrnum - 数据个数.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
int merge_sort(int *arr, int arrnum)
{
    int mid = arrnum / 2;
    int left[mid];
    int right[arrnum - mid];

    if (arrnum < 2) 
    {
        return 0;
    }

    /* 将原数组分成两部分 */
    for (int i = 0; i < mid; i++) 
    {
        left[i] = arr[i];
    }

    for (int i = mid; i < arrnum; i++) 
    {
        right[i - mid] = arr[i];
    }

    /* 递归调用 */
    merge_sort(left, mid);
    merge_sort(right, arrnum - mid);

    /* 合并两个已排序的子数组 */
    merge(arr, left, mid, right, arrnum - mid);

    return 0;
}

/*
    8 4 3 2 7 5 6 1
    max_heapify(arr, 8, 3)
        largest = 3, left = 7, right = 8
    8 4 3 6 7 5 2 1

    max_heapify(arr, 8, 2)
        largest = 2, left = 5, right = 6
    8 4 5 6 7 3 2 1

    max_heapify(arr, 8, 1)
    max_heapify(arr, 8, 0)

*/

// 维护最大堆
void max_heapify(int *arr, int arrnum, int i)
{
    int largest = i; // 初始化最大为根节点
    int left = 2 * i + 1; // 左子节点
    int right = 2 * i + 2; // 右子节点

    // 如果左子节点大于根节点
    if (left < arrnum && arr[left] > arr[largest])
    {
        largest = left;
    }

    // 如果右子节点大于当前最大值
    if (right < arrnum && arr[right] > arr[largest])
    {
        largest = right;
    }

    // 如果最大值不是根节点
    if (largest != i)
    {
        swap(&arr[i], &arr[largest]);

        // 递归地对受影响的子树进行堆化
        max_heapify(arr, arrnum, largest);
    }
}

// 构建最大堆
void build_max_heap(int *arr, int arrnum)
{
    for (int i = arrnum / 2 - 1; i >= 0; i--)
    {
        max_heapify(arr, arrnum, i);
    }
}

/************************************************************************* 
*  负责人    : xupeng
*  创建日期  : 20250219
*  函数功能  : 堆排序 - O(nlogn).
*  输入参数  : arr - 待排序数组.
*             arrnum - 数据个数.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
int heap_sort(int *arr, int arrnum)
{
    /* 构建最大堆 */
    build_max_heap(arr, arrnum);

    /* 一个个从堆中提取元素 */
    for (int i = arrnum - 1; i > 0; i--)
    {
        /* 将当前根节点（最大值）移到数组末尾 */
        swap(&arr[0], &arr[i]);

        /* 调用max_heapify重建最大堆 */
        max_heapify(arr, i, 0);
    }

    return 0;
}
