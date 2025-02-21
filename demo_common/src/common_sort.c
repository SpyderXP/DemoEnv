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
*  函数功能  : 冒泡排序 - O(n^2).
*  输入参数  : arr - 待排序数组.
*             arrnum - 数据个数.
*  输出参数  : 无.
*  返回值    : 无.
*************************************************************************/
int bubble_sort(int *arr, int arrnum)
{
    int tmp = 0;
    int flag = 0;

    for (int i = 0; i < arrnum - 1; i++)
    {
        for (int j = 0; j < arrnum - i - 1; j++)
        {
            if (arr[j] > arr[j + 1])
            {
                tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
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
    int tmp = 0;

    for (int i = 1; i < arrnum; i++)
    {
        for (int j = i; j >= 1; j--)
        {
            if (arr[j] < arr[j - 1])
            {
                tmp = arr[j];
                arr[j] = arr[j - 1];
                arr[j - 1] = tmp;
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
