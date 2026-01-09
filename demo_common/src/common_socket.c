#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common_socket.h"

int tcp_server_init(int port, int support_client_size)
{
    int server_fd = -1;
    struct sockaddr_in address;
    int opt = 1;

    // 创建Socket文件描述符
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        goto FAIL;
    }

    // 绑定Socket到端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // 接受任意网卡的连接
    address.sin_port = htons(port);        // 端口转为网络字节序

    // 设置端口复用
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        goto FAIL;
    }

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        goto FAIL;
    }

    // 开始监听连接请求
    if (listen(server_fd, 3) < 0)
    {
        goto FAIL;
    }

    return server_fd;

FAIL:
    if (server_fd != -1)
    {
        close(server_fd);
    }

    return -1;
}

int tcp_server_accept(int server_fd)
{
    int client_fd = 0;
    struct sockaddr_in address;
    int addrlen = 0;

    // 接受连接
    if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0)
    {
        close(server_fd);
        return -1;
    }

    return client_fd;
}

int tcp_server_msg_send(int client_fd, char *message, int message_len)
{
    if (NULL == message)
    {
        return -1;
    }

    // 发送响应给客户端
    if (send(client_fd, message, message_len, 0) < 0)
    {
        return -1;
    }

    return 0;
}

int tcp_server_msg_recv(int client_fd, char *message, int message_size)
{
    int readsize = 0;

    if (NULL == message)
    {
        return -1;
    }

    // 读取客户端数据
    readsize = read(client_fd, message, message_size - 1);
    if (readsize > 0)
    {
        message[readsize] = '\0';
    }
    else if (0 == readsize)
    {
        return 0;
    }
    else 
    {
        return -1;
    }

    return 0;
}

void tcp_server_destroy(int sock)
{
    if (sock != -1)
    {
        close(sock);
    }

    return ;
}

int tcp_client_init(int port, char *server_ip)
{
    int client_fd = 0;
    struct sockaddr_in serv_addr;

    if (NULL == server_ip)
    {
        return -1;
    }

    // 创建Socket
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return -2;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // 将IP地址从文本转换为二进制形式
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0)
    {
        close(client_fd);
        return -3;
    }

    // 连接到服务器
    if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        close(client_fd);
        return -4;
    }

    return client_fd;
}

int tcp_client_send_msg(int sock, char *message, int message_len)
{
    if (NULL == message)
    {
        return -1;
    }

    return send(sock, message, message_len, 0);
}

int tcp_client_recv_msg(int sock, char *message, int message_size)
{
    if (NULL == message)
    {
        return -1;
    }

    return read(sock, message, message_size);
}

void tcp_client_destroy(int sock)
{
    close(sock);
    return ;
}
