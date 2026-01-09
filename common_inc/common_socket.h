#ifndef __COMMON_SOCKET_H__
#define __COMMON_SOCKET_H__

#ifdef __cplusplus
extern "C" {
#endif

int tcp_server_init(int port, int support_client_size);
int tcp_server_accept(int server_fd);
int tcp_server_msg_send(int client_fd, char *message, int message_len);
int tcp_server_msg_recv(int client_fd, char *message, int message_size);
void tcp_server_destroy(int sock);

int tcp_client_init(int port, char *server_ip);
int tcp_client_send_msg(int sock, char *message, int message_len);
int tcp_client_recv_msg(int sock, char *message, int message_size);
void tcp_client_destroy(int sock);

#ifdef __cplusplus
}
#endif

#endif