#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "../lib-src/tinytls/tinytls.h"

#define MAX_BUFFER_LEN 4096

// 打印 socket 错误
void print_sock_error(const char *msg) {
    perror(msg);
}

// 从 URL 中提取主机名和路径
void parse_url(const char *url, char **host, char **path) {
    char *start;
    char *end;

    if (strstr(url, "https://") == url) {
        start = (char *)url + strlen("https://");
    } else {
        *host = NULL;
        *path = NULL;
        return;
    }

    end = strchr(start, '/');
    if (end) {
        *host = (char *)malloc(end - start + 1);
        strncpy(*host, start, end - start);
        (*host)[end - start] = '\0';
        *path = strdup(end);
    } else {
        *host = strdup(start);
        *path = strdup("/");
    }
}

int main(int argc, char *argv[]) {
    int ret = 0;
    char *url = NULL;
    char *txt = NULL;
    char *host = NULL;
    char *path = NULL;
    const char *port = "443";
    int i;
    int sockfd = -1;
    struct tinytls_ctx *tls = NULL;

    // 参数解析：-url= 和 -txt=
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-url=", 5) == 0) {
            url = argv[i] + 5;
        } else if (strncmp(argv[i], "-txt=", 5) == 0) {
            txt = argv[i] + 5;
        }
    }

    if (!url || !txt) {
        fprintf(stderr, "Usage: %s -url=WEBHOOK_URL -txt=MESSAGE_TEXT\n", argv[0]);
        return 1;
    }

    parse_url(url, &host, &path);
    if (!host || !path) {
        fprintf(stderr, "Invalid webhook URL format.\n");
        ret = -1;
        goto exit;
    }

    // 域名解析
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        print_sock_error("getaddrinfo");
        ret = -1;
        goto exit;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        print_sock_error("socket");
        ret = -1;
        freeaddrinfo(res);
        goto exit;
    }
    printf("Connecting to %s:%s...\n", host, port);
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        print_sock_error("connect");
        ret = -1;
        freeaddrinfo(res);
        goto exit;
    }
    freeaddrinfo(res);
    printf("Connection successful.\n");

    // TLS初始化和握手
    tls = tinytls_client_create(sockfd, host);
    if (!tls) {
        fprintf(stderr, "tinytls_client_create failed\n");
        ret = -1;
        goto exit;
    }
    if (tinytls_client_handshake(tls) != 0) {
        fprintf(stderr, "TLS handshake failed\n");
        ret = -1;
        goto exit;
    }
    printf("Handshake successful.\n");

    // 构建 JSON 消息
    char json_msg[MAX_BUFFER_LEN];
    snprintf(json_msg, sizeof(json_msg),
             "{\"msgtype\": \"text\", \"text\": {\"content\": \"%s\"}}",
             txt);

    // 构建 HTTP 请求
    char request_buffer[MAX_BUFFER_LEN];
    snprintf(request_buffer, sizeof(request_buffer),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/json;charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             path, host, strlen(json_msg), json_msg);

    printf("Sending DingTalk message...\n");
    if (tinytls_client_write(tls, request_buffer, strlen(request_buffer)) <= 0) {
        fprintf(stderr, "TLS write failed\n");
        ret = -1;
        goto exit;
    }

    printf("Reading server response:\n");
    unsigned char buf[1024];
    int n;
    do {
        n = tinytls_client_read(tls, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("%s", buf);
        }
    } while (n > 0);

exit:
    if (host) free(host);
    if (path) free(path);
    if (tls) tinytls_client_free(tls);
    if (sockfd >= 0) close(sockfd);
    return ret;