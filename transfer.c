#include <stdio.h>
#include <string.h>   //strlen
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>   
#include <arpa/inet.h>   
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include <string.h>
#include <netdb.h>
#include <curl/curl.h>
#include "tcp_connect.c"
#include "utils.c"

#define LOCAL "127.0.0.1"
#define LOCAL_PORT 8080

// for test proxy
#define PROXY "30.8.70.185"
#define PORT 8088

struct string {
    char *ptr;
    size_t len;
};

typedef struct req_host{
    char *ip;
    int port;
} req_host;

void init_string(struct string *s) {
    s->len = 0;
    s->ptr = malloc(s->len+1);
    if (s->ptr == NULL) {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

int hostname_to_ip(char *hostname , char *ip)
{
    int sockfd;  
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ( (rv = getaddrinfo( hostname , "http" , &hints , &servinfo)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
    for(p = servinfo; p != NULL; p = p->ai_next) 
    {
        h = (struct sockaddr_in *) p->ai_addr;
        strcpy(ip , inet_ntoa( h->sin_addr ) );
    }
    freeaddrinfo(servinfo); 
    return 0;
}

req_host handle_http_request(char* buffer){
    char req[65536];
    strcpy(req, buffer);
    char* getHost = strstr(req, "Host: ") + 6; 
    printf("getHost: %s", getHost);
    char* host = strtok(getHost, "\n");
    printf("host: %s \n ", host);
    req_host rh;
    int port;
    if(strstr(host, ":") != NULL){
        char* ch;
        char* ip;
        ip = strtok(host, ":");
        port = atoi(strtok(NULL, "\0")); 
        rh.ip = ip;
    }else{
        char ip[100];
        hostname_to_ip(host, ip);
        port = 80;
        rh.ip = ip;
    }
    rh.port = port;
    return rh;
}

char* replace_header(char* message, int size){
    const char* append = "Proxy-Connection: keep-alive\r\n";
    const char* needle = "Host: h5.m.taobao.com\r\n";
    const char* replacement = "Host: h5.m.taobao.com\r\nProxy-Connection: keep-alive\r\n";
    //  const char* needle = "Connection: keep-alive";
    //  const char* replacement = "Proxy-Connection: keep-alive";
    str_replace(message, needle, replacement);
    str_replace(message, "GET /src/hanquan_test.html", "GET http://h5.m.taobao.com/src/hanquan_test.html");
    int add_size = strlen(append);
    return message;
}

int is_http_request(char* message){
    char req[65536];
    strcpy(req, message);
    if (strstr(req, "HTTP/1.1") != NULL) {
        return 1;
    }
    return 0;
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = realloc(s->ptr, new_len+1);
    if (s->ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size*nmemb;
}


void curl(char* url, struct string s){
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if(curl) {
        init_string(&s);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
        res = curl_easy_perform(curl);

        printf("data: %s\n", s.ptr);
        free(s.ptr);
        /* always cleanup */
        curl_easy_cleanup(curl);
    }
}

int tcp_request(char* message, char* server_reply, char* url, int port){
    int sock;
    struct sockaddr_in server;
    sock = socket(AF_INET , SOCK_STREAM , 0);
    int reply_length = 0;
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    printf("Socket created %s \n", url);

    server.sin_addr.s_addr = inet_addr(url);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (connect(sock, (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        printf("url:%s \n", url);
        perror("connect failed. Error");
        return -1;
    }
    int len = 0;
    puts("Connected\n");
    if( write(sock , message , strlen(message)) < 0)
    {
       puts("Send failed");
       return -1;
    } 
    int received = 0;
    while(len = read(sock, server_reply + received, 65536 - received) > 0)
    {
       received += len;
       printf("stream: %s \n", server_reply);
       break;
    }
    close(sock);
    return received;
}

int http_request(char* message, char* server_reply, char* url, int port){
    int sock;
    struct sockaddr_in server;
    sock = socket(AF_INET , SOCK_STREAM , 0);
    int reply_length = 0;
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    printf("Socket created %s \n", url);

    server.sin_addr.s_addr = inet_addr(url);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (connect(sock, (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        printf("url:%s \n", url);
        perror("connect failed. Error");
        return -1;
    }
    int len = 0;
    puts("Connected\n");
    if( write(sock , message , strlen(message)) < 0)
    {
       puts("Send failed");
       return -1;
    } 
    int received = 0;
    memset(server_reply, 0, 65536);
    while(len = read(sock, server_reply, 65536) > 0)
    {
       printf("**************** %d \n", len);
       received += len;
       printf("stream: %s \n", server_reply);
       memset(server_reply, 0, 65536);
    }
    printf("recieved done!!...\n");
    close(sock);
    return received;
}

int request(char* message, char* reply){
    printf("request start \n");
    if(is_http_request(message) == 0){
        return -1; 
    }    
    message = replace_header(message, strlen(message));
    int reply_size = http_request(message, reply, PROXY, PORT);
    // int reply_size = tcp_request(decode_message, server_reply, req.ip, req.port);
    printf("http request done.....\n");
    if(reply_size < 0){
        printf("request http failed!! \n"); 
    }
    return reply_size;
}

void main(){
    //Create a tcp socket
    int master_socket = 0;
    int clients[30];
    struct sockaddr_in address = getAddr(8888);
    conn_init(&master_socket, clients, address, 30);
    printf("conn_init done! \n");
    fd_set readfds;
    int max_sd = master_socket;
    int i, receivedSize;
    char buffer[65536], server_reply[65536];
    while(1){
        loopAccept(&master_socket, clients, &readfds, address, 30, &max_sd);
        for(i = 0; i < 30; i++) {
            receivedSize = readConnection(i, clients, &readfds, buffer);
            if(receivedSize){
                printf("receive size from client.....\n");
                buffer[receivedSize] = '\0'; 
                int size = request(buffer, server_reply);
                if(size > 0){
                    int fds = clients[i];
                    //char* newBuffer; 
                    sendConnection(clients[i], &readfds, server_reply, size);
                }
            } 
        }
    }
}
