/**
 *    Handle multiple socket connections with select and fd_set on Linux
 */

#include <stdio.h>
#include <string.h>   //strlen
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>   //close
#include <arpa/inet.h>    //close
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include "utils.h"

#define TRUE   1
#define FALSE  0
#define BUFFER_SIZE 63325

struct sockaddr_in getAddr(int port){
    struct sockaddr_in address; 
    //type of socket created
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    return address; 
} 

int conn_init(int *master_socket, int client_socket[], struct sockaddr_in address, int max_clients) {
    int opt = TRUE;
    int i;
    char buffer[BUFFER_SIZE];
    //initialise all client_socket[] to 0 so not checked
    for (i = 0; i < max_clients; i++) 
    {
        client_socket[i] = 0;
    }
    //create a master socket
    if( (*master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0) 
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    //set master socket to allow multiple connections , this is just a good habit, it will work without this
    if( setsockopt(*master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 )
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    //bind the socket to localhost port
    if (bind(*master_socket, (struct sockaddr *)&address, sizeof(address))<0) 
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    //try to specify maximum of 3 pending connections for the master socket
    if (listen(*master_socket, max_clients) < 0) // TODO find out difference between one and more connections
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    //accept the incoming connection
    return 0;
}

int loopAccept(int *master_socket, int client_socket[], fd_set* readfds, struct sockaddr_in address, int max_clients, int *max_sd){
    int new_socket , activity, i, sd;
    FD_ZERO(readfds);

    int addrlen = sizeof(address);
    //add master socket to set
    FD_SET(*master_socket, readfds);
    //add child sockets to set
    for ( i = 0 ; i < max_clients ; i++) 
    {
       //socket descriptor
       sd = client_socket[i];
       //if valid socket descriptor then add to read list
       if(sd > 0)
           FD_SET( sd , readfds);

        //highest file descriptor number, need it for the select function
       if(sd > *max_sd)
            *max_sd = sd;
    }

    //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
    activity = select( *max_sd + 1 , readfds , NULL , NULL , NULL);

    if ((activity < 0) && (errno!=EINTR)) 
    {
        printf("select error");
    }

    //If something happened on the master socket , then its an incoming connection
    if (FD_ISSET(*master_socket, readfds)) 
    {
        if ((new_socket = accept(*master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        //inform user of socket number - used in send and receive commands
       // printf("New connection , socket fd is %d , ip is : %s , port : %d \n" , new_socket , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));

        //add new socket to array of sockets
        for (i = 0; i < max_clients; i++) 
        {
            //if position is empty
            if( client_socket[i] == 0 )
            {
                client_socket[i] = new_socket;
               // printf("Adding to list of sockets as %d\n" , i);

                break;
            }
        }
    }   
}

int readConnection(int i, int client_socket[], fd_set* readfds, char* buffer){
    int sd = client_socket[i];
    int len = 0;
    if (FD_ISSET(sd , readfds)) 
    {
        if ((len = read( sd , buffer, BUFFER_SIZE)) == 0)
        {
            //Somebody disconnected , get his details and print
            struct sockaddr_in address; 
            int addrlen = sizeof(address);
            getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);
            //printf("Host disconnected , ip %s , port %d \n" , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));
            //Close the socket and mark as 0 in list for reuse
            close( sd );
            client_socket[i] = 0;
        }
    }
    return len;
}

int sendConnection(int sd, fd_set* readfds, char* buffer, int length){ 
    if (FD_ISSET(sd , readfds)) 
    {
        send(sd , buffer , length, 0 );
    }
}

