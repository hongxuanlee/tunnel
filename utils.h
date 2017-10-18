#ifndef UTILS_H_
#define UTILS_H_

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "log.h"

struct pseudoHeader
{
    u_int32_t  ip_src;
    u_int32_t  ip_dst;
    u_int8_t zero;   //always zero
    u_int8_t protocol;  //for tcp
    u_int16_t tcp_len;
};

int ip_match(u_int32_t addr1, u_int32_t addr2);
    
unsigned short csum(unsigned short *ptr,int nbytes);

unsigned short ipCheckSum(struct iphdr* iph, struct tcphdr* tcph, char* data, int size);

unsigned short tcpCheckSum(struct iphdr* iph, struct tcphdr* tcph, char* data, int size);

int in_array(int val, int *arr, int size);

void exitWithLog(char* title, char* message);

#endif
