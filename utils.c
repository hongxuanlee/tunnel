#include "utils.h"

int ip_match(u_int32_t addr1, u_int32_t addr2)
{
    //printf("match %d, %d \n", addr1, addr2); 
    int res = !(addr1 ^ addr2);
    //printf("res %d \n", res);
    return res;
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);

    return(short)~sum;
}

unsigned short ipCheckSum(struct iphdr* iph, struct tcphdr* tcph, char* data, int size)
{
    iph -> check = 0;
    unsigned int ip_len = iph -> ihl * 4;
    unsigned int tcp_len = tcph -> doff * 4;
    char pseudoData[65536];
    memset(pseudoData, 0, 65536);
    memcpy(pseudoData, data, 20);
    return csum((unsigned short *)pseudoData, 20);
}

unsigned short tcpCheckSum(struct iphdr* iph, struct tcphdr* tcph, char* data, int size)
{
    tcph -> check = 0;
    struct pseudoHeader psd_header;
    psd_header.ip_src = iph -> saddr;
    psd_header.ip_dst = iph -> daddr;
    psd_header.zero = 0;
    psd_header.protocol= IPPROTO_TCP;
    unsigned int tcp_len = tcph -> doff * 4;
    psd_header.tcp_len = htons(tcp_len + size);

    int psize = sizeof(struct pseudoHeader) + tcp_len + size;

    char* tcpBuf = malloc(psize);
    memcpy(tcpBuf, &psd_header, sizeof(struct pseudoHeader));
    memcpy(tcpBuf + sizeof(struct pseudoHeader), tcph, tcp_len + size);
    return csum((unsigned short *)tcpBuf, psize);
}

int in_array(int val, int *arr, int size){
    int i;
    for (i = 0; i < size; i++) {
        if (arr[i] && arr[i] == val)
            return i;
    }
    return -1;
}

void str_replace(char *target, const char *needle, const char *replacement)
{
    char buffer[65536] = { 0 };
    char *insert_point = &buffer[0];
    const char *tmp = target;
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(replacement);

    while (1) {
        const char *p = strstr(tmp, needle);

        if (p == NULL) {
            strcpy(insert_point, tmp);
            break;
        }

        memcpy(insert_point, tmp, p - tmp);
        insert_point += p - tmp;

        memcpy(insert_point, replacement, repl_len);
        insert_point += repl_len;

        tmp = p + needle_len;
    }

    strcpy(target, buffer);
}


void exitWithLog(char* title, char* message) {
    _log(title, message);
    exit(2);
}
