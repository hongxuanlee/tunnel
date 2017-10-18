#include "log.h"

char* getFormattedTime() {
    time_t rawtime;
    struct tm* timeinfo;

    struct timeval tmnow;
    gettimeofday(&tmnow, NULL);

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    // Must be static, otherwise won't work
    static char _retval[24];
    char msec[4];
    strftime(_retval, sizeof(_retval), "%Y-%m-%d %H:%M:%S", timeinfo);
    sprintf(msec,".%03d",(tmnow.tv_usec / 1000));
    strcat(_retval, msec);

    return _retval;
}

char* getFormattedDay(){
    time_t rawtime;
    struct tm* timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    static char _retval[11];
    strftime(_retval, sizeof(_retval), "%Y-%m-%d", timeinfo);

    return _retval;
}

void PrintData (unsigned char* data , int Size)
{
    int i,j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet

                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 

        if(i%16==0) printf("   ");
        printf(" %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) printf("   "); //extra spaces

            printf("         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}

void writeFile(char* str){
    char* day = getFormattedDay();
    FILE *fp;
    char filename[100];
    sprintf(filename, "../../logs/tcp_flow.log.%s", day);
    fp = fopen(filename, "a");
    fputs(str, fp);
    fputs("\n", fp);
    fclose(fp);
}

void getFlag(struct tcphdr* tcph, char* flag){
    if(tcph -> syn != 0) strcat(flag, "S");
    if(tcph -> ack != 0) strcat(flag, "A");
    if(tcph -> psh != 0) strcat(flag, "P");
    if(tcph -> rst != 0) strcat(flag, "R");
    if(tcph -> fin != 0) strcat(flag, "F");
    if(tcph -> urg != 0) strcat(flag, "U");
}

void _logTcpDatagram(unsigned char* Buffer, int Size){
    char str[1024]; 
    struct iphdr *iph = (struct iphdr *)Buffer;

    struct in_addr source; 
    struct in_addr dest; 

    source.s_addr = iph -> saddr;
    char* src_ip  = malloc(32);
    strcpy(src_ip, inet_ntoa(source));

    dest.s_addr = iph -> daddr;
    char* dst_ip = malloc(32);
    strcpy(dst_ip, inet_ntoa(dest));

    char* time = getFormattedTime();
    unsigned short iphdrlen = iph->ihl*4;

    struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen); 

    char flags[6];
    flags[0] = '\0';
    getFlag(tcph, flags);

    unsigned long seq = ntohl(tcph -> seq);
    unsigned long ack = ntohl(tcph -> ack);

    sprintf(str, "%s (flags: [%s]) %s:%d > %s:%d, seq: %d, ack: %d, win: %d, length: %d bytes ", time, flags, src_ip, ntohs(tcph -> source),dst_ip, ntohs(tcph -> dest), seq, ack, ntohs(tcph -> window), ntohs(iph -> tot_len));

    LOGINFO("%s", str);
    // writeFile(str);

    free(src_ip);
    free(dst_ip);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
    struct sockaddr_in source, dest;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("\n");
    printf("src_ip: %s",inet_ntoa(source.sin_addr));
    printf("  dest_ip: %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    struct iphdr *iph = (struct iphdr *) Buffer;
    unsigned short iphdrlen = iph->ihl*4;
    print_ip_header(Buffer, Size);
    struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen); 
    printf("src_port: %u",ntohs(tcph->source));
    printf("  dest_port: %u\n",ntohs(tcph->dest));

}

void print_payload(unsigned char* Buffer, int Size){
    struct iphdr *iph = (struct iphdr *) Buffer;
    unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen); 
    if(Size - tcph->doff*4-iph->ihl*4 > 0){
        printf("Data Payload\n");  
        PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
    }
}

void _log(char *title, char* content) {
   printf(getFormattedTime());
   printf("[");
   printf(title); 
   printf("]");
   printf(content); 
   printf("\n"); 
}

void _logI(char* title, int content) {
   printf(getFormattedTime());
   printf("[");
   printf(title); 
   printf("]");
   printf("%d", content); 
   printf("\n"); 
}

