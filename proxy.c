#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "log.c"
#include "utils.c"
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pcap.h>
#include "tcp_connect.c"
#include "hashmap.h"
#include "vitual_port.c"
#include "db.c"
#define PORT 8186

#define PROXY_PORT 6001
#define ASSIGNED_IP "240.0.0.1"

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define SIZE 8064 

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sockaddr_in source, dest;

typedef struct conn {
    int connection;
    int realport;
    int destport;
    int realip;
} conn_t; 

int phone_connection; 
u_char tmp_buffer[65536];

int device_clients[3];    
int vitual_clients[600];

fd_set readfds, readfds2;

char* getIp(){
    int fd;
    struct ifreq ifr;
    char iface[] = "eth0";
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    char* ip = inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
    return ip;
}

void ProcessPacket(unsigned char* buffer, 
        int size, 
        int connection, 
        hashmap* real_port_map) {
    struct iphdr *iph = (struct iphdr *)buffer;
    int iphdrlen = iph->ihl*4;
    struct sockaddr_in src, dst;
    src.sin_addr.s_addr = iph->saddr;
    dst.sin_addr.s_addr = iph->daddr; 
    u_int32_t source = iph -> saddr;      
    u_int32_t dest = iph -> daddr;
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
    unsigned short tcphdrlen = tcph -> doff*4;
    int p_port = ntohs(tcph -> dest);
    conn_t *real_conn = hashmapGet(real_port_map, p_port);
    if(real_conn == 0){
        _log("map real connection", "get real_conn error!!!!");
        return;
    }
    _logI("map real connection vitrualport", p_port);
    _logI("map real connection realport", real_conn -> realport);

    iph -> daddr = inet_addr(ASSIGNED_IP); 
    iph -> saddr = real_conn -> realip;
    iph -> check = ipCheckSum(iph, tcph, buffer, size);              
    tcph -> source = htons(real_conn -> destport);
    tcph -> dest = htons(real_conn -> realport);
    tcph -> check = tcpCheckSum(iph, tcph, buffer + iphdrlen + tcphdrlen, (size - iphdrlen - tcphdrlen));

    _logTcpDatagram(buffer, size);

    unsigned char newBuffer[65536];
    unsigned int length = size + 8;
    unsigned int identifier = 1011;

    memcpy(newBuffer, &length, 4);
    memcpy(newBuffer + 4, &identifier, 4);
    memcpy(newBuffer + 8, buffer, size);
    sendConnection(device_clients[real_conn -> connection], &readfds, newBuffer, size + 8);
    _logI("message to phone length", length);
}

ssize_t onConnectMessage(int connection, char* message, int size){
//    db_save_device_config((char *) message + strlen("config:"));
    char buffer[1024];
    int identifier = 1011;
    int length = 16;
    char* c = (char*)&length;
    char* ci = (char*)&identifier;
    sprintf(buffer, "%c%c%c%c%c%c%c%cWelcome!", c[0], c[1], c[2], c[3], ci[0], ci[1], ci[2], ci[3]);
    return sendConnection(device_clients[connection], &readfds, buffer, length);
}

/**
 * callback for pcap
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    _log("pcap", "packet recieved");
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct iphdr *ip;                 /* The IP header */
    const struct tcphdr *tcp;               /* The TCP header */
    const char *payload;                    /* Packet payload */

    hashmap* real_port_map = (hashmap *) &args[0];
    int size_ip;
    int size_tcp;
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    /* define/compute ip header offset */
    ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    size_ip = ip -> ihl*4;
    if (size_ip < 20) {
        _logI("Invalid IP header length", size_ip);
        return;
    }

    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip ->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip ->daddr;
    /* print source and destination IP addresses */

    /* define/compute tcp header offset */
    tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = tcp -> doff *4;
    if (size_tcp < 20) {
        _logI("Invalid TCP header length", size_tcp);
        return;
    }
    int tot_size = ntohs(ip -> tot_len);
    u_char buffer[tot_size];
    memcpy(buffer, packet + SIZE_ETHERNET, tot_size); 
    ProcessPacket(buffer, tot_size, 0, real_port_map);
}

int createRawSocket() {
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s == -1)
    {
        perror("Failed to create socket");
    }
    int one = 1;
    const int *val = &one;
    struct sockaddr_in serverProxy;
    serverProxy.sin_family = AF_INET;
    serverProxy.sin_addr.s_addr = INADDR_ANY;
    struct sockaddr saddr;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
    }
    return s;
}

void* 
sendPackets(char* proxy_ip, 
        char* buffer, 
        int size, 
        hashmap* fds_arr[], 
        vp_handle_t* port_pool, 
        hashmap* real_port_map, 
        int connectionIndex, 
        int rawSocket, 
        conn_t* real_conn_obj, 
        int* v_port){
    //?
    /*
    if(strncmp(buffer, tmp_buffer, size) == 0){
        return 0;
    }
    strcpy(tmp_buffer, buffer);
    */

    _log("unpack", "ip header");

    u_char* datagram = (u_char*) &buffer[8]; // start from 8, raw data
    struct iphdr *iph = (struct iphdr *) datagram;
    unsigned short iphdrlen = iph->ihl * 4;

    if((unsigned int)iph->protocol == 6)
    { 
        _log("unpack", "tcp header");

        struct tcphdr *tcph = (struct tcphdr*)(datagram + iphdrlen);
        unsigned short tcphdrlen = tcph->doff * 4;
        int tot_len = ntohs(iph -> tot_len); 
        size -= 8;

        _logTcpDatagram(datagram, size);

        // update (ip, port) -> port mapping
        unsigned int realport = ntohs(tcph -> source);
        int* is_cache = hashmapGet(fds_arr[connectionIndex], realport); 
        int vitual_port;
        if(is_cache == 0){
            *v_port = generate_port(port_pool);
            vitual_port = *v_port;
            hashmapInsert(fds_arr[connectionIndex], v_port, realport);

            real_conn_obj -> connection = connectionIndex;
            real_conn_obj -> realport = realport;
            real_conn_obj -> realip = iph -> daddr; 
            real_conn_obj -> destport = ntohs(tcph -> dest);

            hashmapInsert(real_port_map, real_conn_obj, vitual_port);
            _logI("update-vitual-port", vitual_port);
            _logI("update-real-port", realport);
        } else {
            vitual_port = *is_cache; 
            _logI("set-vitual-port", vitual_port);
            _logI("set-real-port", realport);
        }

        //print_payload(datagram, size - 8);
        iph -> daddr = inet_addr(proxy_ip);
        char* source_ip = getIp(source_ip);
        iph -> saddr = inet_addr(source_ip); 
        iph -> check = ipCheckSum(iph, tcph, datagram, tot_len);              

        tcph -> dest = htons(PROXY_PORT);
        tcph -> source = htons(vitual_port);
        tcph -> check = tcpCheckSum(iph, tcph, datagram + iphdrlen + tcphdrlen, (tot_len - iphdrlen - tcphdrlen));

        // send to ip address
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = tcph -> dest;
        dest.sin_addr.s_addr = iph -> daddr;
        if (sendto (rawSocket, datagram, ntohs(iph -> tot_len),  0, (struct sockaddr *) &dest, sizeof (dest)) < 0) {
            perror("sendto failed");
            _log("raw socket-error", "send to fail");
        } else {
            _logI("raw socket-sent", ntohs(iph -> tot_len));
        }
    } else {
        _log("not tcp pack", "fail to send");
        print_ip_header(datagram, size);
    }
}

char* filterRule(char* proxy_ip) {
    char* filter_exp = (char*) malloc(1000);
    sprintf(filter_exp, "src host %s && src port %d", proxy_ip, PROXY_PORT); 
    return filter_exp;
}

pcap_t * initPcap(char* proxy_ip) {
    _log("init pcap", proxy_ip);
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;    
    struct pcap_pkthdr header;
    // bpf_u_int32 mask;        /* The netmask of our sniffing device */
    bpf_u_int32 net;        /* The IP of our sniffing device */
    char* device = pcap_lookupdev(errbuf);

    // dev = "lo";
    if (device == NULL) {
        exitWithLog("Couldn't find default device", errbuf);
    }
    handle = pcap_open_live(device, BUFSIZ, 1, 2000, errbuf);
    if (handle == NULL) {
        exitWithLog("Couldn't open device", errbuf);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        exitWithLog("not an Ethernet", device);
    }
    /* set non block*/
    if(pcap_setnonblock(handle, 1, errbuf) == -1) {
        exitWithLog("set block fail", errbuf);
    }

    char filter_exp[1000];
    sprintf(filter_exp, "src host %s && src port %d", proxy_ip, PROXY_PORT); 

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        exitWithLog("Couldn't parse filter", pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        exitWithLog("Couldn't install filter", pcap_geterr(handle));
    }

    return handle;
}

struct IPPort {
    hashmap* real_port_map;
    hashmap** fds_arr;
};

/**
 * gateway server
 *
 * target server
 *
 * SPDY encryption-descryption server
 *
 * http content tamper server
 */
int main(int argc, const char * argv[]) {
    _log("main", "aproxy running...");
    // encryption-descryption server ip
    char* proxy_ip = get_aserver_config();
    _log("proxy_ip", proxy_ip);

    struct sockaddr_in address = getAddr(PORT);
    /**
     * tsi : target server ip
     * tsp : target server port
     * cp: client port
     * ci: client ip
     *
     * vp -> (tsi, tsp, cp, ci, fd)
     */
    hashmap* real_port_map = hashmapCreate(SIZE); 

    vp_handle_t port_pool = create_port_pool();
    /**
     * (cp) client port: client request source port
     * (vp) virtual port: gateway server source port
     *
     * (fd, cp) -> vp
     */
    hashmap* fds_arr[3];

    int j;
    for(j = 0; j < 3; j++) {
        fds_arr[j] = hashmapCreate(SIZE);
    }

    // Create socket server
    _log("init", "create socket server");
    int master_socket = 0;
    conn_init(&master_socket, device_clients, address,  3);
    int max_sd = master_socket;

    // Create a raw socket
    int rawSocket = createRawSocket();

    pcap_t *handle = initPcap(proxy_ip); 

    while(1) {
        u_char buffer[65536];
        u_char* arg_array = (u_char*) real_port_map;
        pcap_dispatch(handle, -1, got_packet, arg_array);

        _log("loop accept", "start");
        int acpt = loopAccept(&master_socket, device_clients, &readfds, address, 3, &max_sd);
        _log("loop accept", "end");

        if(acpt < 0) {
            continue;
        }
        int i; 
        for(i = 0; i < 3; i++){
            int receivedSize = readConnection(i, device_clients, &readfds, buffer);
            int fds = device_clients[i];
            if(receivedSize) {
                _logI("received", receivedSize);
                u_char* datagram = (u_char*) &buffer[8];

                if(strncmp(datagram, "config:", strlen("config:")) == 0){
                    int length = *(int*) &buffer[0];
                    _log("raw-config", datagram);
                    onConnectMessage(i, datagram, length);
                } else {
                    conn_t *real_conn_obj;
                    real_conn_obj = (conn_t *) malloc(sizeof(conn_t));
                    int* v_port;
                    v_port = (int*) malloc(sizeof(int));
                    sendPackets(proxy_ip, 
                            buffer, 
                            receivedSize, 
                            fds_arr, 
                            &port_pool, 
                            real_port_map, 
                            i, 
                            rawSocket, 
                            real_conn_obj, 
                            v_port);
                }
            } else {
                //printf("reciedved: No.%d - %d \n", i, receivedSize);
            }
        }   
    }
}       
