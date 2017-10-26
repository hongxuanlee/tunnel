#ifndef LOG_H_
#define LOG_H_

#include <stdio.h> //for printf
#include <string.h> //memset
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>

//Returns the local date/time formatted as 2017-03-19 11:11:52
char* getFormattedTime(void);

/**
 * log_level
 * error : 0,
 * warning: 1,
 * info: 2,
 * debug: 3
 *
 */
#define LOG_LEVEL 3
// Remove path from filename
#define __SHORT_FILE__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
//
// Main log macro
#define __LOG__(format, loglevel, ...) printf("[%s] [%-5s [%s] [%s:%d] " format "\n", getFormattedTime(), loglevel, __func__, __SHORT_FILE__, __LINE__, ## __VA_ARGS__)

// simple log, not include func
#define __LOG_S(format, loglevel, ...) printf("[%s] [%-5s] " format "\n", getFormattedTime(), loglevel,  ## __VA_ARGS__)

// Specific log macros with 
#if LOG_LEVEL > 2
    #define LOGDEBUG(format, ...) __LOG_S(format, "DEBUG", ## __VA_ARGS__)
#else
    #define LOGDEBUG(format, ...) 
#endif

#if LOG_LEVEL>1
    #define LOGINFO(format, ...) __LOG_S(format, "INFO", ## __VA_ARGS__)
#else
    #define LOGINFO(format, ...)
#endif


#if LOG_LEVEL>0
    #define LOGWARN(format, ...) __LOG__(format, "WARN", ## __VA_ARGS__)
#else
    #define LOGWARN(format, ...)
#endif

#define LOGERROR(format, ...) __LOG__(format, "ERROR", ## __VA_ARGS__)

#define LOGNAME "tcp_flow.log"

void _logTcpDatagram(unsigned char* Buffer, int Size);

void PrintData (unsigned char* data , int Size);

void print_ip_header(unsigned char* Buffer, int Size);

void print_payload(unsigned char* Buffer, int Size);
void print_tcp_packet(unsigned char* Buffer, int Size);

void _log(char* title, char* content);
void _logI(char* title, int content);

#endif
