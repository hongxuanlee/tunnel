#ifndef LOG_H_
#define LOG_H_
//
//Returns the local date/time formatted as 2017-03-19 11:11:52
char* getFormattedTime(void);

// Remove path from filename
#define __SHORT_FILE__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
// Main log macro
#define __LOG__(format, loglevel, ...) printf("%s %-5s [%s] [%s:%d] " format "\n", getFormattedTime(), loglevel, __func__, __SHORT_FILE__, __LINE__, ## __VA_ARGS__)

// Specific log macros with 
#define LOGDEBUG(format, ...) __LOG__(format, "DEBUG", ## __VA_ARGS__)
#define LOGWARN(format, ...) __LOG__(format, "WARN", ## __VA_ARGS__)
#define LOGERROR(format, ...) __LOG__(format, "ERROR", ## __VA_ARGS__)
#define LOGINFO(format, ...) __LOG__(format, "INFO", ## __VA_ARGS__)

#define LOGNAME "tcp_flow.log"

void generatorLog(unsigned char* Buffer, int Size);

void PrintData (unsigned char* data , int Size);

void print_ip_header(unsigned char* Buffer, int Size);

void print_tcp_packet(unsigned char* Buffer, int Size);

#endif
