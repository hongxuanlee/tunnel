#include <stdio.h>
#include <mysql/mysql.h>
#include <string.h>
#include <stdlib.h>
#include "config.c"

void db_init(MYSQL **conn){
  dbconf config;
  get_db_config(&config);
  char *server = config.db_host;
  char *user = config.db_user;
  char *password = config.db_pwd;
  char *database = config.db_database;
  int port = config.db_port;
  *conn = mysql_init(NULL);
  if (!mysql_real_connect(*conn, server, user, password, database, port, NULL, 0)) {
    fprintf(stderr, "%s\n", mysql_error(*conn));
  }
}

int proxy_select_data(char* deviceId){
  MYSQL *conn;
  db_init(&conn);
  char query[100];
  sprintf(query, "SELECT * FROM device2proxy WHERE device_id = \"%s\"", deviceId);
  printf("query %s \n", query);
  if (mysql_query(conn, query)) {
    fprintf(stderr, "%s\n", mysql_error(conn));
    printf("error\n");
    return -1;
  }
  MYSQL_ROW row;
  MYSQL_RES *res = mysql_store_result(conn);
  int exist; 
  if((row = mysql_fetch_row(res)) != NULL)
  {
    int num_fields = mysql_num_fields(res);
    int i; 
    for(i = 0; i < num_fields; i++) 
    { 
      printf("%s ", row[i] ? row[i] : "NULL"); 
    } 
    printf("\n"); 
    exist = 1;
  }else{
    exist = 0;
  }
  mysql_free_result(res);
  mysql_close(conn);
  return exist;
} 

int proxy_insert_data(char* deviceId, char* proxy_ip, int port){
  MYSQL *conn;
  db_init(&conn); 
  char query[200];
  sprintf(query, "INSERT INTO device2proxy VALUES (NULL, now(), now(), \"%s\", \"%s\", %d, \"\")",  deviceId, proxy_ip, port);
  printf("query: %s \n", query);
  int success;
  if(mysql_query(conn, query) == 0){
    printf( "Record Added\n");
    success = 0;
  }else{
    printf( "Failed to add records \n");
    success = -1;
  }
  mysql_close(conn);
  return success; 
}

int proxy_update_data(char* deviceId, char* proxy_ip, int port){
  MYSQL *conn;
  db_init(&conn); 
  char query[300];
  sprintf(query, "UPDATE device2proxy SET proxy_ip = \"%s\", proxy_port = %d WHERE device_id = \"%s\"", proxy_ip, port, deviceId);
  printf("query: %s \n", query);
  int success;
  if(mysql_query(conn, query) == 0){
    printf( "Record updated\n");
    success = 0;
  }else{
    printf( "Failed to add records \n");
    success = -1;
  }
  mysql_close(conn);
  return success; 
} 

void saveDavicedId(char* deviceId, char* proxy_ip, int port){
  int exist = proxy_select_data(deviceId);
  printf("is exist %d", exist);
  if(!exist){
    proxy_insert_data(deviceId, proxy_ip, port);      
  }else{
    proxy_update_data(deviceId, proxy_ip, port);
  }
}

int db_save_device_config(char* massage) {
  char* string = strdup(massage);
  char* deviceId = strsep(&string, ",");
  char* proxy_ip = strsep(&string, ",");
  char* port = strsep(&string, ",");
  saveDavicedId(deviceId, proxy_ip, atoi(port));
}
