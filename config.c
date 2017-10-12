#include <stdio.h>
#include <stdlib.h>
#include <string.h> 

typedef struct dbconf_s{
  char* db_host;
  char* db_pwd; 
  int db_port;
  char* db_database;
  char* db_user;
} dbconf;

char* getEnv(){
  char envValue[129]; 
  char*  envPtr = envValue;
  envPtr = getenv("ENV_TYPE");
  return envPtr;
}

void getConfigFileName(char** fileName){
  char* env = getEnv(); 
  if(env == NULL){
    *fileName = strdup("config"); 
    return;
  } 
  if(strcmp(env, "prepub") == 0){
    *fileName = strdup("config_pre");
  }else if(strcmp(env, "production") == 0){
    *fileName = strdup("config_prod");
  }else if(strcmp(env, "development") == 0){
    *fileName = strdup("config_dev"); 
  }else{
    *fileName = strdup("config"); 
  }
}

void getConfig(char* name, dbconf* config){
  FILE *fp;
  char filename[100];
  char str[1024];
  char *token;
  sprintf(filename, "config/%s", name);
  fp = fopen(filename, "r");  
  char *value;
  if(fp) {
    while (fscanf(fp, "%s", str)!=EOF){
      token = strtok(str, "=");
      if(token == NULL){
        break;
      }else{
        value = strtok(NULL, "=");
        if(value == NULL){
          value = "\0";
        }
      }
      if(strcmp(token, "db_host") == 0){
        config -> db_host = strdup(value); 
      }else if(strcmp(token, "db_password") == 0){
        config -> db_pwd = strdup(value);      
      }else if(strcmp(token, "db_port") == 0){
        config -> db_port = atoi(value);      
      }else if(strcmp(token, "db_user") == 0){
        config -> db_user = strdup(value);      
      }else if(strcmp(token, "db_database") == 0){
        config -> db_database = strdup(value);      
      }
    }
    fclose(fp);
  } 
}

void get_db_config(dbconf* config){
  char* filename;
  getConfigFileName(&filename);
  getConfig(filename, config);
  printf("config: %s, %s, %s, %s, %d\n", config -> db_host, config -> db_pwd, config -> db_user, config -> db_database, config -> db_port);
}

char* get_aserver_config(){
  char* name;
  getConfigFileName(&name);
  FILE *fp;
  char filename[100];
  char str[1024];
  char *token;
  sprintf(filename, "config/%s", name);
  fp = fopen(filename, "r");  
  char *value;
  char* a_address;
  if(fp == NULL){
    return NULL;
  }
  while (fscanf(fp, "%s", str)!=EOF){
    token = strtok(str, "=");
    if(token == NULL){
      break;
    }else{
      value = strtok(NULL, "=");
      if(value == NULL){
        value = "\0";
      }
    }
    if(strcmp(token, "aserver_address") == 0){
       a_address = strdup(value);
    }   
  }
  fclose(fp);
  return a_address;
}

