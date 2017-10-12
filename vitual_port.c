#include <stdio.h>
#include "utils.h"
#include <stdbool.h>
#include <sys/queue.h>

#define START 50000
#define VP_MAX 10000

typedef struct vp_handle {
  int i;
  bool used_port[VP_MAX]; 
} vp_handle_t;

vp_handle_t create_port_pool(){
  vp_handle_t handle_t;
  memset(&handle_t, 0, sizeof(vp_handle_t));
  return handle_t;
}

bool is_exist(bool* used_port, int port){
  if(used_port[port - START]){ 
      return true;
  }
  return false;
}

bool port_used(vp_handle_t* t, int port){
  bool *used_port = t -> used_port;
  return is_exist(used_port, port);
}

int generate_port(vp_handle_t* t){
  bool *used_port = t -> used_port;
  int i = t -> i;
  int port = START + i;
  int end = VP_MAX;
  while(is_exist(used_port, port)){
    if(end == 0){
      return 0; 
    }
    if(i >= VP_MAX - 1){
      i = 0;   
      port = START;
    }else{ 
      i += 1;
      port += 1;
    }
    end--;
  }
  if(i == VP_MAX - 1){
    t -> i = 0; 
  }else{
    t -> i = i + 1;
  }
  used_port[i] = true; 
  return port;
}

void remove_port(vp_handle_t* t, int port){
  bool *used_port = t -> used_port;
  int i = port - START;
  used_port[i] = false;
}

