#!/bin/bash

BASE_HOME=`pwd`
PROJECT_NAME=`basename ${BASE_HOME}`
PROJECT_ROOT=${BASE_HOME}
C_LOG=logs/packets_stdout.log

[ ! -d logs ] && mkdir logs

get_c_pid() {
    C_PID=`ps ax | grep -v grep | grep 'output' | awk '{print $1}'`

}

compile() {
    cd ${PROJECT_ROOT}
    gcc hashmap.c proxy.c -o output -lpcap $(mysql_config --cflags) $(mysql_config --libs)
}


stop(){
    get_c_pid
    if [[ ! -z "$C_PID" ]]; then
        c_num=`ps ax | grep output |grep -v grep | wc -l`
        if [[ $c_num != 0 ]]; then
            ps ax | grep output |grep -v grep| awk '{print $1}'| xargs sudo kill -9
            sleep 5
        fi
        if [ -f $C_LOG ]; then
          mv -f $C_LOG "${C_LOG}.`date '+%Y%m%d%H%M%S'`"
        fi
    else
        echo "${PROJECT_NAME}-packets is not running"
    fi
}

start(){
    get_c_pid
    if [[ -z $C_PID ]]; then
        compile
        sudo stdbuf -oL nohup ./output > $C_LOG 2>&1 &
        sleep 5
        get_c_pid
        echo "Start packets_capture success. PID=$C_PID"
    else
        echo "${PROJECT_NAME}: packet handle is already running, PID=$PID"
    fi
}

stop
start

