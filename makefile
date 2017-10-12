THIS_FILE := $(lastword $(MAKEFILE_LIST))
CC=gcc
CFLAGS=-I.

build:
	@echo $@
	@$(CC) -o output proxy.c $(CFLAGS) -lpcap $(mysql_config --cflags) $(mysql_config --libs)	

.PHONY: build
