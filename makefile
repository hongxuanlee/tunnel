THIS_FILE := $(lastword $(MAKEFILE_LIST))
CC=gcc

build:
	@echo $@
	@$(CC) -o output hashmap.c proxy.c -I. -lpcap $$(mysql_config --cflags) $$(mysql_config --libs)	

dev:
	@echo $@
	@./dev.sh

.PHONY: build test dev
