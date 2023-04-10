PROJ_D=$(shell pwd)
SRC=ipk-sniffer.c
OUT=ipk-sniffer
CC=gcc
CFLAGS=-Wall -Wextra -Werror -lpcap

ifeq ($(OS),Windows_NT)
run:
	$(CC) $(SRC) -o $(OUT)
else
run:
	$(CC) $(SRC) $(CFLAGS) -o $(OUT)
endif

clean:
	rm $(OUT)