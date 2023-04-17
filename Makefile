PROJ_D=$(shell pwd)
SRC=ipk-sniffer.c
OUT=ipk-sniffer
CC=gcc
CFLAGS=-Wall -Werror

ifeq ($(OS),Windows_NT)
run:
	$(CC) $(SRC) -o $(OUT)
else
run:
	$(CC) $(SRC) $(CFLAGS) -o $(OUT) -lpcap
endif

clean:
	rm $(OUT)