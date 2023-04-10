PROJ_D=$(shell pwd)
SRC=ipk-sniffer.c
OUT=ipk-sniffer
CC=gcc
CFLAGS=-Wall -Wextra -Werror -lpcap

run:
	$(CC) $(SRC) $(CFLAGS) -o $(OUT)

clean:
	rm $(OUT)