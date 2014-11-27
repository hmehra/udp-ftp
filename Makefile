#
# Makefile for FastFTP
# Team SHY
#

CC=gcc
CFLAGS=-g -Werror 
LFLAGS=-lssl -lcrypto -lm -lpthread
EXE=server client

all: $(EXE)

clean:
	rm -f $(EXE)

server:
	$(CC) $(CFLAGS) -o server server.c $(LFLAGS)

client:
	$(CC) $(CFLAGS) -o client client.c $(LFLAGS)
