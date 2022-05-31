#
# Makefile for solbox cache reader
# 

OBJS := main.o
TGT = url_encrypt

INCLUDES = -I $(OPENSSL_PATH)/include 
CCFLAGS =
CFLAGS = -g -ggdb3 -Wall
LDFLAGS = -L $(OPENSSL_PATH) -lssl -lcrypto -ldl

ifndef PREFIX
PREFIX = /usr/service
endif
BINDIR=$(PREFIX)/bin
.PHONY: $(TGT)

all: $(TGT)
	gcc -o $< $(OBJS) $(LDFLAGS)

clean:
	rm -f *.o $(TGT)

.c.o:
	gcc -c $< $(INCLUDES) $(CFLAGS)

$(TGT): $(OBJS)

install: all
	test -d $(BINDIR) || mkdir -p $(BINDIR)
	install -m 0755 $(shell pwd)/$(TGT) $(BINDIR)
