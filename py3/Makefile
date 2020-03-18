# Makefile for Centos7

TARGETS=vulns.so

GOSRC=vulns.go

GOFLAGS=build -buildmode=c-archive

CFLAGS=-fPIC `pkg-config python3 --cflags`

LIBS=`pkg-config python3 --libs`

#GO=go
GO=/usr/local/go/bin/go
CC=gcc
RM=rm -f
GREP=grep

.SUFFIXES: .o .c

all: $(TARGETS)

clean:
	$(RM) *.o *.exe *.a vulns.h vulnsmodule.so

.c.o:
	$(CC) $(CFLAGS) -c $<

vulns.h: $(GOSRC)
	$(GO) $(GOFLAGS) $(GOSRC)

vulns.a: $(GOSRC)
	$(GO) $(GOFLAGS) $(GOSRC)

vulnspy3.c: vulns.h

vulns.so: vulnspy3.o vulns.a
	$(CC) -shared $^ $(LIBS) -o $@

