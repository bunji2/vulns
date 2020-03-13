# Makefile for Centos7

TARGETS=vulnsmodule.so

GOSRC=vulns.go

GOFLAGS=build -buildmode=c-archive

#CFLAGS=-IC:/msys64/mingw64/include/python2.7
#CFLAGS=-fPIC -I/usr/include/python2.7
CFLAGS=-fPIC `pkg-config python2 --cflags`


#LIBS=-lpython2.7
#LIBS=-lWs2_32 -lwinmm -LC:/msys64/mingw64/lib -lpython2.7
LIBS=`pkg-config python2 --libs`

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

vulns.h: subvulns.h subvulns.o

vulns.h: $(GOSRC)
	$(GO) $(GOFLAGS) $(GOSRC)
#	$(GO) $(GOFLAGS) $^

vulns.a: subvulns.h subvulns.o

vulns.a: $(GOSRC)
	$(GO) $(GOFLAGS) $(GOSRC)

pywrapper.c: vulns.h

vulnsmodule.so: pywrapper.o vulns.a subvulns.o
	$(CC) -shared $^ $(LIBS) -o $@

