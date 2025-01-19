CCOMP = gcc
CFLAGS = -Wall -O0
LFLAGS = -lpcap

all: capture

capture: capture.o
	$(CCOMP) $(CFLAGS) -o capture capture.o $(LFLAGS)

capture.o: capture.c capture.h
	$(CCOMP) $(CFLAGS) -c capture.c

clean:
	rm -f capture.o capture