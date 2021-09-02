APPS = 

TESTS = test/step18-1.exe \
		test/step18-2.exe

DRIVERS = driver/null.o \
          driver/loopback.o \

OBJS = util.o \
       net.o \
       ip.o \
       ether.o \
       arp.o \
       icmp.o \
       udp.o \

CFLAGS := $(CFLAGS) -v -g -W -Wall -Wno-unused-parameter -D_DEFAULT_SOURCE -I .

ifeq ($(shell uname),Linux)
       CFLAGS := $(CFLAGS) -pthread
       DRIVERS := $(DRIVERS) driver/ether_tap_linux.o
endif

ifeq ($(shell uname),Darwin)
       CFLAGS := $(CFLAGS)
       DRIVERS := $(DRIVERS)
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -I./include -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)
