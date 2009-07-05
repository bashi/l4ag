CC = gcc
OBJS = l4ag-config.o
CFLAGS += -g -Wall -I../module

default: l4ag-config

.c.o:
	$(CC) -c $(CFLAGS) $<

l4ag-config: l4ag-config.o
	$(CC) $(CFLAGS) -o $@ $(OBJS)

l4ag-config.o: ../module/if_l4ag.h

clean:
	rm -rf *.o l4ag-config
