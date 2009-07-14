CC = gcc
OBJS_L4CONFIG = l4ag-config.o
OBJS_L4MOND = l4agmond.o
CFLAGS += -g -Wall -I../module

default: l4ag-config l4agmond

.c.o:
	$(CC) -c $(CFLAGS) $<

l4ag-config: l4ag-config.o
	$(CC) $(CFLAGS) -o $@ $(OBJS_L4CONFIG)

l4ag-config.o: ../module/if_l4ag.h

l4agmond: l4agmond.o
	$(CC) $(CFLAGS) -o $@ $(OBJS_L4MOND)

l4agmond.o: ../module/if_l4ag.h

clean:
	rm -rf *.o l4ag-config l4agmond
