CC = gcc
OBJS_L4CONFIG = l4ag-config.o l4agctl.o
OBJS_L4MOND = l4agmond.o l4agctl.o
OBJS_TCPSENDSEG = tcpsendseg.o
CFLAGS += -g -Wall -I../module

default: l4ag-config l4agmond tcpsendseg

.c.o:
	$(CC) -c $(CFLAGS) $<

l4ag-config: $(OBJS_L4CONFIG)
	$(CC) $(CFLAGS) -o $@ $(OBJS_L4CONFIG)

l4ag-config.o: ../module/if_l4ag.h l4agctl.h

l4agmond: $(OBJS_L4MOND)
	$(CC) $(CFLAGS) -o $@ $(OBJS_L4MOND)

l4agmond.o: ../module/if_l4ag.h l4agctl.h

l4agctl.o: ../module/if_l4ag.h l4agctl.h

tcpsendseg: $(OBJS_TCPSENDSEG)
	$(CC) $(CFLAGS) -o $@ $(OBJS_TCPSENDSEG)

clean:
	rm -rf *.o l4ag-config l4agmond
