CFLAGS := -D_GNU_SOURCE -Wall -g

all: sync_manager

sync_manager:	main.o disk_paxos.o log.o
	gcc $(LDFLAGS) -o $@ $^ -lpthread -lrt

main.o:	main.c
	gcc $(CFLAGS) -c -o $@ $<

disk_paxos.o:	disk_paxos.c
	gcc $(CFLAGS) -c -o $@ $<

log.o:	log.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o sync_manager

