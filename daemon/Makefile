CFLAGS := -D_GNU_SOURCE -Wall -g

all: sync_manager

sync_manager:	main.o disk_paxos.o log.o lockfile.o token_manager.o watchdog.o sm_options.o
	gcc $(LDFLAGS) -o $@ $^ -lpthread -lrt

main.o:	main.c
	gcc $(CFLAGS) -c -o $@ $<

disk_paxos.o:	disk_paxos.c
	gcc $(CFLAGS) -c -o $@ $<

log.o:	log.c
	gcc $(CFLAGS) -c -o $@ $<

lockfile.o:	lockfile.c
	gcc $(CFLAGS) -c -o $@ $<

token_manager.o:	token_manager.c
	gcc $(CFLAGS) -c -o $@ $<

watchdog.o:	watchdog.c
	gcc $(CFLAGS) -c -o $@ $<

sm_options.o:	sm_options.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o sync_manager

