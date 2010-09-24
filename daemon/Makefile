CFLAGS := -D_GNU_SOURCE -g \
	-Wall \
	-Wformat \
	-Wformat-security \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wpointer-arith \
	-Wextra -Wshadow \
	-Wcast-align \
	-Wwrite-strings \
	-Waggregate-return \
	-Wstrict-prototypes \
	-Winline \
	-Wredundant-decls \
	-Wno-sign-compare \
	-Wp,-D_FORTIFY_SOURCE=2 \
	-fexceptions \
	-fasynchronous-unwind-tables \
	-fdiagnostics-show-option

INSTALL=$(shell which install)
BINDIR=$(DESTDIR)/usr/libexec

RPMTOP=$(shell bash -c "pwd -P")/rpmbuild
rpmversion:=0.1
rpmrelease:=1.$(shell date +%Y%m%d)git
TARBALL=sync-manger-$(rpmversion)-$(rpmrelease).tar.gz

all: sync_manager

sync_manager:	main.o disk_paxos.o log.o lockfile.o token_manager.o watchdog.o sm_options.o crc32c.o diskio.o
	gcc $(LDFLAGS) -o $@ $^ -lpthread -lrt -lblkid

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

crc32c.o:	crc32c.c
	gcc $(CFLAGS) -c -o $@ $<

diskio.o:	diskio.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o sync_manager

.PHONY: install
install: sync_manager
	mkdir -p $(BINDIR)
	$(INSTALL) -c -m 755 sync_manager $(BINDIR)

rpm:
	rm -rf $(RPMTOP)
	mkdir $(RPMTOP)
	mkdir $(RPMTOP)/BUILD  $(RPMTOP)/BUILDROOT  $(RPMTOP)/RPMS  $(RPMTOP)/SOURCES  $(RPMTOP)/SPECS $(RPMTOP)/SRPMS
	tar zcf $(TARBALL) `git ls-files | grep -v /tests/`
	mv $(TARBALL) $(RPMTOP)/SOURCES
	sed 's/^Version:.*/Version: $(rpmversion)/;s/^Release:.*/Release: $(rpmrelease)%{?dist}/;s/^Source0:.*/Source0: $(TARBALL)/' \
		sync_manager.spec.in > sync_manager.spec
	rpmbuild -v -ba --define="_topdir $(RPMTOP)" \
                        --define="_sourcedir $(RPMTOP)/SOURCES" \
		./sync_manager.spec
