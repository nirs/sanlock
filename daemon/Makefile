TARGET = sanlock

SOURCE = \
	client_admin.c \
	client_msg.c \
	client_resource.c \
	crc32c.c \
	delta_lease.c \
	diskio.c \
	host_id.c \
	lockfile.c \
	log.c \
	main.c \
	paxos_lease.c \
	token_manager.c \
	watchdog.c

CFLAGS += -D_GNU_SOURCE -g \
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

LDFLAGS = -lpthread -lrt -lblkid

INSTALL=$(shell which install)

BINDIR=$(DESTDIR)/usr/libexec

RPMTOP=$(shell bash -c "pwd -P")/rpmbuild
rpmversion:=0.1
rpmrelease:=1.$(shell date +%Y%m%d)git
TARBALL=sanlock-$(rpmversion)-$(rpmrelease).tar.gz

all: $(TARGET)

sanlock: $(SOURCE)
	gcc $(CFLAGS) $(LDFLAGS) $(SOURCE) -o $@

clean:
	rm -f *.o $(TARGET)

.PHONY: install
install: $(TARGET)
	mkdir -p $(BINDIR)
	$(INSTALL) -c -m 755 $(TARGET) $(BINDIR)

rpm:
	rm -rf $(RPMTOP)
	mkdir $(RPMTOP)
	mkdir $(RPMTOP)/BUILD  $(RPMTOP)/BUILDROOT  $(RPMTOP)/RPMS  $(RPMTOP)/SOURCES  $(RPMTOP)/SPECS $(RPMTOP)/SRPMS
	tar zcf $(TARBALL) `git ls-files | grep -v /tests/`
	mv $(TARBALL) $(RPMTOP)/SOURCES
	sed 's/^Version:.*/Version: $(rpmversion)/;s/^Release:.*/Release: $(rpmrelease)%{?dist}/;s/^Source0:.*/Source0: $(TARBALL)/' \
		sanlock.spec.in > sanlock.spec
	rpmbuild -v -ba --define="_topdir $(RPMTOP)" \
                        --define="_sourcedir $(RPMTOP)/SOURCES" \
		./sanlock.spec
