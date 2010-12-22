CMD_TARGET = sanlock

LIB_TARGET = libsanlock

SOMAJOR=1
SOMINOR=0

SHLIB_TARGET = $(LIB_TARGET).so.$(SOMAJOR).$(SOMINOR)

CMD_SOURCE = \
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

LIB_SOURCE = \
	client_msg.c \
	client_resource.c \

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

CMD_LDFLAGS = -lpthread -lrt -lblkid


all: $(CMD_TARGET) $(SHLIB_TARGET)

$(CMD_TARGET): $(CMD_SOURCE)
	$(CC) $(CFLAGS) $(CMD_LDFLAGS) $(CMD_SOURCE) -o $@

$(SHLIB_TARGET): $(LIB_SOURCE)
	$(CC) -shared -fPIC -o $@ -Wl,-soname=$(LIB_TARGET).so.$(SOMAJOR) $^
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so.$(SOMAJOR)


clean:
	rm -f *.o *.so *.so.* $(CMD_TARGET)


INSTALL=$(shell which install)

CMD_BINDIR=$(DESTDIR)/usr/libexec
LIB_LIBDIR=$(DESTDIR)/usr/lib64

RPMTOP=$(shell bash -c "pwd -P")/rpmbuild
rpmversion:=0.1
rpmrelease:=1.$(shell date +%Y%m%d)git
TARBALL=sanlock-$(rpmversion)-$(rpmrelease).tar.gz


.PHONY: install
install: all
	mkdir -p $(CMD_BINDIR)
	mkdir -p $(LIB_LIBDIR)
	$(INSTALL) -c -m 755 $(CMD_TARGET) $(CMD_BINDIR)
	$(INSTALL) -c -m 755 $(SHLIB_TARGET) $(LIB_LIBDIR)
	cp -a $(LIB_TARGET).so $(LIB_LIBDIR)
	cp -a $(LIB_TARGET).so.$(SOMAJOR) $(LIB_LIBDIR)

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
