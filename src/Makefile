# Copyright 2010-2011 Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v2 or (at your option) any later version.

CMD_TARGET = sanlock
HEADER_TARGET = sanlock.h sanlock_rv.h sanlock_resource.h sanlock_admin.h sanlock_direct.h
MAN_TARGET = sanlock.8

SOMAJOR=1
SOMINOR=0

LIB_ENTIRE_TARGET = libsanlock
LIB_CLIENT_TARGET = libsanlock_client
LIBPC_ENTIRE_TARGET = libsanlock.pc
LIBPC_CLIENT_TARGET = libsanlock_client.pc
LIBSO_ENTIRE_TARGET = $(LIB_ENTIRE_TARGET).so.$(SOMAJOR).$(SOMINOR)
LIBSO_CLIENT_TARGET = $(LIB_CLIENT_TARGET).so.$(SOMAJOR).$(SOMINOR)

CMD_SOURCE = \
	crc32c.c \
	delta_lease.c \
	direct.c \
	diskio.c \
	ondisk.c \
	helper.c \
	lockspace.c \
	lockfile.c \
	log.c \
	main.c \
	paxos_lease.c \
	task.c \
	timeouts.c \
	resource.c \
	rindex.c \
	watchdog.c \
	monotime.c \
	cmd.c \
	client_cmd.c \
	sanlock_sock.c \
	env.c

LIB_ENTIRE_SOURCE = \
	client.c \
	sanlock_sock.c \
	crc32c.c \
	diskio.c \
	ondisk.c \
	delta_lease.c \
	paxos_lease.c \
	rindex.c \
	direct.c \
	task.c \
	timeouts.c \
	direct_lib.c \
	monotime.c \
	env.c

LIB_CLIENT_SOURCE = \
	client.c \
	sanlock_sock.c \
	env.c

LIBPC_ENTIRE_SOURCE = libsanlock.pc.in
LIBPC_CLIENT_SOURCE = libsanlock_client.pc.in

CFLAGS += -D_GNU_SOURCE -O2 -ggdb \
	-Wall \
	-Wformat \
	-Wformat-security \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wpointer-arith \
	-Wextra \
	-Wshadow \
	-Wcast-align \
	-Wwrite-strings \
	-Waggregate-return \
	-Wstrict-prototypes \
	-Winline \
	-Wredundant-decls \
	-Wno-sign-compare \
	-Wno-unused-parameter \
	-Wp,-D_FORTIFY_SOURCE=2 \
	-Wno-strict-overflow \
	-fexceptions \
	-fasynchronous-unwind-tables \
	-fdiagnostics-show-option \
	-Wp,-D_GLIBCXX_ASSERTIONS \
	-fstack-protector-strong \
	-fstack-clash-protection \
	-Wl,-z,now

VER=$(shell cat ../VERSION)
CFLAGS += -DVERSION=\"$(VER)\"

CMD_CFLAGS = $(CFLAGS) -fPIE -DPIE
LIB_ENTIRE_CFLAGS = $(CFLAGS) -fPIC
LIB_CLIENT_CFLAGS = $(CFLAGS) -fPIC

CMD_LDFLAGS = $(LDFLAGS) -Wl,-z,relro -pie
LIB_ENTIRE_LDFLAGS = $(LDFLAGS) -Wl,-z,relro -pie
LIB_CLIENT_LDFLAGS = $(LDFLAGS) -Wl,-z,relro -pie

CMD_LDADD = -lpthread -luuid -lrt -laio -lblkid -lsanlock -L../wdmd -lwdmd
LIB_ENTIRE_LDADD = -lpthread -lrt -laio -lblkid -L../wdmd -lwdmd

all: $(LIBSO_ENTIRE_TARGET) $(LIBSO_CLIENT_TARGET) $(CMD_TARGET) $(LIBPC_ENTIRE_TARGET) $(LIBPC_CLIENT_TARGET)

$(LIBSO_ENTIRE_TARGET): $(LIB_ENTIRE_SOURCE)
	$(CC) $(LIB_ENTIRE_CFLAGS) $(LIB_ENTIRE_LDFLAGS) -shared -o $@ -Wl,-soname=$(LIB_ENTIRE_TARGET).so.$(SOMAJOR) $^ $(LIB_ENTIRE_LDADD)
	ln -sf $(LIBSO_ENTIRE_TARGET) $(LIB_ENTIRE_TARGET).so
	ln -sf $(LIBSO_ENTIRE_TARGET) $(LIB_ENTIRE_TARGET).so.$(SOMAJOR)

$(LIBSO_CLIENT_TARGET): $(LIB_CLIENT_SOURCE)
	$(CC) $(LIB_CLIENT_CFLAGS) $(LIB_CLIENT_LDFLAGS) -shared -o $@ -Wl,-soname=$(LIB_CLIENT_TARGET).so.$(SOMAJOR) $^
	ln -sf $(LIBSO_CLIENT_TARGET) $(LIB_CLIENT_TARGET).so
	ln -sf $(LIBSO_CLIENT_TARGET) $(LIB_CLIENT_TARGET).so.$(SOMAJOR)

$(CMD_TARGET): $(LIBSO_ENTIRE_TARGET) $(CMD_SOURCE)
	$(CC) $(CMD_CFLAGS) $(CMD_LDFLAGS) $(CMD_SOURCE) $(CMD_LDADD) -o $@ -L.

$(LIBPC_ENTIRE_TARGET): $(LIBPC_ENTIRE_SOURCE)
	sed -e "s/@VERSION@/$(VER)/" $(LIBPC_ENTIRE_SOURCE) > $(LIBPC_ENTIRE_TARGET)

$(LIBPC_CLIENT_TARGET): $(LIBPC_CLIENT_SOURCE)
	sed -e "s/@VERSION@/$(VER)/" $(LIBPC_CLIENT_SOURCE) > $(LIBPC_CLIENT_TARGET)

clean:
	rm -f *.o *.so *.so.* $(CMD_TARGET) $(LIBSO_ENTIRE_TARGET) $(LIBSO_CLIENT_TARGET) $(LIBPC_ENTIRE_TARGET) $(LIBPC_CLIENT_TARGET)

INSTALL=$(shell which install)

DESTDIR=
BINDIR=/usr/sbin
LIBDIR=/usr/lib64
HEADIR=/usr/include
MANDIR=/usr/share/man

.PHONY: install
install: all
	$(INSTALL) -d $(DESTDIR)/$(BINDIR)
	$(INSTALL) -d $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -d $(DESTDIR)/$(HEADIR)
	$(INSTALL) -d $(DESTDIR)/$(MANDIR)/man8
	$(INSTALL) -d $(DESTDIR)/$(LIBDIR)/pkgconfig
	$(INSTALL) -c -m 755 $(CMD_TARGET) $(DESTDIR)/$(BINDIR)
	$(INSTALL) -c -m 755 $(LIBSO_ENTIRE_TARGET) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 755 $(LIBSO_CLIENT_TARGET) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 644 $(LIBPC_ENTIRE_TARGET) $(DESTDIR)/$(LIBDIR)/pkgconfig
	$(INSTALL) -c -m 644 $(LIBPC_CLIENT_TARGET) $(DESTDIR)/$(LIBDIR)/pkgconfig
	cp -a $(LIB_ENTIRE_TARGET).so $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_CLIENT_TARGET).so $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_ENTIRE_TARGET).so.$(SOMAJOR) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_CLIENT_TARGET).so.$(SOMAJOR) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 644 $(HEADER_TARGET) $(DESTDIR)/$(HEADIR)
	$(INSTALL) -m 644 $(MAN_TARGET) $(DESTDIR)/$(MANDIR)/man8/
