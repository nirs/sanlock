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
LIBSO_ENTIRE_TARGET = $(LIB_ENTIRE_TARGET).so.$(SOMAJOR).$(SOMINOR)
LIBSO_CLIENT_TARGET = $(LIB_CLIENT_TARGET).so.$(SOMAJOR).$(SOMINOR)

CMD_SOURCE = \
	crc32c.c \
	delta_lease.c \
	direct.c \
	diskio.c \
	lockspace.c \
	lockfile.c \
	log.c \
	main.c \
	paxos_lease.c \
	task.c \
	resource.c \
	watchdog.c \
	monotime.c \
	cmd.c \
	client_cmd.c \
	sanlock_sock.c

LIB_ENTIRE_SOURCE = \
	client.c \
	sanlock_sock.c \
	crc32c.c \
	diskio.c \
	delta_lease.c \
	paxos_lease.c \
	direct.c \
	task.c \
	direct_lib.c \
	monotime.c

LIB_CLIENT_SOURCE = \
	client.c \
	sanlock_sock.c

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

CMD_CFLAGS = $(CFLAGS) -fPIE -DPIE

CMD_LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie
CMD_LDADD += -lpthread -luuid -lrt -laio -lblkid -lsanlock -L../wdmd -lwdmd

LIB_ENTIRE_LDFLAGS += -lpthread -lrt -laio -lblkid -L../wdmd -lwdmd
LIB_ENTIRE_LDFLAGS += -Wl,-z,relro -pie

LIB_CLIENT_LDFLAGS += -Wl,-z,relro -pie


all: $(LIBSO_ENTIRE_TARGET) $(LIBSO_CLIENT_TARGET) $(CMD_TARGET)

$(LIBSO_ENTIRE_TARGET): $(LIB_ENTIRE_SOURCE)
	$(CC) $(CFLAGS) $(LIB_ENTIRE_LDFLAGS) -shared -fPIC -o $@ -Wl,-soname=$(LIB_ENTIRE_TARGET).so.$(SOMAJOR) $^
	ln -sf $(LIBSO_ENTIRE_TARGET) $(LIB_ENTIRE_TARGET).so
	ln -sf $(LIBSO_ENTIRE_TARGET) $(LIB_ENTIRE_TARGET).so.$(SOMAJOR)

$(LIBSO_CLIENT_TARGET): $(LIB_CLIENT_SOURCE)
	$(CC) $(CFLAGS) $(LIB_CLIENT_LDFLAGS) -shared -fPIC -o $@ -Wl,-soname=$(LIB_CLIENT_TARGET).so.$(SOMAJOR) $^
	ln -sf $(LIBSO_CLIENT_TARGET) $(LIB_CLIENT_TARGET).so
	ln -sf $(LIBSO_CLIENT_TARGET) $(LIB_CLIENT_TARGET).so.$(SOMAJOR)

$(CMD_TARGET): $(LIBSO_ENTIRE_TARGET) $(CMD_SOURCE)
	$(CC) $(CMD_CFLAGS) $(CMD_LDFLAGS) $(CMD_SOURCE) $(CMD_LDADD) -o $@ -L.

clean:
	rm -f *.o *.so *.so.* $(CMD_TARGET)


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
	$(INSTALL) -c -m 755 $(CMD_TARGET) $(DESTDIR)/$(BINDIR)
	$(INSTALL) -c -m 755 $(LIBSO_ENTIRE_TARGET) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 755 $(LIBSO_CLIENT_TARGET) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_ENTIRE_TARGET).so $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_CLIENT_TARGET).so $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_ENTIRE_TARGET).so.$(SOMAJOR) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_CLIENT_TARGET).so.$(SOMAJOR) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 644 $(HEADER_TARGET) $(DESTDIR)/$(HEADIR)
	$(INSTALL) -m 644 $(MAN_TARGET) $(DESTDIR)/$(MANDIR)/man8/
