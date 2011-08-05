# Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.

CMD_TARGET = sanlock
LIB_TARGET = libsanlock
HEADER_TARGET = sanlock.h sanlock_rv.h sanlock_resource.h sanlock_admin.h sanlock_direct.h
MAN_TARGET = sanlock.8

SOMAJOR=1
SOMINOR=0
SHLIB_TARGET = $(LIB_TARGET).so.$(SOMAJOR).$(SOMINOR)

CMD_SOURCE = \
	crc32c.c \
	delta_lease.c \
	direct.c \
	diskio.c \
	host_id.c \
	lockfile.c \
	log.c \
	main.c \
	paxos_lease.c \
	task.c \
	token_manager.c \
	watchdog.c \
	monotime.c \
	sanlock_sock.c

LIB_SOURCE = \
	client_msg.c \
	client_resource.c \
	client_admin.c \
	crc32c.c \
	diskio.c \
	delta_lease.c \
	paxos_lease.c \
	direct.c \
	task.c \
	direct_lib.c \
	monotime.c \
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

CMD_LDFLAGS += -lpthread -luuid -lrt -laio -lblkid -lsanlock -L../wdmd -lwdmd
CMD_LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie

LIB_LDFLAGS += -lpthread -lrt -laio -lblkid -L../wdmd -lwdmd
LIB_LDFLAGS += -Wl,-z,relro -pie

all: $(SHLIB_TARGET) $(CMD_TARGET)

$(SHLIB_TARGET): $(LIB_SOURCE)
	$(CC) $(CFLAGS) $(LIB_LDFLAGS) -shared -fPIC -o $@ -Wl,-soname=$(LIB_TARGET).so.$(SOMAJOR) $^
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so.$(SOMAJOR)

$(CMD_TARGET): $(SHLIB_TARGET) $(CMD_SOURCE)
	$(CC) $(CMD_CFLAGS) $(CMD_LDFLAGS) $(CMD_SOURCE) -o $@ -L.

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
	$(INSTALL) -c -m 755 $(SHLIB_TARGET) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_TARGET).so $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 644 $(HEADER_TARGET) $(DESTDIR)/$(HEADIR)
	$(INSTALL) $(MAN_TARGET) $(DESTDIR)/$(MANDIR)/man8/
