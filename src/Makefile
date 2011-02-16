# Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.

CMD_TARGET = sanlock

LIB_TARGET = libsanlock

HEADER_TARGET = sanlock.h sanlock_resource.h

SOMAJOR=1
SOMINOR=0

SHLIB_TARGET = $(LIB_TARGET).so.$(SOMAJOR).$(SOMINOR)

CMD_SOURCE = \
	client_admin.c \
	crc32c.c \
	delta_lease.c \
	direct.c \
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
	-fdiagnostics-show-option \
	-DUSE_WDMD

CMD_LDFLAGS = -lpthread -lrt -lblkid -lsanlock -lwdmd


all: $(SHLIB_TARGET) $(CMD_TARGET)

$(SHLIB_TARGET): $(LIB_SOURCE)
	$(CC) -shared -fPIC -o $@ -Wl,-soname=$(LIB_TARGET).so.$(SOMAJOR) $^
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so.$(SOMAJOR)

$(CMD_TARGET): $(SHLIB_TARGET) $(CMD_SOURCE)
	$(CC) $(CFLAGS) $(CMD_LDFLAGS) $(CMD_SOURCE) -o $@ -L.

clean:
	rm -f *.o *.so *.so.* $(CMD_TARGET)


INSTALL=$(shell which install)

CMD_BINDIR=/usr/sbin
LIB_LIBDIR=/usr/lib64
HEADER_DIR=/usr/include

.PHONY: install
install: all
	mkdir -p $(DESTDIR)/$(CMD_BINDIR)
	mkdir -p $(DESTDIR)/$(LIB_LIBDIR)
	mkdir -p $(DESTDIR)/$(HEADER_DIR)
	$(INSTALL) -c -m 755 $(CMD_TARGET) $(DESTDIR)/$(CMD_BINDIR)
	$(INSTALL) -c -m 755 $(SHLIB_TARGET) $(DESTDIR)/$(LIB_LIBDIR)
	cp -a $(LIB_TARGET).so $(DESTDIR)/$(LIB_LIBDIR)
	cp -a $(LIB_TARGET).so.$(SOMAJOR) $(DESTDIR)/$(LIB_LIBDIR)
	$(INSTALL) -c -m 644 $(HEADER_TARGET) $(DESTDIR)/$(HEADER_DIR)
