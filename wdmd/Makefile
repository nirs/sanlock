# Copyright (C) 2011 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v2 or (at your option) any later version.

CMD_TARGET = wdmd
LIB_TARGET = libwdmd
HEADER_TARGET = wdmd.h
MAN_TARGET = wdmd.8
TEST_TARGET = wdmd_client

SOMAJOR=1
SOMINOR=0
SHLIB_TARGET = $(LIB_TARGET).so.$(SOMAJOR).$(SOMINOR)


CMD_SOURCE = main.c wdmd_sock.c

LIB_SOURCE = client.c wdmd_sock.c

TEST_SOURCE = wdmd_client.c

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
	-fPIE -DPIE

CMD_LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie
CMD_LDADD += -lwdmd -lrt

LIB_LDFLAGS += -Wl,-z,relro -pie

TEST_LDFLAGS = -lwdmd


all: $(SHLIB_TARGET) $(CMD_TARGET) $(TEST_TARGET)

$(SHLIB_TARGET): $(LIB_SOURCE)
	$(CC) $(CFLAGS) $(LIB_LDFLAGS) -shared -fPIC -o $@ -Wl,-soname=$(LIB_TARGET).so.$(SOMAJOR) $^
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so.$(SOMAJOR)

$(CMD_TARGET): $(SHLIB_TARGET) $(CMD_SOURCE)
	$(CC) $(CFLAGS) $(CMD_LDFLAGS) $(CMD_SOURCE) $(CMD_LDADD) -o $@ -L.

$(TEST_TARGET): $(SHLIB_TARGET) $(TEST_SOURCE)
	$(CC) $(CFLAGS) $(TEST_LDFLAGS) $(TEST_SOURCE) $(CMD_LDADD) -o $@ -L.

clean:
	rm -f *.o *.so *.so.* $(CMD_TARGET) $(TEST_TARGET)


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
	cp -a $(LIB_TARGET).so.$(SOMAJOR) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 644 $(HEADER_TARGET) $(DESTDIR)/$(HEADIR)
	$(INSTALL) -m 644 $(MAN_TARGET) $(DESTDIR)/$(MANDIR)/man8
