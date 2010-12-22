LIB_TARGET = lock_driver_sanlock

SOMAJOR=1
SOMINOR=0

SHLIB_TARGET = $(LIB_TARGET).so.$(SOMAJOR).$(SOMINOR)

LIB_SOURCE = lock_driver_sanlock.c

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

all: $(SHLIB_TARGET)

$(SHLIB_TARGET): $(LIB_SOURCE)
	$(CC) -shared -fPIC -lsanlock -o $@ -Wl,-soname=$(LIB_TARGET).so.$(SOMAJOR) $^
	ln -sf $(SHLIB_TARGET) $(LIB_TARGET).so

clean:
	rm -f *.o *.so *.so.*

INSTALL=$(shell which install)

LIB_LIBDIR=$(DESTDIR)/usr/lib64/libvirt/lock_manager/

.PHONY: install
install: all
	mkdir -p $(LIB_LIBDIR)
	$(INSTALL) -c -m 755 $(SHLIB_TARGET) $(LIB_LIBDIR)
	cp -a $(LIB_TARGET).so $(LIB_LIBDIR)

