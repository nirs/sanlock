TARGET = devcount
TARGET2 = sanlk_load

SOURCE = devcount.c
SOURCE2 = sanlk_load.c

CFLAGS += -D_GNU_SOURCE -g \
	-Wall \
	-Wformat \
	-Wformat-security \
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

LDFLAGS = -lrt -laio -lblkid -lsanlock

all: $(TARGET) $(TARGET2)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCE) -o $@ -L. -L../src

$(TARGET2): $(SOURCE2)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCE2) -o $@ -L. -L../src

clean:
	rm -f *.o *.so *.so.* $(TARGET) $(TARGET2)

