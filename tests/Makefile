TARGET1 = devcount
TARGET2 = sanlk_load
TARGET3 = sanlk_client
TARGET4 = killpath
TARGET5 = sanlk_path
TARGET6 = sanlk_testr
TARGET7 = sanlk_events

SOURCE1 = devcount.c
SOURCE2 = sanlk_load.c
SOURCE3 = sanlk_client.c
SOURCE4 = killpath.c
SOURCE5 = sanlk_path.c
SOURCE6 = sanlk_testr.c
SOURCE7 = sanlk_events.c

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
	-O2 \
	-fexceptions \
	-fasynchronous-unwind-tables \
	-fdiagnostics-show-option

LDFLAGS = -lrt -laio -lblkid -lsanlock

all: $(TARGET1) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5) $(TARGET6) $(TARGET7)

$(TARGET1): $(SOURCE1)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -I../src -L../src

$(TARGET2): $(SOURCE2)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -I../src -L../src

$(TARGET3): $(SOURCE3)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -I../src -L../src

$(TARGET4): $(SOURCE4)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -I../src -L../src

$(TARGET5): $(SOURCE5)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -I../src -L../src

$(TARGET6): $(SOURCE6)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -I../src -L../src

$(TARGET7): $(SOURCE7)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -I../src -L../src

clean:
	rm -f *.o *.so *.so.* $(TARGET) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5) $(TARGET6) $(TARGET7)

