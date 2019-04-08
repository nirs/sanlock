export CC ?= cc

check = $(shell echo "int main() { return 0; }" \
		| $(CC) $(1) -xc - >&/dev/null && echo $(1) ||:)

export CFLAGS += -D_GNU_SOURCE -O2 -ggdb \
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
	$(check -fstack-clash-protection) \
	-Wl,-z,now
