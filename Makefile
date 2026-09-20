# Redoubt - kernel-module rootkit detector.  Plain C11/GNU, no dependencies.
# Works with GNU make 3.81 (the macOS default).

UNAME_S := $(shell uname -s)
CC      ?= cc
BUILD   := build
BIN     := $(BUILD)/redoubt

CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wformat -Wformat-security -Wno-unused-parameter -Iinclude -Isrc
ifeq ($(WERROR),1)
CFLAGS  += -Werror
endif
ifeq ($(UNAME_S),Linux)
# GCC warns about snprintf() into fixed title buffers; truncating a long name in a report title is intended.
CFLAGS  += -D_GNU_SOURCE -Wno-format-truncation
endif
ifeq ($(UNAME_S),Darwin)
CFLAGS  += -D_DARWIN_C_SOURCE
endif

CORE_SRC := src/util.c src/view.c src/engine.c src/report.c src/intel.c src/main.c \
            src/checks/checks.c src/checks/chk_modules.c src/checks/chk_kernel.c \
            src/checks/chk_userland.c src/checks/chk_intel.c src/checks/chk_macos.c \
            src/platform/fixture.c src/platform/sim.c src/platform/live.c \
            src/platform/linux.c src/platform/macos.c
CORE_OBJ := $(CORE_SRC:%.c=$(BUILD)/%.o)
LIB_OBJ  := $(filter-out $(BUILD)/src/main.o,$(CORE_OBJ))
HDRS     := $(wildcard include/*.h src/*.h)

.PHONY: all test unit eval hooks clean install syntax-linux demo

all: $(BIN)

$(BIN): $(CORE_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $(CORE_OBJ) $(LDFLAGS)
	@ln -sf $(BIN) redoubt

$(BUILD)/%.o: %.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# ---- tests -------------------------------------------------------------
$(BUILD)/test_unit: tests/test_unit.c $(LIB_OBJ) $(HDRS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/test_unit.c $(LIB_OBJ) $(LDFLAGS)

unit: $(BUILD)/test_unit
	./$(BUILD)/test_unit

eval: $(BIN)
	./$(BIN) eval fixtures

test: unit eval

# ---- live-hook demo library (real user-space hiding, see docs/DEMO.md) ----
ifeq ($(UNAME_S),Darwin)
HOOKLIB := $(BUILD)/libhide.dylib
$(HOOKLIB): tests/hooks/hide_pid.c
	@mkdir -p $(BUILD)
	$(CC) -O1 -dynamiclib -o $@ $<
else
HOOKLIB := $(BUILD)/libhide.so
$(HOOKLIB): tests/hooks/hide_pid.c
	@mkdir -p $(BUILD)
	$(CC) -O1 -fPIC -shared -o $@ $< -ldl
endif

hooks: $(HOOKLIB)

# ---- catch typos in the Linux provider from a non-Linux host -------------
syntax-linux:
	$(CC) -std=gnu11 -fsyntax-only -Wall -Wextra -Wno-unused-parameter -D__linux__ -D_GNU_SOURCE \
	    -Itests/shim -Iinclude -Isrc src/platform/linux.c

install: $(BIN)
	install -d $(DESTDIR)/usr/local/bin $(DESTDIR)/usr/local/share/redoubt
	install -m 755 $(BIN) $(DESTDIR)/usr/local/bin/redoubt
	cp -R fixtures $(DESTDIR)/usr/local/share/redoubt/

clean:
	rm -rf $(BUILD) redoubt

