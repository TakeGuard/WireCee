ROOT    := ../..
CC      ?= gcc
CFLAGS  ?= -O2
CFLAGS  += -std=gnu11 -Wall -Wno-unused-function -Wno-format-truncation -DNO_SSL -DNO_CGI -DUSE_IPV6 \
           -I$(ROOT)/src/core -I$(ROOT)/src/linux -I$(ROOT)/third_party/civetweb
LDLIBS  += -lpthread -ldl -lm

PREFIX  ?= /usr
OUT     := $(ROOT)/build/out/linux
VERSION := $(shell sed -n 's/.*WIRECEE_VERSION "\(.*\)".*/\1/p' $(ROOT)/src/core/version.h)
ARCH    := $(shell uname -m)
STAGE   := $(ROOT)/dist/linux/WireCee
TARBALL := $(ROOT)/dist/WireCee-$(VERSION)-linux-$(ARCH).tar.gz

SRC := $(ROOT)/src/linux/main.c \
       $(ROOT)/src/linux/platform_linux.c \
       $(ROOT)/src/linux/netenum_linux.c \
       $(ROOT)/src/linux/fw_nft.c \
       $(ROOT)/src/linux/flows_conntrack.c \
       $(ROOT)/src/core/api.c \
       $(ROOT)/src/core/cli.c \
       $(ROOT)/src/core/dnsd.c \
       $(ROOT)/src/core/engine.c \
       $(ROOT)/src/core/hostmap.c
HDR := $(wildcard $(ROOT)/src/core/*.h)

all: $(OUT)/wirecee

$(OUT)/civetweb.o: $(ROOT)/third_party/civetweb/civetweb.c | $(OUT)
	$(CC) $(CFLAGS) -w -c -o $@ $<

$(OUT)/wirecee: $(SRC) $(HDR) $(OUT)/civetweb.o | $(OUT)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(OUT)/civetweb.o $(LDLIBS)
	strip $@

$(OUT):
	mkdir -p $@

install: $(OUT)/wirecee
	install -Dm755 $(OUT)/wirecee $(DESTDIR)$(PREFIX)/bin/wirecee
	mkdir -p $(DESTDIR)$(PREFIX)/share/wirecee/app
	cp -r $(ROOT)/src/web/. $(DESTDIR)$(PREFIX)/share/wirecee/app/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/wirecee
	rm -rf $(DESTDIR)$(PREFIX)/share/wirecee

dist: $(OUT)/wirecee
	rm -rf $(ROOT)/dist/linux
	mkdir -p $(STAGE)/app
	install -m755 $(OUT)/wirecee $(STAGE)/wirecee
	cp -r $(ROOT)/src/web/. $(STAGE)/app/
	cp $(ROOT)/README.md $(ROOT)/LICENSE $(STAGE)/
	tar -czf $(TARBALL) -C $(ROOT)/dist/linux WireCee
	@echo $(TARBALL)

clean:
	rm -rf $(OUT)

.PHONY: all install uninstall dist clean
