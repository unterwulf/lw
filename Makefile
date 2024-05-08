LW_VERSION = 0.0.1

CFLAGS += -std=c99 -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE -D_BSD_SOURCE -DLW_VERSION=\"$(LW_VERSION)\" -g -Wall -Wno-parentheses

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

lw: lw.o

.PHONY: clean
clean:
	$(RM) lw lw.o

.PHONY: install
install: lw
	install -m 755 -D lw $(DESTDIR)$(BINDIR)/lw
	install -m 644 -D lw.8 $(DESTDIR)$(MANDIR)/man8/lw.8
