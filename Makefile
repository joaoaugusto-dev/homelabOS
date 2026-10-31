CFLAGS ?= -O2 -Wall -Wextra -Wno-format-truncation -pthread

all: homelabos/homelabos hosting/hosting

homelabos/homelabos: homelabos/server.c
	$(CC) $(CFLAGS) -o $@ $<

hosting/hosting: hosting/hosting.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	cd homelabos && ./test.sh
	cd hosting && ./test.sh

clean:
	rm -f homelabos/homelabos hosting/hosting

.PHONY: all test clean
