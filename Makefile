CC = gcc
CFLAGS = -std=c99 -Wall -Werror
SANITIZE_FLAGS = -fsanitize=address -g
DEBUG_FLAGS = -g -O0
RELEASE_FLAGS = -O2 -DNDEBUG

SRC = socks4.c
HDR = socks.h

.PHONY: compile debug release run webapp tailscale-proxy clean compile_commands.json

compile: socks4

debug: socks4-debug

socks4 socks4-debug socks4-asan: LDLIBS += -luring

socks4: $(SRC) $(HDR) Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)

socks4-debug: $(SRC) $(HDR) Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEBUG_FLAGS) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)

socks4-asan: $(SRC) $(HDR) Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZE_FLAGS) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)

release: $(SRC) $(HDR) Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(RELEASE_FLAGS) $(SRC) -o socks4 $(LDFLAGS) $(LDLIBS)

tailscale-proxy: socks4
	./socks4 "$$(tailscale ip -4)"

# Generate clangd entries (requires Python 3).
compile_commands.json: Makefile
	python3 -c 'import json, os, sys; print(json.dumps([{"directory": os.getcwd(), "arguments": sys.argv[1:] + ["socks4.c", "-o", "socks4", "-luring"], "file": "socks4.c"}], indent=2))' $(CC) $(CPPFLAGS) $(CFLAGS) > $@

run: socks4
	./socks4

webapp:
	python3 webapp.py

clean:
	rm -f socks4 socks4-debug socks4-asan socsk5 socks5 socks5-debug sockss5