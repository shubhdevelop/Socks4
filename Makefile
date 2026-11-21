CC = gcc
CFLAGS = -std=c99 -Wall -Werror
SANITIZE_FLAGS = -fsanitize=address -g
DEBUG_FLAGS = -g -O0

.PHONY: compile debug release run webapp tailscale-proxy clean

compile: socks5

debug: socks5-debug

%-debug: %.c Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEBUG_FLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

socsk5: socks5.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZE_FLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

socks5 socks5-debug: LDLIBS += -luring

socks5: socks5.c socks.h Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) socks5.c -o $@ $(LDFLAGS) $(LDLIBS)

tailscale-proxy: socks5
	./socks5 "$$(tailscale ip -4)"

release:
	$(CC) $(CPPFLAGS) $(CFLAGS) socks5.c -o sockss5 $(LDFLAGS) $(LDLIBS) -luring

# Generate clangd entries for both programs (requires Python 3).
compile_commands.json: Makefile
	python3 -c 'import json, os, sys; print(json.dumps([{"directory": os.getcwd(), "arguments": sys.argv[1:] + [name + ".c", "-o", name], "file": name + ".c"} for name in ("main", "client")], indent=2))' $(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZE_FLAGS) > $@

run: socsk5
	./socks5

webapp:
	python3 webapp.py

clean:
	rm -f socsk5 socks5-debug
