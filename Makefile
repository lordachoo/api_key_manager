CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lsqlite3 -lsodium

all: api_key_manager

api_key_manager: api_key_manager.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f api_key_manager

.PHONY: all clean
