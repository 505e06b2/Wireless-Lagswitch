OUT=give_me_a_clean

CC?=gcc
DEBUG?=1
CFLAGS?=-std=gnu99 -O2 -pipe -Wall -Inpcap/Include -Iinclude -DDEBUG=$(DEBUG)
LDFLAGS?=-lpcap -lpthread

SOURCES=main.c linux.c arp.c networking.c

$(OUT): $(SOURCES:%.c=obj/%.o)
	$(CC) $^ -o $@ $(LDFLAGS)

obj/%.o: source/%.c
	$(CC) -c -MD -MP $(CFLAGS) $< -o $@

.PHONY: run clean

run: $(OUT)
	sudo ./$(OUT)

clean:
	rm -f obj/*
	rm -f $(OUT)*

-include $(SOURCES:%.c=obj/%.d)
