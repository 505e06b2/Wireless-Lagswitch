OUT=mitm_gta_online

CC?=gcc
MAKE?=make
DEBUG?=1
CFLAGS?=-std=gnu99 -O2 -pipe -Wall -Inpcap/Include -Iinclude -DDEBUG=$(DEBUG)
LDFLAGS?=-lpcap -lnetfilter_queue -lpthread

SOURCES=main.c linux.c arp.c networking.c args.c routing.c blacklist.c

$(OUT): $(SOURCES:%.c=obj/%.o)
	$(CC) $^ -o $@ $(LDFLAGS)

source/blacklist.c: generate_blacklisted_ips.py
	./generate_blacklisted_ips.py

obj/%.o: source/%.c
	$(CC) -c -MD -MP $(CFLAGS) $< -o $@

.PHONY: run clean release

release:
	$(MAKE) clean
	$(MAKE) DEBUG=0 $(MAKEFLAGS)

run: $(OUT)
	sudo ./$(OUT)

clean:
	rm -f obj/*
	rm -f $(OUT)*

-include $(SOURCES:%.c=obj/%.d)
