CC = gcc
CFLAGS = -g -ggdb -Wall -Wpedantic -Wextra \
	-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE \
	-Wformat -Wformat-security 

TARGETS = bin/unittest bin/mydig bin/digpcap

all: $(TARGETS)

tmp/%.o: src/%.c
	@echo cc -c -o $0 $<
	@$(CC) -c -o $@ $< $(CFLAGS)

bin/mydig: tmp/dns-parse.o tmp/dns-format.o tmp/app-dig.o
	@echo $@
	@$(CC) $(CFLAGS) $^  -o $@ -lresolv

bin/unittest: tmp/dns-parse.o tmp/dns-format.o tmp/app-unittest.o
	@echo $@
	@$(CC) $(CFLAGS) $^  -o $@

bin/digpcap: tmp/dns-parse.o tmp/dns-format.o tmp/app-digpcap.o tmp/util-threads.o \
	tmp/util-hashmap.o tmp/util-packet.o tmp/util-pcapfile.o tmp/util-tcpreasm.o \
	tmp/siphash24.o tmp/util-timeouts.o
	@echo $@
	@$(CC) $(CFLAGS) $^ -lpthread -o $@

	

clean:
	@echo rm $(TARGETS)
	@echo rm tmp/*.o
	@rm -f $(TARGETS) 2>/dev/null || true
	@rm -f tmp/*.o 2>/dev/null || true


