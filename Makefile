CC = gcc
CFLAGS = -g -ggdb -Wall -Wpedantic -Wextra \
	-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE \
	-Wformat -Wformat-security 

TARGETS = bin/unittest bin/mydig

all: $(TARGETS)

tmp/%.o: src/%.c 
	$(CC) -c -o $@ $< $(CFLAGS)

bin/mydig: tmp/dns-parse.o tmp/dns-format.o tmp/app-dig.o
	@echo $@
	$(CC) $(CFLAGS) $^  -o $@ -lresolv

bin/unittest: tmp/dns-parse.o tmp/dns-format.o tmp/app-unittest.o
	@echo $@
	$(CC) $(CFLAGS) $^  -o $@

	

clean: 
	rm $(TARGETS)
	rm tmp/*


