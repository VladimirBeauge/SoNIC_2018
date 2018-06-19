
SDNA := sonic
DIST_FILE = $(SDNA).tar.gz

all: parser

fresh: clean all

CFLAGS = -Wall -O2
CC = gcc $(CFLAGS)

util.o: util.c
	$(CC) -c util.c

parser: parser.c util.o
	$(CC) -o $@ util.o parser.c -lpcap

parser-clean:
	rm -f day1

dist: clean
	tar -cvzf /tmp/$(DIST_FILE) ../$(SDNA) --exclude=".svn" && mv /tmp/$(DIST_FILE) .

clean: parser-clean
	rm -fr *.pyc *.o *~ a.out *.dSYM $(DIST_FILE) parser

fresh: clean all
