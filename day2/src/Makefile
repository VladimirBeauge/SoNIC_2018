CFLAGS= -Wall -g
LDFLAGS=
CC= gcc

all: encode 

encode: encode.c util.c util.h
	$(CC) $(CFLAGS) -o $@ $^

fun: encode 
	./encode -i sonic_example -o tmp
	./decode -i tmp 

clean:
	rm -rf *.o encode tmp tmp2
