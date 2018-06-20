CFLAGS= -Wall -g
LDFLAGS=
CC= gcc
IDLE=12
IDLEC=" " 

all: encode decode

encode: encode.c util.c util.h
	$(shell  /tmp/check_encode.sh)
	$(CC) $(CFLAGS) -o $@ $^

decode: decode.c util.c util.h
	$(shell  /tmp/check_decode.sh)
	$(CC) $(CFLAGS) -o $@ $^

encode.c:

fun: encode decode 
	./encode -i sonic_example2 -o tmp2 -g $(IDLE) 
	./decode -i tmp2 -c $(IDLEC)

clean:
	rm -rf *.o encode decode pgen tmp tmp2
