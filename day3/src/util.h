#ifndef __SONIC_UTIL__
#include <stdint.h>
#include <stdio.h>

#define DEFAULT_MTU	1500
#define PCS_INITIAL_STATE 0xffffffffffffffffULL

struct block {
	char sync_header;
	unsigned long long payload;
};

struct packet {
	int capacity;
	int len;
	int idles;
	unsigned char *eth_frame;
};

void print_64b66b_block(FILE *, int, uint64_t);

void print_block(FILE *, struct block *);
void print_blocks(FILE *, struct block *, int);
void free_blocks(struct block *);
int read_blocks_from_file (const char *, struct block **);

void print_packet(FILE *, struct packet *);
void print_packets(FILE *, struct packet *, int);
void free_packets(struct packet *, int);
int read_packets_from_file (const char *, struct packet **);

#endif /* __SONIC_UTIL__ */
