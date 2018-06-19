#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include "util.h"

void print_binary (uint64_t x, int len)
{
	int i;
	for ( i = 63 ; i >=0 ; i--) {
		printf("%s", (x>>i) ? "1" : "0");
	}
}

void print_64b66b_block(FILE *f, int sync_header, uint64_t payload)
{
	fprintf(f, "%s, %.16llx\n", sync_header == 1 ? "01" : "10",
			(unsigned long long) payload);
}

void print_block(FILE *f, struct block *block)
{
	print_64b66b_block(f, block->sync_header, block->payload);
}

void print_blocks(FILE *f, struct block *blocks, int cnt)
{
	int i;
	for ( i = 0 ; i < cnt ; i ++) {
		print_block(f, &blocks[i]);
	}
}

void print_packet(FILE *f, struct packet *packet)
{
	int i;

	if (!f)
		f = stdout;

	for ( i = 0 ; i < packet->len; i ++) {
		if ( i % 32 == 0)
			fprintf(f, "%.4d ~ %.4d : ", i+1, 
					i+32 > packet->len ? packet->len : i+32);

		fprintf(f, "%.2x ", (unsigned char ) packet->eth_frame[i]);

		if (i % 32 == 31)
			fprintf(f, "\n");
	}

	if (i % 32 != 31)
		fprintf(f, "\n");

}

void print_packets(FILE *f, struct packet *packets, int cnt)
{
	int i;
	for ( i = 0 ; i < cnt ; i ++) 
		print_packet(f, &packets[i]);

}

void free_blocks(struct block *blocks)
{
	free(blocks);
}

int read_blocks_from_file (const char *fname, struct block **pblocks)
{
	FILE *f = NULL;
	char buf[40], *p;
	struct block *blocks = NULL, * tmp;
	int blocks_cnt = 1024, retval = -1, cnt=0;

	if (!(f = fopen(fname, "r"))) 
		return -errno;

	if (!(blocks = malloc(blocks_cnt * sizeof(struct block)))) {
		retval = -errno;
		fclose(f);
		return retval;
	}

	while (fgets(buf, 40, f)) {
		for ( p = buf ; *p != '\0' && (*p == ' ' || *p == '\t'); p++)
			;

		if (*p == '\n')
			continue;

		if (cnt == blocks_cnt) {
			blocks_cnt *= 2;

			tmp = realloc(blocks, blocks_cnt * (sizeof(struct block)));
			if (!tmp) {
				retval = -errno;
				fclose(f);
				free(blocks);
				return retval;
			}
			blocks = tmp;
		}

		sscanf(p, "%hhx, %llx", &blocks[cnt].sync_header, &blocks[cnt].payload);
		cnt++;
	}
	retval = cnt;
	fclose(f);
	*pblocks = blocks;
	return retval;
}

void free_packets(struct packet * packets, int cnt)
{
	int i;


	for ( i = 0 ; i < cnt ; i ++) {
		free(packets[i].eth_frame);
	}

	free(packets);
}

int read_packets_from_file (const char *fname, struct packet **ppackets)
{
	FILE *f = NULL;
	char buf[4 * DEFAULT_MTU], *p;
	struct packet *packets = NULL, *tmp;
	int packets_cnt = 1024, retval = -1, cnt = 0, len=0;

	if(!(f = fopen(fname, "r")))
		return -errno;

	if(!(packets = malloc(packets_cnt * sizeof(struct packet)))) {
		retval = -errno;
		fclose(f);
		return retval;
	}

	while(fgets(buf, 4 * DEFAULT_MTU, f)) {
		if (cnt == packets_cnt) {
			packets_cnt *= 2;

			tmp = realloc(packets, packets_cnt * (sizeof(struct packet)));
			if (!tmp) {
				retval = -errno;
				fclose(f);
				free_packets(packets, cnt);
				return retval;
			}
			packets = tmp;
		}

		len = strlen(buf);

		if (buf[len-1] == '\n') {
			buf[len-1] = '\0';
			len --;
		}

		len = len / 2;

		tmp = &packets[cnt];
		tmp->capacity = len;
		tmp->len = 0;

		if(!(tmp->eth_frame = malloc(len))) {
			retval = -errno;
			fclose(f);
			free_packets(packets, cnt);
			return retval;
		}

		p = buf;
		while ( tmp->len != tmp->capacity) {
			char x[2];
			memcpy(x, p, 2);
			sscanf(x, "%hhx", (unsigned char*)&tmp->eth_frame[tmp->len++]);
			p += 2;
		}
		
		cnt ++;
	}

	fclose(f);
	retval = cnt;
	*ppackets = packets;

	return retval;
}
