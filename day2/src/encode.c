#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "util.h"

static void usage(char *name)
{
	fprintf(stderr, "usage: %s [-g interpacket_gap] "
			"[-o output_file] [-i] input_file\n", name);
	exit(EXIT_FAILURE);
}

/* scrambler scrambles the payload and print out all the information to *f
 * and return a new state
 */
static uint64_t scrambler (uint64_t state, FILE *f, int sync_header, uint64_t payload)
{
	int i;
	uint64_t in_bit, out_bit;
	uint64_t scrambled = 0x0;

	/* This is where you will implement the scrambler */
	for(i = 0; i<64; i++){
		in_bit = (payload >> i) & 0x1;
		out_bit = ((state >> 38)^(state >> 57)^(in_bit)) & 0x1;
		scrambled = (out_bit << i) | scrambled;
		state = (state << 1) | out_bit;
	}

	/* print the scrambled block to *f */
	print_64b66b_block(f, sync_header, scrambled);
	return state;
}

/* @ *packets 	: the array of packets which is defined in util.h
 *	      	  you will only need eth_frame and len
 * @ cnt 	: the number of packets 
 * @ state	: the initial state of the scrambler, i.e. 0xffffffffffffffff
 * @ idle	: the number of idle characters you want to put before each packet
 * @ f		: the file pointer to write the result
 */
static int encode(struct packet *packets, int cnt, uint64_t state, const int idle, FILE *f)
{
	int i, begining_idles=idle, len;
	uint64_t tmp, block_type;
	uint64_t e_frame = 0x1e;
	unsigned char *data;
	static const unsigned char terminal[8] = {0x87, 0x99, 0xaa, 0xb4, 0xcc, 0xd2, 0xe1, 0xff};
	
	/* assume no idle characters in the beginning */
	/* for each packets */
	for ( i = 0 ; i < cnt ; i ++ ) {
		/* data is pointing to the first byte of the packet */
		data = packets[i].eth_frame;
		/* len is the length of the packet */
		len = packets[i].len;

		/* /E/ */
		while (begining_idles >= 8) {
			state = scrambler(state, f, 0x1, e_frame);
			begining_idles -= 8;
		}

		/* /S/ */
		//Section 1
		tmp = 0;
		if(begining_idles > 0 && begining_idles <= 4){	
			block_type = 0x33;
			tmp = *(uint64_t*)data;	
			tmp <<= 40;		//40 = 64(max) - 24(text)
			tmp |= block_type;
			data += 3;
			len -= 3;
		}else{	
		//Section 2
			if(begining_idles != 0){
				state = scrambler(state, f, 0x1, e_frame);
			}
			
			block_type = 0x78;	//allows us to look at 8 bytes then we deference tmp
			tmp = *(uint64_t*)data;	//shift left by 8
			tmp <<= 8;
			tmp |= block_type;
			data += 7; 		//re-assign data to signify that we moved past welcome
			len -= 7;
		}	
		//Section 3
		//this scrambles "welcome" in the first iteration w/ sample text etc
		state = scrambler(state, f, 0x1, tmp);

		//Section 4
		/* Data blocks */
		while(len >= 8){
			tmp = *(uint64_t*)data;
			state = scrambler(state, f, 0x2, tmp);
			data += 8;
			len -= 8;
		}

		/* /T/ */
		//Section 5
		tmp = 0x0;
		block_type = terminal[len];
		if(len != 0){
			tmp = *(uint64_t*)data;
			tmp <<= 8*(8 - len);
			tmp >>= 8*(7 - len);
			tmp |= block_type;
		}
		state = scrambler(state, f, 0x1, tmp);
		
		//Section 6
		begining_idles = idle - (8 - len);      // FIXED
	}

	return 0;
}

void debug_scrambler() 
{
	uint64_t state = 0xffffffffffffffff;
	uint64_t x = 0x0102030405060708;
	uint64_t y = 0x090a0b0c0d0e0f00;

	state = scrambler(state, stdout, 0x1, x);
	state = scrambler(state, stdout, 0x1, y);

	printf("state = %llx\n", (unsigned long long )state);

	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	int c, idle = 12, ret, pcnt;
	char * prg = argv[0];	
	char * inf = NULL, *outf = NULL;

	while((c = getopt(argc, argv, "i:g:o:d")) != -1) {
		switch (c) {
		case 'g':
			idle = atoi(optarg);
			break;
		case 'i':
			inf = optarg;
			break;
		case 'o':
			outf = optarg;
			break;	
		case 'd':
			debug_scrambler();
		default:
			usage(prg);
		}
	}

	if (inf == NULL && optind >= argc) 
		usage(prg);

	if (inf == NULL)
		inf = argv[optind];

	if (idle < 12) {
		fprintf(stderr, "Minimum interpacket gap is 12\n");
		idle = 12;
	}

	/* read packets from inf */
	struct packet *packets;
	if((ret = read_packets_from_file (inf, &packets)) < 0) {
		fprintf(stderr, "Read failed\n");	
		exit(EXIT_FAILURE);
	}
	pcnt = ret;

	/* encode */
	uint64_t state = PCS_INITIAL_STATE;
	FILE *f;
	if (outf) {
		if(!(f = fopen(outf, "w"))) {
			fprintf(stderr, "%s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else
		f = stdout;

	if ((ret = encode(packets, ret, state, idle, f)) < 0) {
		fprintf(stderr, "Encode error\n");
		exit(EXIT_FAILURE);
	}

	if(outf) 
		fclose(f);

	free_packets(packets, pcnt);

	exit(EXIT_SUCCESS);
}
