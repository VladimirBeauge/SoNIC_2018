#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <pcap.h>
#include "util.h"

struct udp_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

/* parse_udp_packet()
 *
 * This routine parses a packet, expecting Ethernet, IP, and UDP headers.
 * It extracts the UDP source and destination port numbers along with the UDP * packet length by casting structs over a pointer that we move through
 * the packet.  We can do this sort of casting safely because libpcap
 * guarantees that the pointer will be aligned.
 *
 * The "ts" argument is the timestamp associated with the packet.
 *
 * Note that "capture_len" is the length of the packet *as captured by the
 * tracing program*, and thus might be less than the full length of the
 * packet.  However, the packet pointer only holds that much data, so
 * we have to be careful not to read beyond it.
 */
void parse_udp_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len) {
	//remove the header
	const unsigned char* payload = packet + 42;
	
	//print bytes
	static int x=0, y=0;
	while(payload != packet + capture_len){
		printf("%c", *payload);	
		payload++;
		
		x++;
		if( (y % 262 == 261) && (x % 195 == 194) ){
			printf("\n");
			x++;	
			y++;
		}
		else if(x % 195 == 0){
			printf("\n");
			y++;
		}
	}
}

int main(int argc, char *argv[]) {
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const unsigned char* packet;

	/* Skip over the program name. */
	++argv; --argc;
	
	/* Check the validity of argument */
	if(argc != 1){
		fprintf(stderr, "Only 1 Argument: You gave %d\n", argc);
		exit(1);
	}
	/* Get a handle to the pcap log file*/
	pcap = pcap_open_offline(argv[0], errbuf);	
	if(pcap == NULL){
		fprintf(stderr, "Error reading cap file %s\n", errbuf);
		exit(1);
	}

	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */	
	while( (packet = pcap_next(pcap, &header)) != NULL ){
		//parse packet
		parse_udp_packet(packet, header.ts, header.len);
	}

	// terminate
	return 0;
}

