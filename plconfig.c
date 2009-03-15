/*
	plconfig.c version 0.2
	Source code for Intellon-based Powerline bridge configuration tool

	Copyright (C) 2002-2003 Manuel Kasper <mk@neon1.net>.
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
	
	1. Redistributions of source code must retain the above copyright notice,
	   this list of conditions and the following disclaimer.
	
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.
	
	THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
	AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
	AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
	OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * 	Linux specific code by Enrik Berkhan <enrik.berkhan@inka.de>
 * 	Copyright (C) 2004 Manuel Kasper <mk@neon1.net>.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#ifdef LINUX
#include <linux/types.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <signal.h>
#else
#include <net/bpf.h>
#endif

#include <sys/socket.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "global.h"
#include "md5.h"

#define PLCONFIG_VERSION "0.2"
#define ETHERTYPE_INTELLON	0x887b

#define logictostr(x) (x) ? "yes" : "no"

#ifndef LINUX
/* bpf instructions to filter for Intellon ethertype packets */
struct bpf_insn insns[] = {
	 BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	 BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_INTELLON, 0, 1),
	 BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
	 BPF_STMT(BPF_RET+BPF_K, 0)
};
#endif

u_short ex_word(u_char *ptr) {
	return ntohs(*((u_short*)ptr));
}

u_long ex_long(u_char *ptr) {
	return ntohl(*((u_long*)ptr));
}

char *format_mac_addr(u_char *addr, char *macbuf) {
	
	sprintf(macbuf, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		
	return macbuf;
}

void dump_params_and_stats(u_char *macmgmt) {
	
	printf("  Tx ACK Counter:             %u\n"
	       "  Tx NACK Counter:            %u\n"
	       "  Tx FAIL Counter:            %u\n"
	       "  Tx Contention Loss Counter: %u\n"
	       "  Tx Collision Counter:       %u\n"
	       "  Tx CA3 Latency Counter:     %u\n"
	       "  Tx CA2 Latency Counter:     %u\n"
	       "  Tx CA1 Latency Counter:     %u\n"
	       "  Tx CA0 Latency Counter:     %u\n"
	       "  Rx Cumul. Bytes per 40-symbol Packet Counter: %lu\n",
	       
	       ex_word(&macmgmt[2]), ex_word(&macmgmt[4]), ex_word(&macmgmt[6]),
	       ex_word(&macmgmt[8]), ex_word(&macmgmt[10]), ex_word(&macmgmt[12]),
	       ex_word(&macmgmt[14]), ex_word(&macmgmt[16]), ex_word(&macmgmt[18]),
	       ex_long(&macmgmt[20]));
}

void dump_network_statistics(u_char *macmgmt) {
	
	int		da;
	u_char	*stat;
	char	macbuf[20];
	
	for (da = 0; da < 15; da++) {
		
		stat = (macmgmt+9+da*12);
		
		/* Check to see if that node entry is valid -
		   stupid Intellon chip is supposed to return 00:00:00:00:00:00 for
		   nonexistant nodes (as per the specs), but instead it returns
		   01:00:00:00:00:00 so we just skip checking the first byte,
		   since heaven knows what else it may return instead of 01 in
		   other places/revisions.
		*/
		
		if (!((stat[1] == 0) && (stat[2] == 0) &&
			  (stat[3] == 0) && (stat[4] == 0) && (stat[5] == 0))) {
			  
			printf("\n  Statistics for Network DA #%d:\n"
				   "  MAC address:         %s\n"
				   "  Bytes in 40 symbols: %u\n"
				   "  FAILS received:      %u\n"
				   "  Frame Drops:         %u\n",
				   
				   da+1, format_mac_addr(stat, macbuf), ex_word(&stat[6]),
				   ex_word(&stat[8]), ex_word(&stat[10])); 
		}
	}
}

void dump_tx_characteristics(u_char *macmgmt) {

	char *retrtab[] = {"Transmit without retries",
		"Transmit with one retry only",
		"Transmit with normal retries (HomePlug)", "Reserved"};
	
	printf("  Local consumption only:        %s\n"
		   "  Encryption flag:               %s\n"
		   "  Transmit priority:             %u\n"
		   "  Response expected:             %s\n"
		   "  Transmit contention free:      %s\n"
		   "  Retry control:                 %s\n"
		   "  No default encryption receive: %s\n"
		   "  No unencrypted receive:        %s\n"
		   "  Transmit EKS:                  %u\n",
		   
		   logictostr(macmgmt[2] & 0x80), logictostr(macmgmt[2] & 0x40),
		   (macmgmt[2] >> 4) & 0x03, logictostr(macmgmt[2] & 0x08), 
		   logictostr(macmgmt[2] & 0x04), retrtab[(macmgmt[3] >> 6) & 0x03],
		   logictostr(macmgmt[3] & 0x08), logictostr(macmgmt[3] & 0x04),
		   macmgmt[4]);
}

void dump_set_key(u_char *macmgmt) {

	char	asckey[17];
	char	*hextab = "0123456789abcdef";
	int		i;
	
	/* Convert the key to ASCII hex */
	for (i = 0; i < 8; i++) {
		asckey[i<<1] = hextab[(macmgmt[i+3] >> 4) & 0x0F];
		asckey[(i<<1)+1] = hextab[macmgmt[i+3] & 0x0F];
	}
	
	asckey[16] = 0;
	
	printf("  Encryption key select:  0x%02x\n"
	       "  Network encryption key: %s\n",
	       
	       macmgmt[2], asckey); 
	       
}

void read_display_responses(int netfd, u_char *framebuf, u_int buflen) {

	u_char	*frameptr;
	ssize_t rdlen;
	u_int	i, j;
#ifdef LINUX
	struct sockaddr_ll addr;
	socklen_t addrlen = sizeof(addr);
#else
	struct bpf_hdr *header;
#endif
	char macbuf[20];

	/* read responses */
	signal(SIGALRM, exit);
	alarm(1);
	while (1) {
#ifdef LINUX
		rdlen = recvfrom(netfd, framebuf+ETHER_HDR_LEN, buflen-ETHER_HDR_LEN, MSG_TRUNC, (struct sockaddr *)&addr, &addrlen);
#else
		rdlen = read(netfd, framebuf, buflen);
#endif
		
		if (rdlen != -1) {
		
#ifdef LINUX
			if ((u_int)rdlen > buflen-ETHER_HDR_LEN) {
				fprintf(stderr, "received jumbo frame of %zd bytes len, truncated\n", rdlen);
			}
			frameptr = framebuf;
			memcpy(framebuf+6, &addr.sll_addr, 6);

			if (addr.sll_pkttype != PACKET_OUTGOING &&
			    addr.sll_protocol == htons(ETHERTYPE_INTELLON)) {
#else
			header = (struct bpf_hdr*)framebuf;
			frameptr = framebuf + header->bh_hdrlen;
			
			if ((frameptr[12] == 0x88) && (frameptr[13] == 0x7B)) {
#endif
			
				/* It's an intellon packet - read MAC management entries */
				j = 15;
				
				for (i = 0; i < (frameptr[14] & (u_int)0x7F); i++) {
					switch (frameptr[j]) {
					
						case 0x04:		/* Set Network Encryption Key */
							printf("\n- Set Network Encryption Key from %s\n",
								format_mac_addr(&frameptr[6], macbuf));
								
							dump_set_key(&frameptr[j]);
							break;
					
						case 0x07:		/* Request Parameters and Statistics */
							printf("\n- Parameters and Statistics request from %s\n",
								format_mac_addr(&frameptr[6], macbuf));
							break;
					
						case 0x08:		/* Parameters and Statistics Response */
							printf("\n- Parameters and Statistics response from %s\n",
								format_mac_addr(&frameptr[6], macbuf));
								
							dump_params_and_stats(&frameptr[j]);
							break;
							
						case 0x06:		/* Confirm Network Encryption Key */
							printf("\n- Network encryption key confirmation from %s\n",
								format_mac_addr(&frameptr[6], macbuf));
							break;
							
						case 0x1a:		/* Intellon specific network statistics */
							if (!(frameptr[j+2] & 0x80)) 	{	/* Really a response? */
								printf("\n- Intellon-specific network statistics from %s\n",
									format_mac_addr(&frameptr[6], macbuf));
								
								dump_network_statistics(&frameptr[j]);
							} else {
								printf("\n- Intellon-specific network statistics  request from %s\n",
								       format_mac_addr(&frameptr[6], macbuf));
							}
							break;
							
						case 0x1f:		/* Set transmit characteristics */
							printf("\n- Set transmit characteristics from %s\n",
								format_mac_addr(&frameptr[6], macbuf));
								
							dump_tx_characteristics(&frameptr[j]);							
							break;
							
							
						default:
							printf("- Unknown response (MTYPE = 0x%02x) from %s\n",
								frameptr[j], format_mac_addr(&frameptr[6], macbuf));
					}
					j += frameptr[j+1] + 2;
				}
			}
		}
	}
}

unsigned char deskeyparity(unsigned char kb) {
	unsigned char parity = 0, i, mykb = kb;
	
	for (i = 0; i < 7; i++) {
		mykb >>= 1;
		parity += (mykb & 0x01);
	}
	
	return ((kb & 0xFE) | (~parity & 0x01));
}

void usage(void) {
	
	printf("%s",
	       "\nPowerline Bridge config version " PLCONFIG_VERSION " by Manuel Kasper <mk@neon1.net>\n\n"
#ifdef LINUX
	       "Usage:   plconfig [-pqrh] [-s key] interface\n\n"
#else
	       "Usage:   plconfig [-pqrh] [-b device] [-s key] interface\n\n"
#endif
	
		   "         -s key            set network encryption key\n"
		   "                           (plaintext password or 8 hex bytes preceded by 0x)\n"
#ifndef LINUX
		   "         -b device         use device (default is /dev/bpf0)\n"
#endif
		   "         -p                don't switch interface to promiscuous mode\n"
		   "         -r                request parameters and statistics\n"
		   "         -q                request Intellon-specific network statistics\n"
		   "         -h                display this help\n\n"
		   
		   "         If -s is not specified, plconfig will listen for management packets\n"
		   "         indefinitely (after requesting stats if -r is specified)\n\n");
}

int main(int argc, char *argv[]) {
	int netfd, ch;
#ifdef LINUX
	struct sockaddr_ll addr = { 0,0,0,0,0,0,{0,} };
#else
	struct bpf_program filter;
#endif
	struct ifreq ifr;
	u_int buflen, i;
	u_char *framebuf;
#ifndef LINUX
	char ifname[8], bpfn[32] = "/dev/bpf0";
#endif
	u_char netkey[8], nib, outframe[200];
	
	/* options */
	int nopromisc = 0, mode = 0;
		
	/* Parse command line options */
	while ((ch = getopt(argc, argv, "s:b:pqrh")) != -1) {
	 
		 switch (ch) {
		 
			 case 'p':
				nopromisc = 1;
				break;
				
			 case 'r':
				mode = 1;
				break;
				
			 case 'q':
				mode = 3;
				break;
				
			 case 's':
				mode = 2;
				
				/* See if it begins with 0x */
				if ((optarg[0] == '0') && (optarg[1] == 'x')) {
								
					for (i = 0; i < 8; i++)
						netkey[i] = 0;
					
					/* convert ASCII hex to binary */
					for (i = 0; i < 16; i++) {
						if ((optarg[i+2] >= '0') && (optarg[i+2] <= '9')) {
							nib = optarg[i+2] - '0';
						} else if ((optarg[i+2] >= 'a') && (optarg[i+2] <= 'f')) {
							nib = optarg[i+2] + 0x0a - 'a';
						} else if ((optarg[i+2] >= 'A') && (optarg[i+2] <= 'F')) {
							nib = optarg[i+2] + 0x0a - 'A';
						} else {
							fprintf(stderr, "Unrecognized character '%c' in key\n", optarg[i+2]);
							exit(1);
						}
						
						if (i & 0x01)
							netkey[i >> 1] |= nib;
						else
							netkey[i >> 1] |= (nib << 4);
					}
				} else {
					/* It's a plaintext password - use PBKDF1 on it */
					MD5_CTX	md5ctx;
					char	digest[16], tmp[256];
					
					strncpy(tmp, optarg, 240);
					/* add salt */
					strcat(tmp, "\x08\x85\x6d\xaf\x7c\xf5\x81\x85");
					
					/* generate initial digest */
					MD5Init(&md5ctx);
					MD5Update(&md5ctx, tmp, strlen(tmp));
					MD5Final(digest, &md5ctx);
					
					/* loop 999 times as required by HomePlug */
					for (i = 0; i < 999; i++) {
						MD5Init(&md5ctx);
						MD5Update(&md5ctx, digest, 16);
						MD5Final(digest, &md5ctx);
					}
					
					/*	extract the first 8 bytes; calculate parity bit
						(LSB = odd parity), even though most powerline bridges
						seem to ignore it
					*/
					for (i = 0; i < 8; i++)
						netkey[i] = deskeyparity(digest[i]);
				}
				break;
				
#ifndef LINUX
			 case 'b':
				strncpy(bpfn, optarg, 32);
				break;
#endif
				
			 case '?':
			 case 'h':
			 default:
				usage();
				exit(0);
		 }
	}
	
	argc -= optind;
    argv += optind;
	
	if (argc != 1) {
		usage();
		exit(0);
	}
	
#ifndef LINUX
	strncpy(ifname, argv[0], 8);
#endif
	
	/* Open bpf device */
#ifdef LINUX
	netfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_INTELLON));
	if (netfd == -1) {
		perror("socket");
		exit(0);
	}
#else
	netfd = open(bpfn, O_RDWR);
	if (netfd == -1) {
		fprintf(stderr, "Cannot open %s\n", bpfn);
		exit(0);
	}
#endif
	
#ifdef LINUX
	strncpy(ifr.ifr_name, argv[0], sizeof(ifr.ifr_name));
	if (ioctl(netfd, SIOCGIFMTU, &ifr) == -1) {
		perror("ioctl(SIOCGIFMTU)");
		return(1);
	}
	buflen = ifr.ifr_mtu + ETHER_HDR_LEN;
#else
	/* Read buffer length */
	if (ioctl(netfd, BIOCGBLEN, &buflen) == -1) {
		fprintf(stderr, "ioctl(BIOCGBLEN) error!\n");
		exit(0);
	}
#endif
	
	/* Allocate buffer */
	if (!(framebuf = (u_char*)malloc((size_t)buflen))) {
		fprintf(stderr, "Cannot malloc() packet buffer!\n");
		exit(0);
	}
	
	/* Bind to interface */
#ifdef LINUX
	if (ioctl(netfd, SIOCGIFINDEX, &ifr) == -1) {
		perror("ioctl(SIOCGIFINDEX)");
		return(1);
	}
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETHERTYPE_INTELLON);
	addr.sll_ifindex = ifr.ifr_ifindex;
	if (bind(netfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("bind");
		return(1);
	}
#else
	strcpy(ifr.ifr_name, ifname);
	
	if (ioctl(netfd, BIOCSETIF, &ifr) == -1) {
		fprintf(stderr, "ioctl(BIOCSETIF) error!\n");
		exit(0);
	}
#endif

#ifndef LINUX
	/* Set filter */
	filter.bf_len = sizeof(insns) / sizeof(insns[0]);
	filter.bf_insns = insns;

	if (ioctl(netfd, BIOCSETF, &filter) == -1) {
		fprintf(stderr, "ioctl(BIOCSETF) error!\n");
		exit(0);
	}

	/* Set immediate mode */
	i = 1;	
	if (ioctl(netfd, BIOCIMMEDIATE, &i) == -1) {
		fprintf(stderr, "ioctl(BIOCIMMEDIATE) error!\n");
		exit(0);
	}
#endif
	
	/* Set promiscuous mode
	   This is necessary because the bridges seem to be returning
	   responses with the destination MAC address set to their own
	   MAC address instead of using broadcasts.
	*/
	if ((!nopromisc) && (mode != 2)) {
#ifdef LINUX
		struct packet_mreq mreq = { ifr.ifr_ifindex, PACKET_MR_PROMISC, 0, {0, }};
		if (setsockopt(netfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
			perror("setsockopt(PACKET_ADD_MEMBERSHIP, PROMISC)");
			return 1;
		}
#else
		i = 1;	
		if (ioctl(netfd, BIOCPROMISC, &i) == -1) {
			fprintf(stderr, "ioctl(BIOCPROMISC) error!\n");
			exit(0);
		}
#endif
	}
	
#ifndef LINUX
	/* We don't want to see local packets */	
	i = 0;	
	if (ioctl(netfd, BIOCGSEESENT, &i) == -1) {
		fprintf(stderr, "ioctl(BIOCGSEESENT) error!\n");
		exit(0);
	}
#endif
	
	if (mode) {
#ifdef LINUX
		addr.sll_family = AF_PACKET;
		addr.sll_protocol = htons(ETHERTYPE_INTELLON);
		addr.sll_ifindex = ifr.ifr_ifindex;
		addr.sll_halen = 6;
		for (i = 0; i < 6; i++)
			addr.sll_addr[i] = 0xFF;        /* broadcast */
		outframe[0] =0x01;    /* one MAC management entry */
#else
		/* set up outgoing command frame */
		for (i = 0; i < 6; i++)
			outframe[i] = 0xFF;		/* broadcast */
			
		for (i = 0; i < 6; i++)
			outframe[i+6] = 0x00;	/* the source address will be set automatically */
			
		outframe[12] = 0x88;	/* Intellon ethertype */
		outframe[13] = 0x7b;
		
		outframe[14] = 0x01;	/* one MAC management entry */
#endif
	}
	
	switch (mode) {
	
		case 1:		/* request parameters & statistics */
#ifdef LINUX
			outframe[1] = 0x07;	/* request parameters and statistics */
			outframe[2] = 0x0;	    /* 0 bytes follow */
			
			/* write out packet */
			sendto(netfd, outframe, 3, 0, (struct sockaddr *)&addr, sizeof(addr));
#else
			outframe[15] = 0x07;	/* request parameters and statistics */
			outframe[16] = 0x0;	    /* 0 bytes follow */
			
			/* fill the rest with zeroes to maintain minimum data payload of 46 bytes */
			for (i = 0; i < 43; i++)
				outframe[i+17] = 0x00;
		
			/* write out packet */
			write(netfd, outframe, 60);
#endif
			break;
			
		case 2:		/* set network key */
#ifdef LINUX
			outframe[1] = 0x04;	/* set network key */
			outframe[2] = 0x09;	/* 9 bytes follow */
			outframe[3] = 0x01;	/* encryption key select -> 1 */
			
			for (i = 0; i < 8; i++)
				outframe[i+4] = netkey[i];

			/* write out packet */
			sendto(netfd, outframe, 12, 0, (struct sockaddr *)&addr, sizeof(addr));
#else
			outframe[15] = 0x04;	/* set network key */
			outframe[16] = 0x09;	/* 9 bytes follow */
			outframe[17] = 0x01;	/* encryption key select -> 1 */
			
			for (i = 0; i < 8; i++)
				outframe[i+18] = netkey[i];
				
			/* fill the rest with zeroes to maintain minimum data payload of 46 bytes */
			for (i = 0; i < 34; i++)
				outframe[i+26] = 0x00;
		
			/* write out packet */
			write(netfd, outframe, 60);
#endif
			break;
			
		case 3:		/* request Intellon-specific network statistics */
#ifdef LINUX
			outframe[1] = 0x1a;	/* request network statistics */
			outframe[2] = 0xbb;	/* 187 bytes follow */
			
			outframe[3] = 0x80;	/* read the stats, don't clear them */
			
			for (i = 0; i < 186; i++)
				outframe[i+4] = 0x00;
		
			/* write out packet */
			sendto(netfd, outframe, 190, 0, (struct sockaddr *)&addr, sizeof(addr));
#else
			outframe[15] = 0x1a;	/* request network statistics */
			outframe[16] = 0xbb;	/* 187 bytes follow */
			
			outframe[17] = 0x80;	/* read the stats, don't clear them */
			
			for (i = 0; i < 186; i++)
				outframe[i+18] = 0x00;
		
			/* write out packet */
			write(netfd, outframe, 204);
#endif
			break;
	}
	
	if (mode != 2)
		read_display_responses(netfd, framebuf, buflen);
	
	free(framebuf);
	
	/* Close bpf device */
	close(netfd);
	return 0;
}
