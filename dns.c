/*
Copyright (c) 2013, Ethan Willoner
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "dns.h"

void error(char *str)
{
    printf("%s\n",str);
}

// Taken from http://www.binarytides.com/raw-udp-sockets-c-linux/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((unsigned char *)&oddbyte)=*(unsigned char *)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

// Taken from http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
void dns_format(unsigned char * dns,unsigned char * host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++=0x00;
}

// Creates the dns header and packet
void dns_hdr_create(dns_hdr *dns)
{
	dns->id = (unsigned short) htons(getpid());
	dns->flags = htons(0x0100);
	dns->qcount = htons(1);
	dns->ans = 0;
	dns->auth = 0;
	dns->add = 0;
}

void dns_send(char *trgt_ip, int trgt_p, char *dns_srv, int dns_p,
	unsigned char *dns_record)
{
	// Building the DNS request data packet
	
	unsigned char dns_data[128];
	
	dns_hdr *dns = (dns_hdr *)&dns_data;
	dns_hdr_create(dns);
	
	unsigned char *dns_name, dns_rcrd[32];
	dns_name = (unsigned char *)&dns_data[sizeof(dns_hdr)];
	strcpy(dns_rcrd, dns_record);
	dns_format(dns_name , dns_rcrd);
	
	query *q;
	q = (query *)&dns_data[sizeof(dns_hdr) + (strlen(dns_name)+1)];
	q->qtype = htons(0x00ff);
	q->qclass = htons(0x1);
	
	
	// Building the IP and UDP headers
	char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);
    
	data = datagram + sizeof(iph) + sizeof(udph);
    memcpy(data, &dns_data, sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) +1);
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dns_p);
    sin.sin_addr.s_addr = inet_addr(dns_srv);
    
    iph *ip = (iph *)datagram;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(iph) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(trgt_ip);
    ip->daddr = sin.sin_addr.s_addr;
	ip->check = csum((unsigned short *)datagram, ip->tot_len);
	
    udph *udp = (udph *)(datagram + sizeof(iph));
	udp->source = htons(trgt_p);
    udp->dest = htons(dns_p);
    udp->len = htons(8+sizeof(dns_hdr)+(strlen(dns_name)+1)+sizeof(query));
    udp->check = 0;
	
	// Pseudoheader creation and checksum calculation
	ps_hdr pshdr;
	pshdr.saddr = inet_addr(trgt_ip);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));

	int pssize = sizeof(ps_hdr) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    psgram = malloc(pssize);
	
    memcpy(psgram, (char *)&pshdr, sizeof(ps_hdr));
    memcpy(psgram + sizeof(ps_hdr), udp, sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));
		
    udp->check = csum((unsigned short *)psgram, pssize);
    
    // Send data
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd==-1) error("Could not create socket.");
    else sendto(sd, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    
	free(psgram);
	close(sd);
	
	return;
}
