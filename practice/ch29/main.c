#include "udpcksum.h"

struct sockaddr *dest, *local;
struct sockaddr_in locallookup;
socklen_t destlen, locallen;

int datalink; // from pcap_datalink(), in <net/bpf.h>
char *device; // pcap device
pcap_t *pd;
int rawfd;
int snaplen = 200;  // amount of data to capture
int verbose;
int zerosum; // send udp query with no checksum

static void usage(const char*);

int main(int argc, char **argv) {
    int c, lopt=0;
    char *ptr, localname[1024], *localport;
    struct addrinfo *aip;
    opterr = 0;
    while ((c = getopt(argc, argv, "0i:l:v")) != -1) {
        switch (c) {
        case '0':
            zerosum = 1;
            break;
        case 'i':
            device = optarg;
            break;
        case 'l':
            if ((ptr = strchr(optarg, '.')) == NULL) {
                usage("invalid -l option");
            }
            *ptr++ = 0; // null replace final period
            localport = ptr; // service name or port number
            strncpy(localname, optarg, sizeof(localname));
            lopt = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case '?':
            usage("unrecognized option");
        }
    }

    if (optind != argc - 2) {
        usage("missing <host> and/or <serv>");
    }

    aip = Host_serv(argv[optind], argv[optind+1], AF_INET, SOCK_DGRAM);
    dest = aip->ai_addr;
    destlen = aip->ai_addrlen;

    if (lopt) {
        aip = Host_serv(localname, localport, AF_INET, SOCK_DGRAM);
        local = aip->ai_addr; 
        locallen = aip->ai_addrlen;
    } else {
        int s;
        s = Socket(AF_INET, SOCK_DGRAM, 0);
        Connect(s, dest, destlen);
        locallen = sizeof(locallookup);
        local = (struct sockaddr *)&locallookup;
        Getsockname(s, local, &locallen);
        if (locallookup.sin_addr.s_addr == htonl(INADDR_ANY)) {
            err_quit("Can't determine local address - use - 1\n");
        }
        close(s);
    }
    open_output(); // open output, either raw socket or libnet
    open_pcap();  // open packet capture device
    setuid(getuid()); // dont't need superuser privileges anymore
    Signal(SIGTERM, cleanup);
    Signal(SIGINT, cleanup);
    Signal(SIGHUP, cleanup);
    test_udp();
    cleanup(0);
}


static void
usage(const char *msg)
{
	err_msg(
"usage: udpcksum [ options ] <host> <serv>\n"
"options: -0    send UDP datagram with checksum set to 0\n"
"         -i s  packet capture device\n"
"         -l a.b.c.d.p  local IP=a.b.c.d, local port=p\n"
"         -v    verbose output"
);

	if (msg[0] != 0)
		err_quit("%s", msg);
	exit(1);
}
