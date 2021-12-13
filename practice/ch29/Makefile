

# run eg: sudo ./cksum -i en0 -0 -v 8.8.8.8 domain

all: cksum

cksum:
	gcc -I../lib  -I./ -o cksum main.c cleanup.c pcap.c send_dns_query.c udpcksum.c udpread.c udpwrite.c  ../libunp.a /usr/local/Cellar/libpcap/1.10.1/lib/libpcap.a

clean:
	rm -f cksum