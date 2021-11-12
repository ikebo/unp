include ../Make.defines

PROGS =	cli01 serv01 dg_cli.o udp_local_addr  serv_select

all:	${PROGS}

cli01:	udpcli01.o dg_cli.o
	${CC} ${CFLAGS} -o $@ $^ ${LIBS}

serv01: udpserv01.o dg_echo.o
	${CC} ${CFLAGS} -o $@ $^ ${LIBS}

dg_cli.o: dg_cli_traffic.c
	${CC} ${CFLAGS} -o $@ -c $<

dg_echo.o: dg_echo_traffic.c
	${CC} ${CFLAGS} -o $@ -c $<

udp_local_addr: udp_local_addr.c
	${CC} ${CFLAGS} -o $@ $< ${LIBS}

serv_select: udp_serv_select.c sigchldwait.c
	${CC} ${CFLAGS} -o $@ $^ ${LIBS}

clean:
	rm -f ${PROGS} *.o