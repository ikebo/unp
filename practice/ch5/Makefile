include ../Make.defines

PROGS = echo_cli01 echo_serv01 tcpserv02 tcpserv03 tcpcli04

all: ${PROGS}

echo_cli01: echo_cli01.o str_cli.o
	${CC} ${CFLAGS} -o $@ echo_cli01.o str_cli.o ${LIBS}

echo_serv01: echo_serv01.o
	${CC} ${CFLAGS} -o $@ echo_serv01.o ${LIBS}

tcpserv02: tcpserv02.o sigchldwait.o
	${CC} ${CFLAGS} -o $@ tcpserv02.o sigchldwait.o ${LIBS}

tcpserv03: tcpserv03.o sigchldwaitpid.o
	${CC} ${CFLAGS}  -o $@ tcpserv03.o sigchldwaitpid.o ${LIBS}

tcpcli04: tcpcli04.o
	${CC} ${CFLAGS} -o $@ tcpcli04.o ${LIBS}





