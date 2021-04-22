#include "unp.h"

void str_cli(FILE *fp, int sockfd) {
    int maxfdp1, stdineof;
    fd_set rset;
    char buf[MAXLINE];
    int n;

    stdineof = 0;
    FD_ZERO(&rset);
    for ( ; ; ) {
        if (stdineof == 0) {
            FD_SET(fileno(fp), &rset);
        }
        FD_SET(sockfd, &rset);
        maxfdp1 = max(fileno(fp), sockfd) + 1;
        Select(maxfdp1, &rset, NULL, NULL, NULL);
        if (FD_ISSET(sockfd, &rset)) {  // socket is readable
            if ( (n = Read(sockfd, buf, MAXLINE)) == 0) {
                if (stdineof == 1) {
                    return ; // normal termination
                } else {
                    err_quit("str_cli: server terminated permaturely");
                }
            }
            Write(fileno(stdout), buf, n);
        }
        if (FD_ISSET(fileno(fp), &rset)) {  // input is readable
            if ((n = Read(fileno(fp), buf, MAXLINE)) == 0) {
                stdineof = 1;
                Shutdown(sockfd, SHUT_WR);  // send FIN
                FD_CLR(fileno(fp), &rset);
                continue;
            }
            Writen(sockfd, buf, n);
        }
    }
}

// void str_cli(FILE *fp, int sockfd) {
//     int maxfdp1;
//     fd_set rset;
//     char sendline[MAXLINE], recvline[MAXLINE];
//     FD_ZERO(&rset);
//     for ( ; ; ) {
//         FD_SET(fileno(fp), &rset);
//         FD_SET(sockfd, &rset);
//         maxfdp1 = max(fileno(fp), sockfd) + 1;
//         Select(maxfdp1, &rset, NULL, NULL, NULL);

//         if (FD_ISSET(sockfd, &rset)) {
//             if (Readline(sockfd, recvline, MAXLINE) == 0) {
//                 err_quit("str_cli: server terminated prematurely");
//             }
//             Fputs("....", stdout);
//             Fputs(recvline, stdout);
//         }

//         if (FD_ISSET(fileno(fp), &rset)) {
//             if (Fgets(sendline, MAXLINE, fp) == NULL) {
//                 return;
//             }
//             Writen(sockfd, "xxx", 3);
//             Writen(sockfd, sendline, strlen(sendline));
//         }
//     }
// }

// // void str_cli(FILE *fp, int sockfd) {
// //     char sendline[MAXLINE], recvline[MAXLINE];
// //     while (Fgets(sendline, MAXLINE, fp) != NULL) {
// //         Writen(sockfd, sendline, 1);
// //         sleep(1);
// //         Writen(sockfd, sendline + 1, strlen(sendline) - 1);
// //         if (Readline(sockfd, recvline, MAXLINE) == 0) {
// //             err_quit("str_cli: server terminated permaturely");
// //         }
// //         Fputs(recvline, stdout);
// //     }
// // }