#include <bits/stdc++.h>
#include "./headsock.h"

using namespace std;

void start() {
    int sockfd;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr, cliaddr;
    struct state s;
    struct state old_s;
    
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    memset(&s, 0, sizeof(s));
    memset(&old_s, 0, sizeof(s));
       
    setup(sockfd, servaddr);
    for (;;) {
        size_t n = rx(buffer, sockfd, sizeof(cliaddr), &cliaddr);
        // make a copy of s
        memcpy(&old_s, &s, sizeof(s));
        read(n, buffer, s);

        size_t l = write(buffer, s, old_s);
        tx(buffer, l, sockfd, sizeof(cliaddr), &cliaddr);
    }
}

int main(void) {
    printf("Hello From Server\n\n\n");
    start();

    return 0;
}