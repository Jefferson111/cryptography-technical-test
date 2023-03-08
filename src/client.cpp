#include <bits/stdc++.h>
#include "./headsock.h"

using namespace std;

void start() {
    int sockfd;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr;
    struct state s;
    struct state old_s;
    
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&s, 0, sizeof(s));
    memset(&old_s, 0, sizeof(s));

    setup_initiator(sockfd, servaddr); 
    s.EXCHANGE_TYPE = IKE_SA_INIT;
    s.initiator_spi = rand();
    s.responder_spi = 0;
    s.q.device = 17;
    s.I = true;

    printf("Starting IKE_SA_INIT...\n");
    
    for (;;) {
        size_t l = write(buffer, s, old_s);
        if (!tx(buffer, l, sockfd, sizeof(servaddr), &servaddr)) {
            break;
        }

        size_t n = rx(buffer, sockfd, sizeof(servaddr), &servaddr);
        // make a copy of s
        memcpy(&old_s, &s, sizeof(s));
        read(n, buffer, s);
    }

    s.EXCHANGE_TYPE = CREATE_CHILD_SA;
    s.q.device = 33;
    s.I = true;
    s.R = false;
    printf("Starting CREATE_CHILD_SA...\n");

    for (;;) {
        size_t l = write(buffer, s, old_s);
        if (!tx(buffer, l, sockfd, sizeof(servaddr), &servaddr)) {
            break;
        }

        size_t n = rx(buffer, sockfd, sizeof(servaddr), &servaddr);
        // make a copy of s
        memcpy(&old_s, &s, sizeof(s));
        read(n, buffer, s);
    }

    s.EXCHANGE_TYPE = CREATE_CHILD_SA;
    s.q.device = 0;
    s.I = true;
    s.R = false;
    printf("Starting CREATE_CHILD_SA (fallback)...\n");

    for (;;) {
        size_t l = write(buffer, s, old_s);
        if (!tx(buffer, l, sockfd, sizeof(servaddr), &servaddr)) {
            break;
        }

        size_t n = rx(buffer, sockfd, sizeof(servaddr), &servaddr);
        // make a copy of s
        memcpy(&old_s, &s, sizeof(s));
        read(n, buffer, s);
    }
}

int main(int, char**) {
    printf("Hello From Client\n\n\n");
    start();

    return 0;
}