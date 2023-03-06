#include <bits/stdc++.h>
#include "./headsock.h"

using namespace std;

bool check_state(struct state &s) {
    // whatever other validating logic goes here
    return false;
}

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
        int n = rx(buffer, sockfd, sizeof(cliaddr), &cliaddr);
        // make a copy of s
        memcpy(&old_s, &s, sizeof(s));
        read(n, buffer, s);
        if (check_state(s)) {
            // revert or crash if any errors
            break;
        }
        size_t l = write(buffer, s, old_s);
        tx(buffer, l, sockfd, sizeof(cliaddr), &cliaddr);
    }
}

int main(void) {
    printf("Hello From Server\n");
    start();

    return 0;
}