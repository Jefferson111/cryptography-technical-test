#include <bits/stdc++.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
   
#define PORT    5359
#define MAXLINE 1024

#define IKE_SA_INIT               34
#define IKE_AUTH                  35
#define CREATE_CHILD_SA           36
#define INFORMATIONAL             37

#define NO_PAYLOAD 0
#define SA 33
#define KE 34
#define IDi 35
#define IDr 36
#define CERT 37
#define CERTREQ 38
#define AUTH 39
#define NONCE 40
#define TSi 44
#define TSr 45
#define SK 46
#define QKD_ID 66
#define QKD_FALL 67

#define MAJOR_MASK 0x00F00000
#define MAJOR_VER 2
#define MINOR_MASK 0x000F0000
#define MINOR_VER 0
#define EXCHANGE_MASK 0x0000FF00
#define R_FLAG_MASK 0x00000040
#define I_FLAG_MASK 0x00000001
#define CRITICAL_MASK 0x00100000
#define RUNNING_MODE_MASK 0x00100000

#define WAIT_QKD 1
#define DH 2
#define CONTINUE 3

using namespace std;

struct attributes {
    uint32_t value;
    uint16_t type;
};

struct transform {
    uint16_t id;
    uint8_t type;
    vector<struct attribute> attributes;
};

struct proposal {
    uint8_t no;
    uint8_t id;
    vector<struct transform> transforms;
};

struct qkd {
    uint16_t device;
    uint16_t fallback_method;
    bool F; // running mode
    uint8_t version;
    string key;
};

struct state {
    uint32_t SPI;
    uint8_t EXCHANGE_TYPE;
    bool R; // response flag
    bool I; // initiator is last re-key flag
    vector<struct proposal> proposals;
    struct qkd q;
};

int rx(
    char* buffer, 
    int sockfd, 
    socklen_t len, 
    struct sockaddr_in* cliaddrptr
    ) {
    int n = recvfrom(
        sockfd, 
        (char *)buffer, 
        MAXLINE, 
        MSG_WAITALL, 
        (struct sockaddr *) cliaddrptr,
        &len
    );
    return n;
}

bool tx(
    char* buffer, 
    size_t bufferlen,
    int sockfd, 
    socklen_t len, 
    struct sockaddr_in* cliaddrptr
    ) {
    int n = sendto(
        sockfd, 
        (const char *)buffer, 
        bufferlen, 
        MSG_CONFIRM, 
        (const struct sockaddr *) cliaddrptr,
        len
    );
    
    return n > 0;
}

void setup(int &sockfd, struct sockaddr_in &servaddr) {
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
    }

    // Filling server information
    servaddr.sin_family    = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind the socket with the server address
    if ( bind(sockfd, (const struct sockaddr *)&servaddr, 
            sizeof(servaddr)) < 0 )
    {
        perror("bind failed");
    }

    srand(time(NULL));
}

uint8_t read_hdr(char* buffer, struct state &s) {
    uint32_t initiator_spi = htonl(*(uint32_t *)(buffer));
    uint32_t responder_spi = htonl(*(uint32_t *)(buffer + 4));
    if (initiator_spi == 0) {
        perror("invalid initiator spi");
    }
    if (s.SPI == 0 && responder_spi != 0) {
        perror("invalid responder spi");
    }
    uint32_t t = htonl(*(uint32_t *)(buffer + 8));
    if ((t & MAJOR_MASK) != MAJOR_VER) {
        perror("invalid major version");
    }
    if ((t & MINOR_MASK) != MINOR_VER) {
        perror("invalid minor version");
    }
    
    s.EXCHANGE_TYPE = (EXCHANGE_MASK & t) >> 16;
    s.R = R_FLAG_MASK & t;
    s.I = I_FLAG_MASK & t;
    if (s.SPI == 0) {
        s.SPI = rand();
    }

    return *(uint8_t *)(buffer + 8);
}

void read_transforms(char* buffer, struct proposal &p) {
    uint8_t next_transform = *(uint8_t *)buffer;

    while (next_transform != 0) {
        struct transform t;
        t.type = *(uint8_t *)(buffer + 4);
        t.id = *(uint8_t *)(buffer + 6);
        p.transforms.push_back(t);

        // skip atrributes here
        
        uint16_t transform_len = htons(*(uint16_t *)(buffer + 2));
        buffer = buffer + transform_len;
        next_transform = *(uint8_t *)buffer;
    }
}

void read_sa(char* buffer, struct state &s) {
    uint8_t next_proposal = *(uint8_t *)(buffer + 4);
    buffer = buffer + 4;

    while (next_proposal != 0) {
        uint8_t proposal_no = *(uint8_t *)(buffer + 4);
        uint8_t protocol_id = *(uint8_t *)(buffer + 5);
        uint8_t no_of_transforms = *(uint8_t *)(buffer + 7);

        struct proposal p;
        p.id = protocol_id;
        p.no = proposal_no;
        read_transforms(buffer + 12, p);

        uint16_t proposal_len = htons(*(uint16_t *)(buffer + 2));
        buffer = buffer + proposal_len;
        next_proposal = *(uint8_t *)buffer;
    }
}

void read_qkdid(char* buffer, struct state &s) {
    uint8_t version = *(uint8_t *)(buffer + 4);
    if (version == 1) {
        perror("invalid qkd version");
    }
    if ((s.EXCHANGE_TYPE == IKE_SA_INIT || s.EXCHANGE_TYPE == IKE_AUTH) && !(CRITICAL_MASK & *(uint32_t *)(buffer))) {
        perror("Critical bit not set to 1");
    }
    s.q.version = 1;
    s.q.F = RUNNING_MODE_MASK & *(uint32_t *)(buffer + 4);
    s.q.device = *(uint16_t *)(buffer + 6);

    string ss;
    char* arr = buffer + 12;
    for (uint16_t i = 0; i < *(uint16_t *)(buffer + 8); ++i) {
        ss.push_back(arr[i]);
    }
    s.q.key = ss;
}

void read_qkdfall(char* buffer, struct state &s) {
    uint8_t version = *(uint8_t *)(buffer + 4);
    if (version == 1) {
        perror("invalid qkd version");
    }
    if (!(CRITICAL_MASK & *(uint32_t *)(buffer))) {
        perror("Critical bit not set to 1");
    }
    s.q.fallback_method = *(uint16_t *)(buffer + 6);
}

void read_ke(char* buffer, struct state &s) {}
void read_idi(char* buffer, struct state &s) {}
void read_idr(char* buffer, struct state &s) {}
void read_nonce(char* buffer, struct state &s) {}
void read_auth(char* buffer, struct state &s) {}
void read_tsi(char* buffer, struct state &s) {}
void read_tsr(char* buffer, struct state &s) {}
void read_sk(char* buffer, struct state &s) {}

void read(int len, char* buffer, struct state &s) {
    uint8_t next_payload = read_hdr(buffer, s);
    buffer = buffer + 20;

    while (next_payload != NO_PAYLOAD) {
        if (next_payload == SA) {
            read_sa(buffer, s);
        } else if (next_payload == KE) {
            read_ke(buffer, s);
        } else if (next_payload == IDi) {
            read_idi(buffer, s);
        } else if (next_payload == IDr) {
            read_idr(buffer, s);
        } else if (next_payload == NONCE) {
            read_nonce(buffer, s);
        } else if (next_payload == AUTH) {
            read_auth(buffer, s);
        } else if (next_payload == TSi) {
            read_tsi(buffer, s);
        } else if (next_payload == TSr) {
            read_tsr(buffer, s);
        } else if (next_payload == SK) {
            read_sk(buffer, s);
        } else if (next_payload == QKD_ID) {
            read_qkdid(buffer, s);
        } else if (next_payload == QKD_FALL) {
            read_qkdfall(buffer, s);
        } else {
            perror("unexpected payload");
        }

        uint16_t payload_len = htons(*(uint16_t *)(buffer + 2));
        buffer = buffer + payload_len;
        next_payload = *(uint8_t *)buffer;
    }
}

size_t write(char* buffer, struct state &s, struct state &old_s) {
    if (!s.R) {
        // provide a response
        if (s.EXCHANGE_TYPE == IKE_SA_INIT || s.EXCHANGE_TYPE == IKE_AUTH) {
            // echoes back msg and set with whatever fields system has
        } else if (s.EXCHANGE_TYPE == CREATE_CHILD_SA) {
            if (s.q.key == "") {
                if (s.q.fallback_method == WAIT_QKD) {
                    // do nothing and wait
                } else if (s.q.fallback_method == CONTINUE) {
                    s.q.key = old_s.q.key;
                } else if (s.q.fallback_method == DH) {
                    // do diffie-hellman
                }
            }
        }
        return htonl(*(uint32_t *)(buffer + 16));
    } else {
        if (s.EXCHANGE_TYPE == IKE_SA_INIT) {
            if (s.R) {
                // proceed to IKE_AUTH as u hav a response
                s.EXCHANGE_TYPE = IKE_AUTH;
                // sends HDR, SK{IDi, [CERT,] [CERTREQ,] [IDr,] QKDfallback, AUTH, SAi2, TSi, TSr}
            } else {
                // sends HDR, SAi1, KEi, Ni KeyID
            }
        } else if (s.EXCHANGE_TYPE == CREATE_CHILD_SA) {
            // sends HDR, SK{[N], SA, Ni, KeyID, [KEi,] [TSi, TSr]}
        }
    }
}