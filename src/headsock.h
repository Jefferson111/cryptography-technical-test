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

#define ENCR 1
#define PRF 2
#define INTEG 3
#define QKD 13

#define IKE 1
#define AH 2
#define ESP 3

#define MAJOR_MASK 0x000F0000
#define MAJOR_VER 2
#define MINOR_MASK 0x00F00000
#define MINOR_VER 0
#define EXCHANGE_MASK 0x0000FF00
#define R_FLAG_MASK 0x00000004
#define I_FLAG_MASK 0x00000010
#define CRITICAL_MASK 0x00010000
#define RUNNING_MODE_MASK 0x00010000
#define HDR_SIZE 20
#define PAYLOAD_HDR_SIZE 4

#define WAIT_QKD 1
#define DH 2
#define CONTINUE 3

#define KEY_ID_LEN 2
#define VER 1
#define RESERVED 0

using namespace std;

struct attribute {
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
    uint8_t version;
    bool F; // running mode
    uint16_t key; // modify to fit security param
};

struct state {
    uint32_t responder_spi;
    uint32_t initiator_spi;
    uint8_t EXCHANGE_TYPE;
    bool R; // response flag
    bool I; // initiator is last re-key flag
    vector<struct proposal> proposals;
    struct qkd q;
};

size_t rx(
    char* buffer, 
    int sockfd, 
    socklen_t len, 
    struct sockaddr_in* cliaddrptr
    ) {
    size_t n = recvfrom(
        sockfd, 
        (char *)buffer, 
        MAXLINE, 
        MSG_WAITALL, 
        (struct sockaddr *) cliaddrptr,
        &len
    );
    printf("Packet recieved: %ld\n", n);
    return n;
}

bool tx(
    char* buffer, 
    size_t buffer_len,
    int sockfd, 
    socklen_t len, 
    struct sockaddr_in* cliaddrptr
    ) {
    if (buffer_len == 0) {
        return false;
    }

    printf("Packet sent: %ld\n", buffer_len);
    int n = sendto(
        sockfd, 
        (const char *)buffer, 
        buffer_len, 
        MSG_CONFIRM, 
        (const struct sockaddr *) cliaddrptr,
        len
    );
    
    return n > 0;
}

void setup_initiator(int &sockfd, struct sockaddr_in &servaddr) {
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
    }

    // Filling server information
    servaddr.sin_family    = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    srand(time(NULL));
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
    uint32_t initiator_spi = ntohl(*(uint32_t *)(buffer));
    uint32_t responder_spi = ntohl(*(uint32_t *)(buffer + 4));
    if (initiator_spi == 0) {
        perror("invalid initiator spi");
    }
    if (responder_spi == 0) {
        if (s.EXCHANGE_TYPE == 0) {
            responder_spi = rand();
        } else {
            perror("invalid responder spi");
        }
    }
    uint32_t t = ntohl(*(uint32_t *)(buffer + 8));
    if ((t & MAJOR_MASK) >> 16 != MAJOR_VER) {
        perror("invalid major version");
    }
    if ((t & MINOR_MASK) >> 20 != MINOR_VER) {
        perror("invalid minor version");
    }
    
    s.EXCHANGE_TYPE = (EXCHANGE_MASK & t) >> 8;
    s.R = R_FLAG_MASK & t;
    s.I = !(I_FLAG_MASK & t);
    s.initiator_spi = initiator_spi;
    s.responder_spi = responder_spi;

    return t >> 24;
}

void read_transforms(char* buffer, struct proposal &p) {
    uint8_t next_transform = *(uint8_t *)buffer;

    do {
        struct transform t;
        t.type = *(uint8_t *)(buffer + 4);
        t.id = ntohs(*(uint16_t *)(buffer + 6));
        p.transforms.push_back(t);

        // skip atrributes here
        
        uint16_t transform_len = ntohs(*(uint16_t *)(buffer + 2));
        next_transform = *(uint8_t *)buffer;
        buffer = buffer + transform_len;
    } while (next_transform != 0);
}

void read_sa(char* buffer, struct state &s) {
    buffer = buffer + 4;
    uint8_t next_proposal;

    do {
        uint8_t proposal_no = *(uint8_t *)(buffer + 4);
        uint8_t protocol_id = *(uint8_t *)(buffer + 5);
        uint8_t no_of_transforms = *(uint8_t *)(buffer + 7);

        struct proposal p;
        p.id = protocol_id;
        p.no = proposal_no;
        read_transforms(buffer + 8, p);

        uint16_t proposal_len = ntohs(*(uint16_t *)(buffer + 2));
        next_proposal = *(uint8_t *)buffer;
        buffer = buffer + proposal_len;
    } while (next_proposal != 0);
}

void read_qkdid(char* buffer, struct state &s) {
    uint8_t version = *(uint8_t *)(buffer + 4);
    if (version != 1) {
        perror("invalid qkd version");
    }
    if (s.EXCHANGE_TYPE == IKE_SA_INIT && !(CRITICAL_MASK & ntohl(*(uint32_t *)(buffer)))) {
        perror("Critical bit not set to 1");
    }
    s.q.version = 1;
    s.q.F = RUNNING_MODE_MASK & ntohl(*(uint32_t *)(buffer + 4));
    s.q.device = ntohs(*(uint16_t *)(buffer + 6));
    s.q.key = ntohs(*(uint16_t *)(buffer + 10));
}

void read_qkdfall(char* buffer, struct state &s) {
    uint8_t version = *(uint8_t *)(buffer + 4);
    if (version != 1) {
        perror("invalid qkd version");
    }
    if (!(CRITICAL_MASK & ntohl(*(uint32_t *)(buffer)))) {
        perror("Critical bit not set to 1");
    }
    s.q.fallback_method = ntohs(*(uint16_t *)(buffer + 6));
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
        printf("Next payload: %d\n", next_payload);
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

        uint16_t payload_len = ntohs(*(uint16_t *)(buffer + 2));
        next_payload = *(uint8_t *)buffer;
        buffer = buffer + payload_len;
    }
}

uint16_t get_key(uint16_t device) {
    return device;
}

size_t write_qkdid(char* buffer, struct state &s) {
    if (s.EXCHANGE_TYPE == IKE_AUTH) {
        return 0;
    }

    uint16_t key_id = htons(get_key(s.q.device));
    uint8_t flags = 0;
    uint8_t F = 0;
    uint16_t payload_len = 10 + KEY_ID_LEN;
    uint8_t c_flag = 1;
    uint8_t next_payload = NO_PAYLOAD;

    // calculate the starting index for the key_id field
    int key_id_index = MAXLINE - KEY_ID_LEN;

    // backfill the data into the buffer starting from the back
    memcpy(buffer + key_id_index, &key_id, KEY_ID_LEN);
    buffer[--key_id_index] = KEY_ID_LEN & 0xFF;
    buffer[--key_id_index] = KEY_ID_LEN >> 8;
    buffer[--key_id_index] = s.q.device & 0xFF;
    buffer[--key_id_index] = s.q.device >> 8;
    buffer[--key_id_index] = flags | F;
    buffer[--key_id_index] = VER;
    buffer[--key_id_index] = payload_len & 0xFF;
    buffer[--key_id_index] = payload_len >> 8;
    buffer[--key_id_index] = RESERVED | c_flag;
    buffer[--key_id_index] = next_payload;

    return payload_len;
}

size_t write_sa(char* buffer, struct state &s) {
    // assume SA only has QKD
    uint16_t transform_id = 0; // direct
    uint8_t transform_type = QKD;
    uint16_t transform_len = 8;
    uint8_t no_of_transforms = 1;
    uint8_t spi_size = 8; // for IKE
    uint8_t protocol_id = IKE;
    uint8_t protocol_no = 1; // simplicity sake, only 1
    uint16_t proposal_len = transform_len + 8;
    uint16_t payload_len = proposal_len + 4;
    uint8_t c_flag = 0;
    uint8_t next_payload = (s.EXCHANGE_TYPE == IKE_AUTH) ? NO_PAYLOAD : QKD_ID;

    int last_byte_index = MAXLINE - 1;

    buffer[last_byte_index] = transform_id & 0xFF;
    buffer[--last_byte_index] = transform_id >> 8;
    buffer[--last_byte_index] = RESERVED;
    buffer[--last_byte_index] = transform_type;
    buffer[--last_byte_index] = transform_len & 0xFF;
    buffer[--last_byte_index] = transform_len >> 8;
    buffer[--last_byte_index] = RESERVED;
    buffer[--last_byte_index] = 0; // assume single
    buffer[--last_byte_index] = no_of_transforms;
    buffer[--last_byte_index] = spi_size;
    buffer[--last_byte_index] = protocol_id;
    buffer[--last_byte_index] = protocol_no;
    buffer[--last_byte_index] = proposal_len & 0xFF;
    buffer[--last_byte_index] = proposal_len >> 8;
    buffer[--last_byte_index] = RESERVED;
    buffer[--last_byte_index] = 0; // assume single
    buffer[--last_byte_index] = payload_len & 0xFF;
    buffer[--last_byte_index] = payload_len >> 8;
    buffer[--last_byte_index] = RESERVED | c_flag;
    buffer[--last_byte_index] = next_payload;

    return payload_len;
}

size_t write_qkdfall(char* buffer, struct state &s) {
    if (s.EXCHANGE_TYPE != IKE_AUTH) {
        return 0;
    }
    uint16_t fallback = CONTINUE;
    uint8_t flags = 0;
    uint16_t payload_len = 8;
    uint8_t c_flag = 1;
    uint8_t next_payload = SA;

    // calculate the index of the last byte of the buffer
    int last_byte_index = MAXLINE - 1;

    // fill the data from the back of the buffer
    buffer[last_byte_index] = s.q.fallback_method & 0xFF;
    buffer[--last_byte_index] = s.q.fallback_method >> 8;
    buffer[--last_byte_index] = flags;
    buffer[--last_byte_index] = VER;
    buffer[--last_byte_index] = payload_len & 0xFF;
    buffer[--last_byte_index] = payload_len >> 8;
    buffer[--last_byte_index] = RESERVED | c_flag;
    buffer[--last_byte_index] = next_payload;

    return payload_len;
}

size_t write_sk(char* buffer, size_t len, struct state &s) {
    // insert with whatever encryption scheme

    return 0;
}

size_t write_hdr(char* buffer, size_t len, struct state &s) {
    uint32_t hdr_len = len + HDR_SIZE;
    uint8_t flags = (s.R << 2) | (s.I << 4);
    uint8_t next_payload = s.EXCHANGE_TYPE == IKE_AUTH ? QKD_FALL : SA;

    memmove(buffer + HDR_SIZE, buffer + MAXLINE - len, len);
    buffer[0] = s.initiator_spi >> 24;
    buffer[1] = s.initiator_spi >> 16;
    buffer[2] = s.initiator_spi >> 8;
    buffer[3] = s.initiator_spi & 0xFF;
    buffer[4] = s.responder_spi >> 24;
    buffer[5] = s.responder_spi >> 16;
    buffer[6] = s.responder_spi >> 8;
    buffer[7] = s.responder_spi & 0xFF;
    buffer[8] = next_payload;
    buffer[9] = MAJOR_VER | (MINOR_VER << 4);
    buffer[10] = s.EXCHANGE_TYPE;
    buffer[11] = flags;
    buffer[16] = hdr_len >> 24;
    buffer[17] = hdr_len >> 16;
    buffer[18] = hdr_len >> 8;
    buffer[19] = hdr_len & 0xFF;

    return hdr_len;
}

void print_key_message(struct state &s, struct state &old_s) {
    if (s.EXCHANGE_TYPE == IKE_AUTH) {
        printf("Key is: %d\n\n", s.q.key);
    } else if (s.q.key == 0) {
        if (s.q.fallback_method == CONTINUE) {
            printf("Re-use old key: %d\\n", old_s.q.key);
        } else if (s.q.fallback_method == WAIT_QKD) {
            printf("Wait for QKD device\n\n");
        } else {
            printf("Diffie-hellman\n\n");
        }
    } else {
        printf("Key is: %d\n\n", s.q.key);
    }
}

size_t write(char* buffer, struct state &s, struct state &old_s) {
    if (s.I && s.EXCHANGE_TYPE == IKE_SA_INIT && s.R) {
        printf("Advancing to IKE_AUTH...\n");
        s.EXCHANGE_TYPE = IKE_AUTH;
        s.R = false;
    }
    if (s.R) {
        printf("End of process...\n");
        print_key_message(s, old_s);
        return 0;
    }
    if (!s.I) {
        s.R = true;
        print_key_message(s, old_s);
    }
    size_t len = write_qkdid(buffer, s);
    len += write_sa(buffer - len, s);
    len += write_qkdfall(buffer - len, s);
    len += write_sk(buffer - len, len, s);
    return write_hdr(buffer, len, s);
}